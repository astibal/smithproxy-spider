#include "content_decoding_enrichment.hpp"

#include <zlib.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

namespace spider {
namespace {

constexpr std::size_t output_chunk_size = 32U * 1024U;
constexpr std::size_t max_output_per_event = 16U * 1024U * 1024U;

struct Annotation {
    std::size_t index{};
    std::size_t start{};
    std::size_t end{};
    std::string kind;
    nlohmann::json attributes{nlohmann::json::object()};
};

struct Range {
    std::size_t start{};
    std::size_t end{};
    std::string encoding;
};

struct ContextKey {
    std::string session;
    std::string side;
    std::string layer;
    std::uint32_t stream_id{};

    auto operator<=>(const ContextKey&) const = default;
};

std::string session_key(const nlohmann::json& event) {
    auto key = event.value("id", "");
    if (!key.empty()) return key;
    return event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object()).value("session", "");
}

std::string side_key(const nlohmann::json& event) {
    return event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object()).value("side", "L");
}

std::vector<Annotation> annotations(const nlohmann::json& info,
                                    const std::size_t payload_size) {
    const auto raw = info.value("content_annotations", nlohmann::json::array());
    std::vector<Annotation> result;
    if (!raw.is_array()) return result;
    for (std::size_t index = 0; index < raw.size(); ++index) {
        const auto& item = raw[index];
        if (!item.is_array() || item.size() < 3 || !item[2].is_string() ||
            (!item[0].is_number_integer() && !item[0].is_number_unsigned()) ||
            (!item[1].is_number_integer() && !item[1].is_number_unsigned())) continue;
        const auto start = item[0].get<std::int64_t>();
        const auto end = item[1].get<std::int64_t>();
        if (start < 0 || end < start || static_cast<std::size_t>(end) > payload_size) continue;
        Annotation annotation{index, static_cast<std::size_t>(start),
                              static_cast<std::size_t>(end), item[2].get<std::string>()};
        if (item.size() > 3 && item[3].is_object()) annotation.attributes = item[3];
        result.push_back(std::move(annotation));
    }
    return result;
}

std::string canonical_encoding(std::string value) {
    const auto not_space = [](const unsigned char character) {
        return std::isspace(character) == 0;
    };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    std::ranges::transform(value, value.begin(), [](const unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    if (value == "x-gzip") return "gzip";
    return value;
}

std::vector<Range> encoded_ranges(const nlohmann::json& info,
                                  const std::size_t payload_size) {
    const auto starts = info.value("L7_payload_start", nlohmann::json::array());
    const auto ends = info.value("L7_payload_end", nlohmann::json::array());
    const auto encodings = info.value("L7_encoding", nlohmann::json::array());
    std::vector<Range> result;
    if (!starts.is_array() || !ends.is_array() || !encodings.is_array() ||
        starts.size() != ends.size() || starts.size() != encodings.size()) return result;
    for (std::size_t index = 0; index < starts.size(); ++index) {
        if ((!starts[index].is_number_integer() && !starts[index].is_number_unsigned()) ||
            (!ends[index].is_number_integer() && !ends[index].is_number_unsigned()) ||
            !encodings[index].is_string()) continue;
        const auto start = starts[index].get<std::int64_t>();
        const auto end = ends[index].get<std::int64_t>();
        auto encoding = canonical_encoding(encodings[index].get<std::string>());
        if (start < 0 || end <= start || static_cast<std::size_t>(end) > payload_size ||
            (encoding != "gzip" && encoding != "deflate")) continue;
        result.push_back({static_cast<std::size_t>(start),
                          static_cast<std::size_t>(end), std::move(encoding)});
    }
    return result;
}

std::optional<std::pair<ContextKey, std::size_t>> range_context(
        const std::string& session, const std::string& side, const Range& range,
        const std::vector<Annotation>& items) {
    for (const auto& item : items) {
        if (item.start > range.start || item.end < range.end) continue;
        if (item.kind == "http1.body" || item.kind == "http1.chunk.data")
            return std::pair{ContextKey{session, side, "http1", 0}, item.index};
        if (item.kind == "h2.data" && item.attributes.contains("stream_id") &&
            (item.attributes["stream_id"].is_number_integer() ||
             item.attributes["stream_id"].is_number_unsigned())) {
            const auto stream = item.attributes["stream_id"].get<std::int64_t>();
            if (stream > 0 && stream <= UINT32_MAX)
                return std::pair{ContextKey{session, side, "h2",
                    static_cast<std::uint32_t>(stream)}, item.index};
        }
    }
    return std::nullopt;
}

class Decoder {
public:
    explicit Decoder(std::string encoding) : encoding_(std::move(encoding)) {
        if (encoding_ == "gzip") initialize(16 + MAX_WBITS);
    }
    ~Decoder() {
        if (initialized_) inflateEnd(&stream_);
    }
    Decoder(const Decoder&) = delete;
    Decoder& operator=(const Decoder&) = delete;

    [[nodiscard]] const std::string& encoding() const { return encoding_; }
    [[nodiscard]] bool valid() const { return valid_; }
    [[nodiscard]] bool at_stream_boundary() const { return at_stream_boundary_; }

    bool feed(const std::string_view input, std::string& output, bool& finished) {
        finished = false;
        if (!valid_) return false;
        if (!input.empty()) at_stream_boundary_ = false;
        if (encoding_ == "deflate" && !initialized_) {
            prefix_.append(input);
            if (prefix_.size() < 2) return true;
            const auto first = static_cast<std::uint8_t>(prefix_[0]);
            const auto second = static_cast<std::uint8_t>(prefix_[1]);
            const bool zlib_header = (first & 0x0fU) == Z_DEFLATED &&
                (first >> 4U) <= 7U &&
                ((static_cast<unsigned>(first) << 8U) + second) % 31U == 0;
            initialize(zlib_header ? MAX_WBITS : -MAX_WBITS);
            if (!valid_) return false;
            const auto buffered = std::move(prefix_);
            prefix_.clear();
            return inflate_bytes(buffered, output, finished);
        }
        return inflate_bytes(input, output, finished);
    }

private:
    void initialize(const int window_bits) {
        stream_ = {};
        window_bits_ = window_bits;
        initialized_ = inflateInit2(&stream_, window_bits_) == Z_OK;
        valid_ = initialized_;
    }

    bool inflate_bytes(const std::string_view input, std::string& output, bool& finished) {
        stream_.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
        stream_.avail_in = static_cast<uInt>(input.size());
        std::array<unsigned char, output_chunk_size> buffer{};
        do {
            stream_.next_out = buffer.data();
            stream_.avail_out = static_cast<uInt>(buffer.size());
            const auto before_in = stream_.avail_in;
            const auto status = inflate(&stream_, Z_NO_FLUSH);
            const auto produced = buffer.size() - stream_.avail_out;
            if (output.size() + produced > max_output_per_event) {
                valid_ = false;
                return false;
            }
            output.append(reinterpret_cast<const char*>(buffer.data()), produced);
            if (status == Z_STREAM_END) {
                finished = true;
                const auto* remaining = stream_.next_in;
                const auto remaining_size = stream_.avail_in;
                if (inflateReset2(&stream_, window_bits_) != Z_OK) {
                    valid_ = false;
                    return false;
                }
                stream_.next_in = const_cast<Bytef*>(remaining);
                stream_.avail_in = remaining_size;
                if (remaining_size == 0) {
                    at_stream_boundary_ = true;
                    break;
                }
                finished = false;
                continue;
            }
            if (status == Z_BUF_ERROR && stream_.avail_in == 0) break;
            if (status != Z_OK || (before_in == stream_.avail_in && produced == 0)) {
                valid_ = false;
                return false;
            }
        } while (stream_.avail_in != 0 || stream_.avail_out == 0);
        return true;
    }

    std::string encoding_;
    std::string prefix_;
    z_stream stream_{};
    int window_bits_{};
    bool initialized_{};
    bool valid_{true};
    bool at_stream_boundary_{true};
};

struct Context {
    explicit Context(std::string encoding) : decoder(std::move(encoding)) {}
    Decoder decoder;
    bool complete{true};
};

struct PendingOutput {
    ContextKey key;
    std::size_t generation{};
    std::string encoding;
    std::string payload;
    std::vector<std::array<std::size_t, 2>> ranges;
    std::vector<std::size_t> annotations;
    bool finished{};
};

} // namespace

class ContentDecodingEnrichment::Impl {
public:
    std::vector<SxbnEnvelope> process(const nlohmann::json& event,
                                      const std::string_view payload,
                                      const bool selected) {
        const auto info = event.value("details", nlohmann::json::object())
            .value("info", nlohmann::json::object());
        const auto ranges = encoded_ranges(info, payload.size());
        const auto items = annotations(info, payload.size());
        if (ranges.empty() && items.empty()) return {};
        const auto session = session_key(event);
        if (session.empty()) return {};
        const auto side = side_key(event);

        std::scoped_lock lock(mutex_);
        std::vector<std::size_t> http1_starts;
        for (const auto& item : items)
            if (item.kind == "http1.start_line") http1_starts.push_back(item.start);
        std::size_t next_http1_start{};
        std::size_t http1_generation{};
        std::vector<PendingOutput> pending;
        for (const auto& range : ranges) {
            while (next_http1_start < http1_starts.size() &&
                   http1_starts[next_http1_start] <= range.start) {
                reset_http1_context(session, side);
                ++next_http1_start;
                ++http1_generation;
            }
            const auto identified = range_context(session, side, range, items);
            if (!identified) {
                unmapped_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            const auto& [key, annotation] = *identified;
            auto position = contexts_.try_emplace(key, range.encoding).first;
            auto& context = position->second;
            if (!selected) {
                context.complete = false;
                skipped_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            if (!context.complete || !context.decoder.valid() ||
                context.decoder.encoding() != range.encoding) {
                incomplete_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            auto output = std::ranges::find_if(pending, [&](const auto& item) {
                return item.key == key &&
                    (key.layer != "http1" || item.generation == http1_generation);
            });
            if (output == pending.end()) {
                pending.push_back({key, http1_generation, range.encoding, {}, {}, {}, false});
                output = std::prev(pending.end());
            }
            output->ranges.push_back({range.start, range.end});
            output->annotations.push_back(annotation);
            bool finished{};
            input_bytes_.fetch_add(range.end - range.start, std::memory_order_relaxed);
            if (!context.decoder.feed(payload.substr(range.start, range.end - range.start),
                                      output->payload, finished)) {
                context.complete = false;
                decode_errors_.fetch_add(1, std::memory_order_relaxed);
                output->payload.clear();
                continue;
            }
            output->finished = finished;
        }
        while (next_http1_start < http1_starts.size()) {
            reset_http1_context(session, side);
            ++next_http1_start;
        }

        std::vector<SxbnEnvelope> result;
        for (auto& output : pending) {
            if (output.payload.empty()) continue;
            output_bytes_.fetch_add(output.payload.size(), std::memory_order_relaxed);
            decoded_.fetch_add(1, std::memory_order_relaxed);
            if (output.encoding == "gzip") gzip_decoded_.fetch_add(1, std::memory_order_relaxed);
            else deflate_decoded_.fetch_add(1, std::memory_order_relaxed);
            auto source = nlohmann::json{
                {"kind", output.key.layer + ".content"},
                {"ranges", output.ranges},
                {"annotations", output.annotations},
                {"side", output.key.side},
            };
            if (output.key.stream_id != 0) source["stream_id"] = output.key.stream_id;
            result.push_back({{
                {"type", "enrichment"},
                {"source", std::move(source)},
                {"operation", output.encoding + ".inflate"},
                {"content_type", "application/octet-stream"},
                {"content_encoding", output.encoding},
                {"context", "complete"},
                {"finished", output.finished},
            }, std::move(output.payload)});
        }
        return result;
    }

    void forget(const nlohmann::json& event) {
        const auto session = session_key(event);
        if (session.empty()) return;
        std::scoped_lock lock(mutex_);
        for (const auto& [key, context] : contexts_) {
            if (key.session == session && context.complete &&
                !context.decoder.at_stream_boundary())
                truncated_.fetch_add(1, std::memory_order_relaxed);
        }
        std::erase_if(contexts_, [&](const auto& item) {
            return item.first.session == session;
        });
    }

    nlohmann::json diagnostics() const {
        std::size_t contexts{};
        {
            std::scoped_lock lock(mutex_);
            contexts = contexts_.size();
        }
        return {
            {"decoded", decoded_.load(std::memory_order_relaxed)},
            {"by_encoding", {
                {"gzip", gzip_decoded_.load(std::memory_order_relaxed)},
                {"deflate", deflate_decoded_.load(std::memory_order_relaxed)},
            }},
            {"decode_errors", decode_errors_.load(std::memory_order_relaxed)},
            {"skipped_ranges", skipped_.load(std::memory_order_relaxed)},
            {"incomplete_context", incomplete_.load(std::memory_order_relaxed)},
            {"unmapped_ranges", unmapped_.load(std::memory_order_relaxed)},
            {"truncated_streams", truncated_.load(std::memory_order_relaxed)},
            {"input_bytes", input_bytes_.load(std::memory_order_relaxed)},
            {"output_bytes", output_bytes_.load(std::memory_order_relaxed)},
            {"tracked_contexts", contexts},
            {"max_output_per_event", max_output_per_event},
        };
    }

private:
    void reset_http1_context(const std::string& session, const std::string& side) {
        const ContextKey key{session, side, "http1", 0};
        const auto context = contexts_.find(key);
        if (context != contexts_.end() && context->second.complete &&
            !context->second.decoder.at_stream_boundary())
            truncated_.fetch_add(1, std::memory_order_relaxed);
        contexts_.erase(key);
    }

    mutable std::mutex mutex_;
    std::map<ContextKey, Context> contexts_;
    std::atomic_uint64_t decoded_{};
    std::atomic_uint64_t gzip_decoded_{};
    std::atomic_uint64_t deflate_decoded_{};
    std::atomic_uint64_t decode_errors_{};
    std::atomic_uint64_t skipped_{};
    std::atomic_uint64_t incomplete_{};
    std::atomic_uint64_t unmapped_{};
    std::atomic_uint64_t truncated_{};
    std::atomic_uint64_t input_bytes_{};
    std::atomic_uint64_t output_bytes_{};
};

ContentDecodingEnrichment::ContentDecodingEnrichment()
    : impl_(std::make_unique<Impl>()) {}
ContentDecodingEnrichment::~ContentDecodingEnrichment() = default;

std::vector<SxbnEnvelope> ContentDecodingEnrichment::process(
        const nlohmann::json& event, const std::string_view payload,
        const bool selected) {
    return impl_->process(event, payload, selected);
}

void ContentDecodingEnrichment::forget(const nlohmann::json& event) {
    impl_->forget(event);
}

nlohmann::json ContentDecodingEnrichment::diagnostics() const {
    return impl_->diagnostics();
}

} // namespace spider
