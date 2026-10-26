#include "http2_enrichment.hpp"

#include <nghttp2/nghttp2.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <utility>

namespace spider {
namespace {

constexpr std::size_t frame_header_size = 9;
constexpr std::size_t max_header_block_size = 1024U * 1024U;
constexpr std::uint32_t max_dynamic_table_size = 1024U * 1024U;

struct Annotation {
    std::size_t index{};
    std::size_t start{};
    std::size_t end{};
    std::string kind;
};

struct DisplayText {
    std::string value;
    bool escaped{};
};

DisplayText display_text(const std::uint8_t* data, const std::size_t size) {
    static constexpr std::string_view hex{"0123456789ABCDEF"};
    DisplayText result;
    result.value.reserve(size);
    for (std::size_t index = 0; index < size; ++index) {
        const auto byte = data[index];
        if (byte >= 0x20U && byte < 0x7fU && byte != '\\') {
            result.value.push_back(static_cast<char>(byte));
        } else {
            result.value += "\\x";
            result.value.push_back(hex[(byte >> 4U) & 0x0fU]);
            result.value.push_back(hex[byte & 0x0fU]);
            result.escaped = true;
        }
    }
    return result;
}

std::vector<Annotation> h2_annotations(const nlohmann::json& event,
                                       const std::size_t payload_size) {
    const auto raw = event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object())
        .value("content_annotations", nlohmann::json::array());
    std::vector<Annotation> result;
    if (!raw.is_array()) return result;
    for (std::size_t index = 0; index < raw.size(); ++index) {
        const auto& item = raw[index];
        if (!item.is_array() || item.size() < 3 || !item[2].is_string() ||
            (!item[0].is_number_integer() && !item[0].is_number_unsigned()) ||
            (!item[1].is_number_integer() && !item[1].is_number_unsigned())) continue;
        const auto start = item[0].get<std::int64_t>();
        const auto end = item[1].get<std::int64_t>();
        const auto kind = item[2].get<std::string>();
        if (start < 0 || end < start || static_cast<std::size_t>(end) > payload_size ||
            !kind.starts_with("h2.")) continue;
        result.push_back({index, static_cast<std::size_t>(start),
                          static_cast<std::size_t>(end), kind});
    }
    return result;
}

std::string session_key(const nlohmann::json& event) {
    auto key = event.value("id", "");
    if (!key.empty()) return key;
    return event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object()).value("session", "");
}

std::size_t direction_index(const nlohmann::json& event) {
    const auto side = event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object()).value("side", "L");
    return side == "R" || side == "r" ? 1U : 0U;
}

class Inflater {
public:
    Inflater() { reset(); }
    ~Inflater() {
        if (value_) nghttp2_hd_inflate_del(value_);
    }
    Inflater(const Inflater&) = delete;
    Inflater& operator=(const Inflater&) = delete;

    void reset() {
        if (value_) nghttp2_hd_inflate_del(value_);
        value_ = nullptr;
        if (nghttp2_hd_inflate_new(&value_) != 0) value_ = nullptr;
    }

    std::optional<nlohmann::json> decode(const std::string_view block) {
        if (!value_) return std::nullopt;
        auto fields = nlohmann::json::array();
        const auto* input = reinterpret_cast<const std::uint8_t*>(block.data());
        std::size_t remaining = block.size();
        for (;;) {
            nghttp2_nv field{};
            int flags{};
            const auto consumed = nghttp2_hd_inflate_hd2(
                value_, &field, &flags, input, remaining, 1);
            if (consumed < 0) {
                reset();
                return std::nullopt;
            }
            input += static_cast<std::size_t>(consumed);
            remaining -= static_cast<std::size_t>(consumed);
            if ((flags & NGHTTP2_HD_INFLATE_EMIT) != 0) {
                const auto name = display_text(field.name, field.namelen);
                const auto value = display_text(field.value, field.valuelen);
                auto output = nlohmann::json{{"name", name.value}, {"value", value.value}};
                if (name.escaped) output["name_encoding"] = "escaped-bytes";
                if (value.escaped) output["value_encoding"] = "escaped-bytes";
                fields.push_back(std::move(output));
            }
            if ((flags & NGHTTP2_HD_INFLATE_FINAL) != 0) {
                if (nghttp2_hd_inflate_end_headers(value_) != 0) {
                    reset();
                    return std::nullopt;
                }
                return std::optional<nlohmann::json>{std::move(fields)};
            }
            if (consumed == 0 && (flags & NGHTTP2_HD_INFLATE_EMIT) == 0) {
                reset();
                return std::nullopt;
            }
        }
    }

    bool change_table_size(const std::uint32_t size) {
        if (!value_) return false;
        if (nghttp2_hd_inflate_change_table_size(value_, size) == 0) return true;
        reset();
        return false;
    }

private:
    nghttp2_hd_inflater* value_{};
};

struct Direction {
    Inflater inflater;
    std::array<std::uint8_t, frame_header_size> header{};
    std::size_t header_bytes{};
    // Callback-local anchors, never reused across content envelopes.
    std::optional<std::size_t> frame_offset;
    std::optional<std::size_t> header_offset;
    std::uint32_t frame_remaining{};
    std::uint8_t frame_type{};
    std::uint8_t frame_flags{};
    std::uint32_t stream_id{};
    std::string frame_payload;
    std::vector<std::size_t> frame_annotations;
    std::string header_block;
    std::uint32_t header_stream{};
    std::uint32_t continuation_stream{};
    std::uint32_t parent_stream{};
    std::string header_kind;
    std::size_t header_annotation_count{};
    bool pending_headers{};
    bool spans_previous_envelopes{};
    bool context_complete{true};

    void reset_frame() {
        frame_offset.reset();
        header_bytes = 0;
        frame_remaining = 0;
        frame_type = 0;
        frame_flags = 0;
        stream_id = 0;
        frame_payload.clear();
        frame_annotations.clear();
    }

    void lose_context() {
        reset_frame();
        header_offset.reset();
        header_block.clear();
        header_stream = 0;
        continuation_stream = 0;
        parent_stream = 0;
        header_kind.clear();
        header_annotation_count = 0;
        pending_headers = false;
        spans_previous_envelopes = false;
        context_complete = false;
        inflater.reset();
    }
};

struct Session {
    std::array<Direction, 2> directions;
};

std::optional<std::string_view> header_fragment(const Direction& direction) {
    std::size_t start{};
    std::size_t padding{};
    if ((direction.frame_flags & 0x08U) != 0) {
        if (direction.frame_payload.empty()) return std::nullopt;
        padding = static_cast<std::uint8_t>(direction.frame_payload.front());
        start = 1;
    }
    if ((direction.frame_flags & 0x20U) != 0) start += 5;
    if (start + padding > direction.frame_payload.size()) return std::nullopt;
    return std::string_view(direction.frame_payload).substr(
        start, direction.frame_payload.size() - start - padding);
}

struct PushPromiseFragment {
    std::uint32_t promised_stream{};
    std::string_view bytes;
};

std::optional<PushPromiseFragment> push_promise_fragment(const Direction& direction) {
    std::size_t start{};
    std::size_t padding{};
    if ((direction.frame_flags & 0x08U) != 0) {
        if (direction.frame_payload.empty()) return std::nullopt;
        padding = static_cast<std::uint8_t>(direction.frame_payload.front());
        start = 1;
    }
    if (start + 4U + padding > direction.frame_payload.size()) return std::nullopt;
    const auto* value = reinterpret_cast<const std::uint8_t*>(
        direction.frame_payload.data() + start);
    const auto promised_stream =
        (static_cast<std::uint32_t>(value[0] & 0x7fU) << 24U) |
        (static_cast<std::uint32_t>(value[1]) << 16U) |
        (static_cast<std::uint32_t>(value[2]) << 8U) |
        static_cast<std::uint32_t>(value[3]);
    start += 4U;
    return PushPromiseFragment{
        promised_stream,
        std::string_view(direction.frame_payload).substr(
            start, direction.frame_payload.size() - start - padding),
    };
}

} // namespace

class Http2Enrichment::Impl {
public:
    std::vector<SxbnEnvelope> process(const nlohmann::json& event,
                                      const std::string_view payload,
                                      const bool selected) {
        const auto items = h2_annotations(event, payload.size());
        if (items.empty()) return {};
        seen_.fetch_add(1, std::memory_order_relaxed);
        const auto key = session_key(event);
        if (key.empty()) return {};

        std::scoped_lock lock(mutex_);
        auto& session = sessions_[key];
        const auto side = direction_index(event);
        auto& direction = session.directions[side];
        direction.frame_offset.reset();
        direction.header_offset.reset();
        if (!selected) {
            // We cannot reconstruct an HPACK dynamic table or peer SETTINGS
            // later.  Once an H2 callback is skipped, neither direction may
            // claim complete context for this connection.
            session.directions[0].lose_context();
            session.directions[1].lose_context();
            missed_context_.fetch_add(1, std::memory_order_relaxed);
            return {};
        }

        selected_.fetch_add(1, std::memory_order_relaxed);
        std::vector<SxbnEnvelope> output;
        for (const auto& item : items) {
            const auto bytes = payload.substr(item.start, item.end - item.start);
            if (item.kind == "h2.preface") continue;
            if (item.kind == "h2.invalid") {
                direction.lose_context();
                decode_errors_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            consume(session, side, item, bytes, output);
        }
        return output;
    }

    void forget(const nlohmann::json& event) {
        const auto key = session_key(event);
        if (key.empty()) return;
        std::scoped_lock lock(mutex_);
        sessions_.erase(key);
    }

    nlohmann::json diagnostics() const {
        std::size_t sessions{};
        {
            std::scoped_lock lock(mutex_);
            sessions = sessions_.size();
        }
        return {
            {"content_seen", seen_.load(std::memory_order_relaxed)},
            {"selected", selected_.load(std::memory_order_relaxed)},
            {"decoded", decoded_.load(std::memory_order_relaxed)},
            {"decode_errors", decode_errors_.load(std::memory_order_relaxed)},
            {"missed_context", missed_context_.load(std::memory_order_relaxed)},
            {"tracked_sessions", sessions},
        };
    }

private:
    void consume(Session& session, const std::size_t side,
                 const Annotation& annotation,
                 std::string_view bytes, std::vector<SxbnEnvelope>& output) {
        auto& direction = session.directions[side];
        if (annotation.kind == "h2.frame.header") {
            if (direction.header_bytes == 0)
                direction.frame_offset = annotation.start;
            for (const auto character : bytes) {
                if (direction.header_bytes == frame_header_size) {
                    direction.lose_context();
                    decode_errors_.fetch_add(1, std::memory_order_relaxed);
                }
                direction.header[direction.header_bytes++] =
                    static_cast<std::uint8_t>(character);
                if (direction.header_bytes == frame_header_size) begin_frame(direction);
            }
            if (direction.header_bytes == frame_header_size && direction.pending_headers &&
                (direction.frame_type != 9 ||
                 direction.stream_id != direction.continuation_stream)) {
                direction.lose_context();
                decode_errors_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            direction.frame_annotations.push_back(annotation.index);
            if (direction.header_bytes == frame_header_size && direction.frame_remaining == 0)
                finish_frame(session, side, output);
            return;
        }

        if (direction.header_bytes != frame_header_size) {
            direction.lose_context();
            return;
        }
        direction.frame_annotations.push_back(annotation.index);
        const auto count = std::min<std::size_t>(bytes.size(), direction.frame_remaining);
        if (direction.frame_type == 1 || direction.frame_type == 4 ||
            direction.frame_type == 5 ||
            direction.frame_type == 9)
            direction.frame_payload.append(bytes.data(), count);
        direction.frame_remaining -= static_cast<std::uint32_t>(count);
        if (count != bytes.size()) {
            direction.lose_context();
            decode_errors_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        if (direction.frame_remaining == 0) finish_frame(session, side, output);
    }

    static void begin_frame(Direction& direction) {
        direction.frame_remaining =
            (static_cast<std::uint32_t>(direction.header[0]) << 16U) |
            (static_cast<std::uint32_t>(direction.header[1]) << 8U) |
            static_cast<std::uint32_t>(direction.header[2]);
        direction.frame_type = direction.header[3];
        direction.frame_flags = direction.header[4];
        direction.stream_id =
            (static_cast<std::uint32_t>(direction.header[5] & 0x7fU) << 24U) |
            (static_cast<std::uint32_t>(direction.header[6]) << 16U) |
            (static_cast<std::uint32_t>(direction.header[7]) << 8U) |
            static_cast<std::uint32_t>(direction.header[8]);
        direction.frame_payload.clear();
    }

    void finish_frame(Session& session, const std::size_t side,
                      std::vector<SxbnEnvelope>& output) {
        auto& direction = session.directions[side];
        if (direction.frame_type == 1) finish_headers(direction, output);
        else if (direction.frame_type == 5) finish_push_promise(direction, output);
        else if (direction.frame_type == 9) finish_continuation(direction, output);
        else if (direction.frame_type == 4 && (direction.frame_flags & 0x01U) == 0)
            finish_settings(session.directions[1U - side], direction.frame_payload);
        direction.reset_frame();
    }

    void finish_settings(Direction& encoded_direction, const std::string_view payload) {
        if (payload.size() % 6U != 0U) {
            encoded_direction.lose_context();
            decode_errors_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        for (std::size_t offset = 0; offset < payload.size(); offset += 6U) {
            const auto id = (static_cast<std::uint16_t>(
                                 static_cast<std::uint8_t>(payload[offset])) << 8U) |
                            static_cast<std::uint8_t>(payload[offset + 1]);
            if (id != 0x01U) continue;
            const auto value =
                (static_cast<std::uint32_t>(
                     static_cast<std::uint8_t>(payload[offset + 2])) << 24U) |
                (static_cast<std::uint32_t>(
                     static_cast<std::uint8_t>(payload[offset + 3])) << 16U) |
                (static_cast<std::uint32_t>(
                     static_cast<std::uint8_t>(payload[offset + 4])) << 8U) |
                static_cast<std::uint8_t>(payload[offset + 5]);
            if (value > max_dynamic_table_size) {
                encoded_direction.lose_context();
                decode_errors_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            if (!encoded_direction.inflater.change_table_size(value)) {
                encoded_direction.lose_context();
                decode_errors_.fetch_add(1, std::memory_order_relaxed);
            }
        }
    }

    void finish_headers(Direction& direction, std::vector<SxbnEnvelope>& output) {
        if (direction.pending_headers || direction.stream_id == 0) {
            direction.lose_context();
            decode_errors_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const auto fragment = header_fragment(direction);
        if (!fragment || fragment->size() > max_header_block_size) {
            direction.lose_context();
            decode_errors_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        direction.header_block.assign(*fragment);
        direction.header_offset = direction.frame_offset;
        direction.header_stream = direction.stream_id;
        direction.continuation_stream = direction.stream_id;
        direction.parent_stream = 0;
        direction.header_kind = "h2.header_block";
        direction.header_annotation_count = direction.frame_annotations.size();
        direction.pending_headers = true;
        direction.spans_previous_envelopes = (direction.frame_flags & 0x04U) == 0;
        if ((direction.frame_flags & 0x04U) != 0) decode_headers(direction, output);
    }

    void finish_push_promise(Direction& direction,
                             std::vector<SxbnEnvelope>& output) {
        if (direction.pending_headers || direction.stream_id == 0) {
            direction.lose_context();
            decode_errors_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        const auto fragment = push_promise_fragment(direction);
        if (!fragment || fragment->promised_stream == 0 ||
            fragment->bytes.size() > max_header_block_size) {
            direction.lose_context();
            decode_errors_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        direction.header_block.assign(fragment->bytes);
        direction.header_offset = direction.frame_offset;
        direction.header_stream = fragment->promised_stream;
        direction.continuation_stream = direction.stream_id;
        direction.parent_stream = direction.stream_id;
        direction.header_kind = "h2.push_promise_block";
        direction.header_annotation_count = direction.frame_annotations.size();
        direction.pending_headers = true;
        direction.spans_previous_envelopes = (direction.frame_flags & 0x04U) == 0;
        if ((direction.frame_flags & 0x04U) != 0) decode_headers(direction, output);
    }

    void finish_continuation(Direction& direction, std::vector<SxbnEnvelope>& output) {
        if (!direction.pending_headers ||
            direction.continuation_stream != direction.stream_id ||
            direction.header_block.size() + direction.frame_payload.size() >
                max_header_block_size) {
            direction.lose_context();
            decode_errors_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        direction.header_block += direction.frame_payload;
        direction.header_annotation_count += direction.frame_annotations.size();
        direction.spans_previous_envelopes = true;
        if ((direction.frame_flags & 0x04U) != 0) decode_headers(direction, output);
    }

    void decode_headers(Direction& direction, std::vector<SxbnEnvelope>& output) {
        if (!direction.context_complete) {
            direction.header_block.clear();
            direction.pending_headers = false;
            return;
        }
        auto fields = direction.inflater.decode(direction.header_block);
        if (!fields) {
            direction.lose_context();
            decode_errors_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        nlohmann::json source{
            {"kind", direction.header_kind},
            {"stream_id", direction.header_stream},
            {"annotation_count", direction.header_annotation_count},
            {"spans_previous_envelopes", direction.spans_previous_envelopes},
        };
        if (direction.parent_stream != 0)
            source["parent_stream_id"] = direction.parent_stream;
        if (direction.header_offset)
            source["payload_offset"] = *direction.header_offset;
        output.push_back({{
            {"type", "enrichment"},
            {"source", std::move(source)},
            {"operation", "hpack.decode"},
            {"content_type", "application/http-fields+json"},
            {"provenance", {{"ranges", "smithproxy"},
                            {"content_type", "spider"},
                            {"transform", "spider"}}},
            {"context", "complete"},
            {"headers", std::move(*fields)},
        }, {}});
        decoded_.fetch_add(1, std::memory_order_relaxed);
        direction.header_block.clear();
        direction.header_stream = 0;
        direction.continuation_stream = 0;
        direction.parent_stream = 0;
        direction.header_kind.clear();
        direction.header_annotation_count = 0;
        direction.pending_headers = false;
        direction.spans_previous_envelopes = false;
    }

    mutable std::mutex mutex_;
    std::map<std::string, Session> sessions_;
    std::atomic_uint64_t seen_{};
    std::atomic_uint64_t selected_{};
    std::atomic_uint64_t decoded_{};
    std::atomic_uint64_t decode_errors_{};
    std::atomic_uint64_t missed_context_{};
};

Http2Enrichment::Http2Enrichment() : impl_(std::make_unique<Impl>()) {}
Http2Enrichment::~Http2Enrichment() = default;

std::vector<SxbnEnvelope> Http2Enrichment::process(const nlohmann::json& event,
                                                   const std::string_view payload,
                                                   const bool selected) {
    return impl_->process(event, payload, selected);
}

void Http2Enrichment::forget(const nlohmann::json& event) { impl_->forget(event); }

nlohmann::json Http2Enrichment::diagnostics() const { return impl_->diagnostics(); }

} // namespace spider
