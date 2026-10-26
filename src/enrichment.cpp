#include "enrichment.hpp"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <optional>
#include <string>
#include <vector>
#include <chrono>
#include <set>
#include <stdexcept>

namespace spider {
std::string EnrichmentEngine::replay(const std::vector<SxbnEnvelope>& records) {
    if (records.size() > 10000) throw std::runtime_error("Replay is limited to 10000 retained payloads");
    EnrichmentEngine engine;
    std::set<std::string> incomplete;
    for (const auto& record : records) {
        const auto& event = record.metadata.at("event");
        if (event.value("action", "") != "connection-content" || event.value("id", "").empty())
            throw std::runtime_error("Replay requires connection-content events with session IDs");
        if (!record.metadata.value("context_complete", false)) incomplete.insert(event.at("id").get<std::string>());
    }
    std::string output;
    std::size_t count = 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    for (std::size_t index = 0; index < records.size(); ++index) {
        if (std::chrono::steady_clock::now() > deadline) throw std::runtime_error("Replay exceeded its 5 second budget");
        auto event = records[index].metadata.at("event");
        const auto id = event.at("id").get<std::string>();
        const auto info = event.value("details", nlohmann::json::object()).value("info", nlohmann::json::object());
        bool h2 = false;
        for (const auto& annotation : info.value("content_annotations", nlohmann::json::array()))
            if (annotation.is_array() && annotation.size() >= 3 && annotation[2].is_string() &&
                annotation[2].get<std::string>().starts_with("h2.")) h2 = true;
        if (h2 && incomplete.contains(id)) {
            (void)engine.http2_.process(event, records[index].payload, false);
        }
        event["traffic_rule"] = {{"mode", "focus"}};
        for (auto item : engine.process(event, records[index].payload)) {
            item.metadata["replay_index"] = index;
            item.metadata["replayed"] = true;
            const auto envelope = encode_sxbn(item.metadata, item.payload);
            if (output.size() + envelope.size() > 32U * 1024U * 1024U)
                throw std::runtime_error("Replay output exceeds 32 MiB");
            output += envelope;
            ++count;
        }
    }
    output += encode_sxbn({{"type", "replay-summary"}, {"records", records.size()},
        {"outputs", count}, {"incomplete_sessions", incomplete}, {"diagnostics", engine.diagnostics()}});
    return output;
}
namespace {

struct Annotation {
    std::size_t index{};
    std::size_t start{};
    std::size_t end{};
    std::string kind;
    nlohmann::json attributes{nlohmann::json::object()};
};

struct DisplayText {
    std::string value;
    bool escaped{};
};

DisplayText display_text(const std::string_view raw) {
    static constexpr std::string_view hex{"0123456789ABCDEF"};
    DisplayText result;
    result.value.reserve(raw.size());
    for (const auto character : raw) {
        const auto byte = static_cast<unsigned char>(character);
        if (byte >= 0x20U && byte < 0x7fU && byte != '\\') {
            result.value.push_back(character);
        } else {
            result.value += "\\x";
            result.value.push_back(hex[(byte >> 4U) & 0x0fU]);
            result.value.push_back(hex[byte & 0x0fU]);
            result.escaped = true;
        }
    }
    return result;
}

bool header_name_character(const unsigned char value) {
    return std::isalnum(value) != 0 ||
           std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(value)) !=
               std::string_view::npos;
}

std::string_view trim(std::string_view value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) {
        value.remove_prefix(1);
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) {
        value.remove_suffix(1);
    }
    return value;
}

std::vector<Annotation> annotations(const nlohmann::json& event,
                                    const std::size_t payload_size) {
    const auto raw = event.value("details", nlohmann::json::object())
        .value("info", nlohmann::json::object())
        .value("content_annotations", nlohmann::json::array());
    std::vector<Annotation> result;
    if (!raw.is_array()) return result;
    for (std::size_t index = 0; index < raw.size(); ++index) {
        const auto& item = raw[index];
        if (!item.is_array() || item.size() < 3 ||
            (!item[0].is_number_integer() && !item[0].is_number_unsigned()) ||
            (!item[1].is_number_integer() && !item[1].is_number_unsigned()) ||
            !item[2].is_string()) continue;
        const auto start = item[0].get<std::int64_t>();
        const auto end = item[1].get<std::int64_t>();
        if (start < 0 || end < 0) continue;
        Annotation annotation{index, static_cast<std::size_t>(start),
                              static_cast<std::size_t>(end), item[2].get<std::string>()};
        if (annotation.start > annotation.end || annotation.end > payload_size) continue;
        if (item.size() > 3 && item[3].is_object()) annotation.attributes = item[3];
        result.push_back(std::move(annotation));
    }
    return result;
}

std::optional<nlohmann::json> parse_start_line(const std::string_view raw) {
    auto line = raw;
    if (line.ends_with("\r\n")) line.remove_suffix(2);
    if (line.empty() || line.find('\r') != std::string_view::npos ||
        line.find('\n') != std::string_view::npos) return std::nullopt;

    nlohmann::json result;
    if (line.starts_with("HTTP/")) {
        const auto version_end = line.find(' ');
        if (version_end == std::string_view::npos) return std::nullopt;
        const auto code_end = line.find(' ', version_end + 1);
        const auto code = line.substr(version_end + 1,
            code_end == std::string_view::npos ? line.size() - version_end - 1
                                               : code_end - version_end - 1);
        if (code.size() != 3 || !std::ranges::all_of(code, [](const unsigned char value) {
                return std::isdigit(value) != 0;
            })) return std::nullopt;
        const auto reason = display_text(code_end == std::string_view::npos
            ? std::string_view{} : line.substr(code_end + 1));
        result = {{"kind", "response"}, {"version", std::string(line.substr(0, version_end))},
                  {"status", std::stoi(std::string(code))}, {"reason", reason.value}};
        if (reason.escaped) result["reason_encoding"] = "escaped-bytes";
        return std::optional<nlohmann::json>{std::move(result)};
    }

    const auto method_end = line.find(' ');
    if (method_end == std::string_view::npos) return std::nullopt;
    const auto target_end = line.find(' ', method_end + 1);
    if (target_end == std::string_view::npos || line.find(' ', target_end + 1) != std::string_view::npos) {
        return std::nullopt;
    }
    const auto method = line.substr(0, method_end);
    const auto target = line.substr(method_end + 1, target_end - method_end - 1);
    const auto version = line.substr(target_end + 1);
    if (method.empty() || target.empty() || !version.starts_with("HTTP/") ||
        !std::ranges::all_of(method, header_name_character)) return std::nullopt;
    const auto displayed_target = display_text(target);
    result = {{"kind", "request"}, {"method", std::string(method)},
              {"target", displayed_target.value}, {"version", std::string(version)}};
    if (displayed_target.escaped) result["target_encoding"] = "escaped-bytes";
    return std::optional<nlohmann::json>{std::move(result)};
}

std::optional<nlohmann::json> parse_headers(const std::string_view raw) {
    if (!raw.ends_with("\r\n")) return std::nullopt;
    auto headers = nlohmann::json::array();
    std::size_t offset{};
    while (offset < raw.size()) {
        const auto end = raw.find("\r\n", offset);
        if (end == std::string_view::npos) return std::nullopt;
        const auto line = raw.substr(offset, end - offset);
        offset = end + 2;
        if (line.empty()) {
            if (offset != raw.size()) return std::nullopt;
            return std::optional<nlohmann::json>{std::move(headers)};
        }
        if ((line.front() == ' ' || line.front() == '\t') && !headers.empty()) {
            const auto continuation = display_text(trim(line));
            auto& value = headers.back()["value"].get_ref<std::string&>();
            if (!continuation.value.empty()) value += " " + continuation.value;
            if (continuation.escaped) headers.back()["value_encoding"] = "escaped-bytes";
            continue;
        }
        const auto separator = line.find(':');
        if (separator == std::string_view::npos || separator == 0) return std::nullopt;
        const auto name = trim(line.substr(0, separator));
        if (name.empty() || !std::ranges::all_of(name, header_name_character)) return std::nullopt;
        const auto value = display_text(trim(line.substr(separator + 1)));
        auto field = nlohmann::json{{"name", std::string(name)}, {"value", value.value}};
        if (value.escaped) field["value_encoding"] = "escaped-bytes";
        headers.push_back(std::move(field));
    }
    return std::nullopt;
}

std::optional<SxbnEnvelope> http1_head(const std::vector<Annotation>& items,
                                       const std::string_view payload) {
    for (std::size_t position = 0; position < items.size(); ++position) {
        const auto& start = items[position];
        if (start.kind != "http1.start_line" || position + 1 >= items.size()) continue;
        const auto& headers = items[position + 1];
        if (headers.kind != "http1.headers" || start.end != headers.start) continue;
        const auto start_line = parse_start_line(payload.substr(start.start, start.end - start.start));
        const auto fields = parse_headers(payload.substr(headers.start, headers.end - headers.start));
        if (!start_line || !fields) continue;

        auto message = *start_line;
        message["headers"] = *fields;
        return SxbnEnvelope{{
            {"type", "enrichment"},
            {"source", {{"annotations", {start.index, headers.index}},
                        {"kind", "http1.message_head"},
                        {"ranges", {{start.start, start.end}, {headers.start, headers.end}}}}},
            {"operation", "http1.parse-head"},
            {"content_type", "application/http-fields+json"},
            {"provenance", {{"ranges", "smithproxy"},
                            {"content_type", "spider"},
                            {"transform", "spider"}}},
            {"context", "complete"},
            {"message", std::move(message)},
        }, {}};
    }
    return std::nullopt;
}

} // namespace

std::vector<SxbnEnvelope> EnrichmentEngine::process(const nlohmann::json& event,
                                                    const std::string_view payload) {
    content_seen_.fetch_add(1, std::memory_order_relaxed);
    const auto mode = event.value("traffic_rule", nlohmann::json::object()).value("mode", "");
    const bool selected = mode == "focus" || mode == "inspect" || event.contains("collections");
    auto result = http2_.process(event, payload, selected);
    content_decoding_.observe_http2_headers(event, result);
    auto decoded_content = content_decoding_.process(event, payload, selected);
    result.insert(result.end(), std::make_move_iterator(decoded_content.begin()),
                  std::make_move_iterator(decoded_content.end()));
    if (!selected) return result;
    selected_.fetch_add(1, std::memory_order_relaxed);
    const auto items = annotations(event, payload.size());
    if (auto head = http1_head(items, payload)) {
        result.push_back(std::move(*head));
        http1_heads_.fetch_add(1, std::memory_order_relaxed);
        outputs_.fetch_add(1, std::memory_order_relaxed);
    }
    return result;
}

void EnrichmentEngine::observe(const nlohmann::json& event) {
    if (event.value("action", "") == "connection-stop") {
        http2_.forget(event);
        content_decoding_.forget(event);
    }
}

nlohmann::json EnrichmentEngine::diagnostics() const {
    const auto http2 = http2_.diagnostics();
    const auto content_decoding = content_decoding_.diagnostics();
    const auto http2_outputs = http2.value("decoded", std::uint64_t{});
    const auto decoded_outputs = content_decoding.value("decoded", std::uint64_t{});
    const auto decoded_by_encoding = content_decoding.value(
        "by_encoding", nlohmann::json::object());
    return {
        {"content_seen", content_seen_.load(std::memory_order_relaxed)},
        {"selected", selected_.load(std::memory_order_relaxed)},
        {"outputs", outputs_.load(std::memory_order_relaxed) + http2_outputs +
                    decoded_outputs},
        {"by_operation", {
            {"http1.parse-head", http1_heads_.load(std::memory_order_relaxed)},
            {"hpack.decode", http2_outputs},
            {"gzip.inflate", decoded_by_encoding.value("gzip", 0U)},
            {"deflate.inflate", decoded_by_encoding.value("deflate", 0U)},
        }},
        {"http2", http2},
        {"content_decoding", content_decoding},
    };
}

} // namespace spider
