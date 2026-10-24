#include "decision_broker.hpp"
#include "binary_envelope.hpp"
#include "enrichment.hpp"
#include "session_filter.hpp"
#include "session_store.hpp"
#include "webhook.hpp"

#include <nghttp2/nghttp2.h>
#include <zlib.h>

#include <array>
#include <cassert>
#include <cstdio>
#include <future>
#include <iterator>
#include <string_view>
#include <vector>

namespace {

std::string h2_frame(const std::uint8_t type, const std::uint8_t flags,
                     const std::uint32_t stream, const std::string_view payload) {
    std::string result(9, '\0');
    result[0] = static_cast<char>((payload.size() >> 16U) & 0xffU);
    result[1] = static_cast<char>((payload.size() >> 8U) & 0xffU);
    result[2] = static_cast<char>(payload.size() & 0xffU);
    result[3] = static_cast<char>(type);
    result[4] = static_cast<char>(flags);
    result[5] = static_cast<char>((stream >> 24U) & 0x7fU);
    result[6] = static_cast<char>((stream >> 16U) & 0xffU);
    result[7] = static_cast<char>((stream >> 8U) & 0xffU);
    result[8] = static_cast<char>(stream & 0xffU);
    result.append(payload);
    return result;
}

class HpackEncoder {
public:
    HpackEncoder() { assert(nghttp2_hd_deflate_new(&value_, 4096) == 0); }
    ~HpackEncoder() { nghttp2_hd_deflate_del(value_); }

    std::string encode(const std::vector<std::pair<std::string, std::string>>& fields) {
        std::vector<nghttp2_nv> values;
        values.reserve(fields.size());
        for (const auto& [name, value] : fields) {
            values.push_back({
                reinterpret_cast<std::uint8_t*>(const_cast<char*>(name.data())),
                reinterpret_cast<std::uint8_t*>(const_cast<char*>(value.data())),
                name.size(), value.size(), NGHTTP2_NV_FLAG_NONE,
            });
        }
        std::string output(nghttp2_hd_deflate_bound(value_, values.data(), values.size()), '\0');
        const auto size = nghttp2_hd_deflate_hd2(
            value_, reinterpret_cast<std::uint8_t*>(output.data()), output.size(),
            values.data(), values.size());
        assert(size >= 0);
        output.resize(static_cast<std::size_t>(size));
        return output;
    }

private:
    nghttp2_hd_deflater* value_{};
};

nlohmann::json h2_event(const std::string& id, const std::string_view side,
                        nlohmann::json annotations, const bool selected = true) {
    nlohmann::json result{
        {"action", "connection-content"}, {"id", id},
        {"details", {{"info", {{"side", side},
                                  {"content_annotations", std::move(annotations)}}}}},
    };
    if (selected) result["traffic_rule"] = {{"mode", "focus"}};
    return result;
}

nlohmann::json complete_h2_annotations(const std::size_t size,
                                       const std::string_view payload_kind) {
    auto result = nlohmann::json::array({
        nlohmann::json::array({0, 9, "h2.frame.header"}),
    });
    if (size > 9) result.push_back(nlohmann::json::array({9, size, payload_kind}));
    return result;
}

std::string compress_payload(const std::string_view input, const int window_bits) {
    z_stream stream{};
    assert(deflateInit2(&stream, Z_BEST_SPEED, Z_DEFLATED, window_bits, 8,
                        Z_DEFAULT_STRATEGY) == Z_OK);
    stream.next_in = reinterpret_cast<Bytef*>(const_cast<char*>(input.data()));
    stream.avail_in = static_cast<uInt>(input.size());
    std::string output;
    std::array<unsigned char, 4096> block{};
    int status{};
    do {
        stream.next_out = block.data();
        stream.avail_out = static_cast<uInt>(block.size());
        status = deflate(&stream, Z_FINISH);
        assert(status == Z_OK || status == Z_STREAM_END);
        output.append(reinterpret_cast<const char*>(block.data()),
                      block.size() - stream.avail_out);
    } while (status != Z_STREAM_END);
    assert(deflateEnd(&stream) == Z_OK);
    return output;
}

nlohmann::json compressed_event(const std::string& id, const std::string_view side,
                                const std::string_view encoding, const std::size_t size,
                                const std::string_view kind = "http1.body",
                                const std::uint32_t stream_id = 0,
                                const bool selected = true) {
    auto annotation = nlohmann::json::array({0, size, kind});
    if (stream_id != 0)
        annotation.push_back({{"frame_type", "DATA"}, {"stream_id", stream_id}});
    auto event = h2_event(id, side, nlohmann::json::array({std::move(annotation)}),
                          selected);
    event["details"]["info"]["L7_payload_start"] = {0};
    event["details"]["info"]["L7_payload_end"] = {size};
    event["details"]["info"]["L7_encoding"] = {encoding};
    return event;
}

} // namespace

int main() {
    const auto envelope_metadata = nlohmann::json{
        {"action", "connection-content"}, {"id", "binary-session"},
        {"details", {{"info", {{"session", "tcp_10.0.0.1:1+tcp_10.0.0.2:2"},
                                  {"side", "L"}, {"payload_length", 4}}}}}};
    const auto envelope_json = envelope_metadata.dump();
    char envelope_prefix[26]{};
    std::snprintf(envelope_prefix, sizeof(envelope_prefix), "SXBN001:%08X:%08X",
                  static_cast<unsigned>(envelope_json.size()), 4U);
    const std::string envelope = std::string(envelope_prefix, 25) + envelope_json +
                                 std::string("\x00\x01\xfe\xff", 4);
    nlohmann::json decoded_envelope;
    std::string envelope_error;
    assert(spider::decode_sxbn(envelope, decoded_envelope, envelope_error));
    assert(decoded_envelope["details"]["info"]["content"] == "AAH+/w==");
    assert(decoded_envelope["details"]["info"]["payload_encoding"] == "sxbn-001");
    std::string decoded_payload;
    assert(spider::decode_sxbn(envelope, decoded_envelope, decoded_payload, envelope_error));
    assert(decoded_payload == std::string("\x00\x01\xfe\xff", 4));

    const auto original_wire = spider::encode_sxbn(
        {{"type", "event"}, {"key", "event:7"}, {"revision", 7}},
        std::string_view("\x00\x01\xfe\xff", 4));
    const auto enrichment_wire = spider::encode_sxbn(
        {{"type", "enrichment"},
         {"source", {{"envelope", "event:7"}, {"annotation", 1}}}});
    std::vector<spider::SxbnEnvelope> chain;
    std::string chain_error;
    assert(spider::decode_sxbn_chain(original_wire + enrichment_wire, chain, chain_error));
    assert(chain.size() == 2);
    assert(chain[0].metadata["revision"] == 7);
    assert(chain[0].payload == std::string("\x00\x01\xfe\xff", 4));
    assert(chain[1].metadata["type"] == "enrichment");
    assert(chain[1].payload.empty());
    const auto truncated_chain = original_wire + enrichment_wire.substr(0, enrichment_wire.size() - 1);
    assert(!spider::decode_sxbn_chain(truncated_chain, chain, chain_error));
    assert(chain.empty());
    assert(!spider::decode_sxbn_chain({}, chain, chain_error));
    assert(!spider::decode_sxbn_chain("not-an-envelope", chain, chain_error));
    assert(chain_error == "missing SXBN001 envelope");
    assert(!spider::decode_sxbn_chain("SXBN001:00000002;00000000{}", chain, chain_error));
    assert(chain_error == "invalid SXBN length separator");
    assert(!spider::decode_sxbn_chain("SXBN001:zzzzzzzz:00000000", chain, chain_error));
    assert(chain_error == "invalid SXBN JSON length");
    assert(!spider::decode_sxbn_chain("SXBN001:00000002:zzzzzzzz{}", chain, chain_error));
    assert(chain_error == "invalid SXBN payload length");
    assert(!spider::decode_sxbn_chain("SXBN001:00000002:00000000[]", chain, chain_error));
    assert(chain_error == "SXBN metadata must be an object");
    assert(!spider::decode_sxbn_chain("SXBN001:00000001:00000000{", chain, chain_error));
    assert(chain_error == "invalid SXBN JSON metadata");

    auto wrong_action = envelope_metadata;
    wrong_action["action"] = "ping";
    assert(!spider::decode_sxbn(spider::encode_sxbn(wrong_action), decoded_envelope,
                                decoded_payload, envelope_error));
    assert(envelope_error == "SXBN is only valid for connection-content");
    auto duplicate_content = envelope_metadata;
    duplicate_content["details"]["info"]["content"] = "AA==";
    assert(!spider::decode_sxbn(spider::encode_sxbn(duplicate_content), decoded_envelope,
                                decoded_payload, envelope_error));
    assert(envelope_error == "invalid SXBN connection-content metadata");
    auto wrong_length = envelope_metadata;
    wrong_length["details"]["info"]["payload_length"] = 3;
    assert(!spider::decode_sxbn(spider::encode_sxbn(
                                    wrong_length, std::string_view("data", 4)),
                                decoded_envelope, decoded_payload, envelope_error));
    assert(envelope_error == "SXBN payload length mismatch");
    assert(!spider::decode_sxbn(original_wire + enrichment_wire, decoded_envelope,
                                decoded_payload, envelope_error));
    assert(envelope_error == "callback requires exactly one SXBN envelope");

    auto empty_metadata = envelope_metadata;
    empty_metadata["details"]["info"]["payload_length"] = 0;
    const auto empty_wire = spider::encode_sxbn(empty_metadata);
    assert(spider::decode_sxbn(empty_wire, decoded_envelope, decoded_payload, envelope_error));
    assert(decoded_payload.empty());

    spider::EnrichmentEngine enrichment;
    const std::string http1 =
        "GET /watch?v=1 HTTP/1.1\r\nHost: example.test\r\nX-Value: one\r\n\ttwo\r\n\r\n";
    const auto first_line_end = http1.find("\r\n") + 2;
    nlohmann::json focused_http1{
        {"action", "connection-content"}, {"id", "http1-focused"},
        {"traffic_rule", {{"mode", "focus"}}},
        {"details", {{"info", {{"content_annotations", nlohmann::json::array({
            nlohmann::json::array({0, first_line_end, "http1.start_line"}),
            nlohmann::json::array({first_line_end, http1.size(), "http1.headers"}),
        })}}}}},
    };
    const auto http1_enrichments = enrichment.process(focused_http1, http1);
    assert(http1_enrichments.size() == 1);
    const auto& http1_metadata = http1_enrichments[0].metadata;
    assert(http1_metadata["operation"] == "http1.parse-head");
    assert(http1_metadata["context"] == "complete");
    assert(http1_metadata["message"]["kind"] == "request");
    assert(http1_metadata["message"]["method"] == "GET");
    assert(http1_metadata["message"]["target"] == "/watch?v=1");
    assert(http1_metadata["message"]["headers"][1]["value"] == "one two");
    assert(http1_metadata["provenance"]["ranges"] == "smithproxy");
    assert(http1_metadata["provenance"]["content_type"] == "spider");
    assert(http1_enrichments[0].payload.empty());
    auto passed_http1 = focused_http1;
    passed_http1.erase("traffic_rule");
    assert(enrichment.process(passed_http1, http1).empty());
    auto partial_http1 = http1.substr(0, http1.size() - 2);
    assert(enrichment.process(focused_http1, partial_http1).empty());
    const std::string binary_header = "HTTP/1.1 200 OK\r\nX-Binary: \xff\r\n\r\n";
    const auto binary_line_end = binary_header.find("\r\n") + 2;
    auto binary_event = focused_http1;
    binary_event["details"]["info"]["content_annotations"] = nlohmann::json::array({
        nlohmann::json::array({0, binary_line_end, "http1.start_line"}),
        nlohmann::json::array({binary_line_end, binary_header.size(), "http1.headers"}),
    });
    const auto binary_enrichment = enrichment.process(binary_event, binary_header);
    assert(binary_enrichment.size() == 1);
    assert(binary_enrichment[0].metadata["message"]["kind"] == "response");
    assert(binary_enrichment[0].metadata["message"]["status"] == 200);
    assert(binary_enrichment[0].metadata["message"]["headers"][0]["value"] == "\\xFF");
    assert(binary_enrichment[0].metadata["message"]["headers"][0]["value_encoding"] ==
           "escaped-bytes");
    const auto enrichment_diagnostics = enrichment.diagnostics();
    assert(enrichment_diagnostics["content_seen"] == 4);
    assert(enrichment_diagnostics["selected"] == 3);
    assert(enrichment_diagnostics["outputs"] == 2);

    HpackEncoder hpack;
    const auto first_hpack = hpack.encode({{":method", "GET"}, {":path", "/video"},
                                           {"x-spider-test", "dynamic-value"}});
    const auto first_headers = h2_frame(1, 0x04, 1, first_hpack);
    const auto split = 4U;
    const auto first_header_part = std::string_view(first_headers).substr(0, split);
    const auto second_header_part = std::string_view(first_headers).substr(split);
    const auto split_first_event = h2_event("h2-split", "L", nlohmann::json::array({
        nlohmann::json::array({0, split, "h2.frame.header"}),
    }));
    assert(enrichment.process(split_first_event, first_header_part).empty());
    const auto split_second_event = h2_event("h2-split", "L", nlohmann::json::array({
        nlohmann::json::array({0, 9 - split, "h2.frame.header"}),
        nlohmann::json::array({9 - split, second_header_part.size(), "h2.headers"}),
    }));
    const auto split_output = enrichment.process(split_second_event, second_header_part);
    assert(split_output.size() == 1);
    assert(split_output[0].metadata["operation"] == "hpack.decode");
    assert(split_output[0].metadata["source"]["stream_id"] == 1);
    assert(split_output[0].metadata["headers"][0]["name"] == ":method");
    assert(split_output[0].metadata["headers"][1]["value"] == "/video");
    assert(split_output[0].metadata["headers"][2]["value"] == "dynamic-value");
    assert(split_output[0].metadata["provenance"]["ranges"] == "smithproxy");
    assert(split_output[0].metadata["provenance"]["transform"] == "spider");

    // Every possible split of one HEADERS frame must produce the same
    // enrichment, including splits inside the 9-byte frame header and HPACK.
    for (std::size_t cut = 0; cut <= first_headers.size(); ++cut) {
        spider::EnrichmentEngine split_enrichment;
        std::vector<spider::SxbnEnvelope> outputs;
        if (cut != 0) {
            auto annotations = nlohmann::json::array();
            const auto header_end = std::min<std::size_t>(cut, 9);
            if (header_end != 0)
                annotations.push_back(nlohmann::json::array(
                    {0, header_end, "h2.frame.header"}));
            if (cut > 9)
                annotations.push_back(nlohmann::json::array(
                    {9, cut, "h2.headers"}));
            outputs = split_enrichment.process(h2_event(
                "h2-every-split", "L", std::move(annotations)),
                std::string_view(first_headers).substr(0, cut));
        }
        if (cut != first_headers.size()) {
            auto annotations = nlohmann::json::array();
            if (cut < 9)
                annotations.push_back(nlohmann::json::array(
                    {0, 9 - cut, "h2.frame.header"}));
            const auto payload_start = cut < 9 ? 9 - cut : 0;
            if (first_headers.size() - cut > payload_start)
                annotations.push_back(nlohmann::json::array(
                    {payload_start, first_headers.size() - cut, "h2.headers"}));
            auto tail = split_enrichment.process(h2_event(
                "h2-every-split", "L", std::move(annotations)),
                std::string_view(first_headers).substr(cut));
            outputs.insert(outputs.end(), std::make_move_iterator(tail.begin()),
                           std::make_move_iterator(tail.end()));
        }
        assert(outputs.size() == 1);
        assert(outputs[0].metadata["headers"][1]["value"] == "/video");
    }

    const auto second_hpack = hpack.encode({{":method", "GET"}, {":path", "/again"},
                                            {"x-spider-test", "dynamic-value"}});
    const auto block_split = second_hpack.size() / 2;
    const auto headers_frame = h2_frame(1, 0, 3,
        std::string_view(second_hpack).substr(0, block_split));
    const auto continuation_frame = h2_frame(9, 0x04, 3,
        std::string_view(second_hpack).substr(block_split));
    assert(enrichment.process(h2_event("h2-split", "L",
        complete_h2_annotations(headers_frame.size(), "h2.headers")), headers_frame).empty());
    const auto continuation_output = enrichment.process(h2_event("h2-split", "L",
        complete_h2_annotations(continuation_frame.size(), "h2.continuation")),
        continuation_frame);
    assert(continuation_output.size() == 1);
    assert(continuation_output[0].metadata["source"]["stream_id"] == 3);
    assert(continuation_output[0].metadata["source"]["spans_previous_envelopes"] == true);
    assert(continuation_output[0].metadata["headers"][1]["value"] == "/again");
    // Replay rebuilds HPACK history independently of the live engine and input rule mode.
    auto replay_first = h2_event("replay", "L", complete_h2_annotations(first_headers.size(), "h2.headers"));
    replay_first["traffic_rule"] = {{"mode", "pass"}};
    std::vector<spider::SxbnEnvelope> replay_records{
        {{{"event", replay_first}, {"context_complete", true}}, first_headers},
        {{{"event", h2_event("replay", "L", complete_h2_annotations(headers_frame.size(), "h2.headers"))},
          {"context_complete", true}}, headers_frame},
        {{{"event", h2_event("replay", "L", complete_h2_annotations(continuation_frame.size(), "h2.continuation"))},
          {"context_complete", true}}, continuation_frame}};
    std::vector<spider::SxbnEnvelope> replay_output;
    std::string replay_error;
    assert(spider::decode_sxbn_chain(spider::EnrichmentEngine::replay(replay_records), replay_output, replay_error));
    assert(replay_output.size() == 3);
    assert(replay_output[1].metadata["headers"][1]["value"] == "/again");
    assert(replay_output[1].metadata["replay_index"] == 2);
    assert(replay_records[0].metadata["event"]["traffic_rule"]["mode"] == "pass");
    replay_records[0].metadata["context_complete"] = false;
    replay_output.clear();
    assert(spider::decode_sxbn_chain(spider::EnrichmentEngine::replay(replay_records), replay_output, replay_error));
    assert(replay_output.size() == 1 && replay_output[0].metadata["outputs"] == 0);
    assert(replay_output[0].metadata["incomplete_sessions"].size() == 1);

    HpackEncoder padded_hpack;
    const auto padded_block = padded_hpack.encode({{":status", "200"},
                                                    {"content-type", "text/plain"}});
    std::string padded_payload(1, '\x02');
    padded_payload.append(5, '\0');
    padded_payload += padded_block;
    padded_payload.append(2, '\0');
    const auto padded_frame = h2_frame(1, 0x2c, 5, padded_payload);
    const auto padded_output = enrichment.process(h2_event("h2-padded", "R",
        complete_h2_annotations(padded_frame.size(), "h2.headers")), padded_frame);
    assert(padded_output.size() == 1);
    assert(padded_output[0].metadata["headers"][0]["name"] == ":status");
    assert(padded_output[0].metadata["headers"][1]["value"] == "text/plain");

    const std::string settings_payload{"\x00\x01\x00\x01\x00\x00", 6};
    const auto settings_frame = h2_frame(4, 0, 0, settings_payload);
    assert(enrichment.process(h2_event("h2-settings", "R",
        complete_h2_annotations(settings_frame.size(), "h2.settings")),
        settings_frame).empty());

    HpackEncoder binary_hpack;
    const auto binary_hpack_block = binary_hpack.encode(
        {{"x-binary", std::string("\xff", 1)}});
    const auto binary_h2_frame = h2_frame(1, 0x04, 7, binary_hpack_block);
    const auto binary_h2_output = enrichment.process(h2_event("h2-binary", "L",
        complete_h2_annotations(binary_h2_frame.size(), "h2.headers")), binary_h2_frame);
    assert(binary_h2_output.size() == 1);
    assert(binary_h2_output[0].metadata["headers"][0]["value"] == "\\xFF");
    assert(binary_h2_output[0].metadata["headers"][0]["value_encoding"] ==
           "escaped-bytes");

    HpackEncoder push_hpack;
    const auto push_block = push_hpack.encode({{":method", "GET"}, {":path", "/asset"},
                                                {"x-push", "shared-value"}});
    std::string push_payload{"\x00\x00\x00\x02", 4};
    push_payload += push_block;
    const auto push_frame = h2_frame(5, 0x04, 1, push_payload);
    const auto push_output = enrichment.process(h2_event("h2-push", "R",
        complete_h2_annotations(push_frame.size(), "h2.push_promise")), push_frame);
    assert(push_output.size() == 1);
    assert(push_output[0].metadata["source"]["kind"] == "h2.push_promise_block");
    assert(push_output[0].metadata["source"]["stream_id"] == 2);
    assert(push_output[0].metadata["source"]["parent_stream_id"] == 1);
    const auto post_push_block = push_hpack.encode({{":status", "200"},
                                                    {"x-push", "shared-value"}});
    const auto post_push_frame = h2_frame(1, 0x04, 2, post_push_block);
    const auto post_push_output = enrichment.process(h2_event("h2-push", "R",
        complete_h2_annotations(post_push_frame.size(), "h2.headers")), post_push_frame);
    assert(post_push_output.size() == 1);
    assert(post_push_output[0].metadata["headers"][1]["value"] == "shared-value");

    spider::EnrichmentEngine invalid_h2;
    const auto invalid_padding_frame = h2_frame(1, 0x0c, 1, std::string("\x05\x82", 2));
    assert(invalid_h2.process(h2_event("h2-invalid-padding", "L",
        complete_h2_annotations(invalid_padding_frame.size(), "h2.headers")),
        invalid_padding_frame).empty());
    const auto orphan_continuation = h2_frame(9, 0x04, 1, std::string("\x82", 1));
    assert(invalid_h2.process(h2_event("h2-orphan", "L",
        complete_h2_annotations(orphan_continuation.size(), "h2.continuation")),
        orphan_continuation).empty());
    const auto invalid_hpack_frame = h2_frame(1, 0x04, 1, std::string("\x80", 1));
    assert(invalid_h2.process(h2_event("h2-invalid-hpack", "L",
        complete_h2_annotations(invalid_hpack_frame.size(), "h2.headers")),
        invalid_hpack_frame).empty());
    HpackEncoder interrupted_hpack;
    const auto interrupted_block = interrupted_hpack.encode({{":method", "GET"}});
    const auto unfinished_headers = h2_frame(1, 0, 1, interrupted_block);
    assert(invalid_h2.process(h2_event("h2-interleaved", "L",
        complete_h2_annotations(unfinished_headers.size(), "h2.headers")),
        unfinished_headers).empty());
    const auto interleaved_data = h2_frame(0, 0, 1, "body");
    assert(invalid_h2.process(h2_event("h2-interleaved", "L",
        complete_h2_annotations(interleaved_data.size(), "h2.data")),
        interleaved_data).empty());
    const auto invalid_settings_frame = h2_frame(4, 0, 0, std::string("x", 1));
    assert(invalid_h2.process(h2_event("h2-invalid-settings", "R",
        complete_h2_annotations(invalid_settings_frame.size(), "h2.settings")),
        invalid_settings_frame).empty());
    const std::string oversized_setting{"\x00\x01\x00\x20\x00\x00", 6};
    const auto oversized_settings_frame = h2_frame(4, 0, 0, oversized_setting);
    assert(invalid_h2.process(h2_event("h2-oversized-settings", "R",
        complete_h2_annotations(oversized_settings_frame.size(), "h2.settings")),
        oversized_settings_frame).empty());
    assert(invalid_h2.diagnostics()["http2"]["decode_errors"] >= 6);

    HpackEncoder missed_hpack;
    spider::EnrichmentEngine partial_enrichment;
    const auto missed_first_block = missed_hpack.encode({{"x-dynamic", "first"}});
    const auto missed_first_frame = h2_frame(1, 0x04, 1, missed_first_block);
    assert(partial_enrichment.process(h2_event("h2-partial", "L",
        complete_h2_annotations(missed_first_frame.size(), "h2.headers"), false),
        missed_first_frame).empty());
    const auto missed_second_block = missed_hpack.encode({{"x-dynamic", "first"}});
    const auto missed_second_frame = h2_frame(1, 0x04, 3, missed_second_block);
    assert(partial_enrichment.process(h2_event("h2-partial", "L",
        complete_h2_annotations(missed_second_frame.size(), "h2.headers")),
        missed_second_frame).empty());
    assert(partial_enrichment.diagnostics()["http2"]["missed_context"] == 1);
    assert(partial_enrichment.diagnostics()["http2"]["tracked_sessions"] == 1);
    partial_enrichment.observe({{"action", "connection-stop"}, {"id", "h2-partial"}});
    assert(partial_enrichment.diagnostics()["http2"]["tracked_sessions"] == 0);

    // Smithproxy may publish HEADERS and the first DATA frames in one
    // callback before its L7_encoding shortcut reflects the decoded HPACK
    // fields. Spider already decodes that field block, so it must use the
    // representation metadata for DATA from the same callback.
    const std::string hpack_gzip_plain =
        "gzip learned from HPACK before the shortcut catches up\n";
    const auto hpack_gzip_body = compress_payload(hpack_gzip_plain, 16 + MAX_WBITS);
    HpackEncoder response_hpack;
    const auto response_fields = response_hpack.encode({
        {":status", "200"},
        {"content-type", "text/plain"},
        {"content-encoding", "gzip"},
    });
    const auto response_headers = h2_frame(1, 0x04, 31, response_fields);
    const auto response_data = h2_frame(0, 0x01, 31, hpack_gzip_body);
    const auto response_wire = response_headers + response_data;
    const auto data_header = response_headers.size();
    const auto data_start = data_header + 9U;
    auto hpack_gzip_event = h2_event("h2-hpack-gzip", "R", nlohmann::json::array({
        nlohmann::json::array({0, 9, "h2.frame.header",
                               {{"frame_type", "HEADERS"}, {"stream_id", 31}}}),
        nlohmann::json::array({9, response_headers.size(), "h2.headers",
                               {{"frame_type", "HEADERS"}, {"stream_id", 31}}}),
        nlohmann::json::array({data_header, data_start, "h2.frame.header",
                               {{"frame_type", "DATA"}, {"stream_id", 31}}}),
        nlohmann::json::array({data_start, response_wire.size(), "h2.data",
                               {{"frame_type", "DATA"}, {"stream_id", 31}}}),
    }));
    hpack_gzip_event["details"]["info"]["L7_payload_start"] = {data_start};
    hpack_gzip_event["details"]["info"]["L7_payload_end"] = {response_wire.size()};
    hpack_gzip_event["details"]["info"]["L7_encoding"] = {""};
    spider::EnrichmentEngine hpack_gzip_enrichment;
    const auto hpack_gzip_output = hpack_gzip_enrichment.process(
        hpack_gzip_event, response_wire);
    const auto recovered_gzip = std::ranges::find_if(
        hpack_gzip_output, [](const auto& item) {
            return item.metadata.value("operation", "") == "gzip.inflate";
        });
    assert(recovered_gzip != hpack_gzip_output.end());
    assert(recovered_gzip->payload == hpack_gzip_plain);
    std::vector<spider::SxbnEnvelope> replay_gzip;
    assert(spider::decode_sxbn_chain(spider::EnrichmentEngine::replay({
        {{{"event", hpack_gzip_event}, {"context_complete", true}}, response_wire}}),
        replay_gzip, replay_error));
    const auto replay_inflate = std::ranges::find_if(replay_gzip, [](const auto& item) {
        return item.metadata.value("operation", "") == "gzip.inflate";
    });
    assert(replay_inflate != replay_gzip.end() && replay_inflate->payload == hpack_gzip_plain);
    assert(recovered_gzip->metadata["source"]["stream_id"] == 31);
    assert(recovered_gzip->metadata["provenance"]["encoding"] == "spider-hpack");
    assert(hpack_gzip_enrichment.diagnostics()["content_decoding"]
                                             ["recovered_encodings"] == 1);

    const auto later_fields = response_hpack.encode({
        {":status", "200"}, {"content-encoding", "gzip"},
    });
    const auto later_headers = h2_frame(1, 0x04, 33, later_fields);
    auto later_header_event = h2_event("h2-hpack-gzip", "R", nlohmann::json::array({
        nlohmann::json::array({0, 9, "h2.frame.header",
                               {{"frame_type", "HEADERS"}, {"stream_id", 33}}}),
        nlohmann::json::array({9, later_headers.size(), "h2.headers",
                               {{"frame_type", "HEADERS"}, {"stream_id", 33}}}),
    }));
    assert(hpack_gzip_enrichment.process(later_header_event, later_headers).size() == 1);
    const auto later_plain = std::string("gzip in a later callback");
    const auto later_body = compress_payload(later_plain, 16 + MAX_WBITS);
    auto later_data_event = compressed_event(
        "h2-hpack-gzip", "R", "", later_body.size(), "h2.data", 33);
    const auto later_output = hpack_gzip_enrichment.process(later_data_event, later_body);
    const auto later_decoded = std::ranges::find_if(later_output, [](const auto& item) {
        return item.metadata.value("operation", "") == "gzip.inflate";
    });
    assert(later_decoded != later_output.end());
    assert(later_decoded->payload == later_plain);

    const std::string plain_content =
        "Spider stateful decompression across arbitrary callback boundaries.\n";
    for (const auto& compressed : std::array{
             std::pair{std::string("gzip"),
                       compress_payload(plain_content, 16 + MAX_WBITS)},
             std::pair{std::string("deflate"),
                       compress_payload(plain_content, MAX_WBITS)},
             std::pair{std::string("deflate"),
                       compress_payload(plain_content, -MAX_WBITS)},
         }) {
        for (std::size_t cut = 1; cut < compressed.second.size(); ++cut) {
            spider::EnrichmentEngine decoding;
            std::string decoded;
            const auto first = std::string_view(compressed.second).substr(0, cut);
            const auto second = std::string_view(compressed.second).substr(cut);
            for (const auto& envelope : decoding.process(
                     compressed_event("compressed-split", "R", compressed.first,
                                      first.size()), first))
                if (envelope.metadata.value("operation", "").ends_with(".inflate"))
                    decoded += envelope.payload;
            for (const auto& envelope : decoding.process(
                     compressed_event("compressed-split", "R", compressed.first,
                                      second.size()), second))
                if (envelope.metadata.value("operation", "").ends_with(".inflate"))
                    decoded += envelope.payload;
            assert(decoded == plain_content);
        }
    }

    const auto chunked_gzip = compress_payload(plain_content, 16 + MAX_WBITS);
    const auto chunk_cut = chunked_gzip.size() / 2;
    const std::string chunked_wire = chunked_gzip.substr(0, chunk_cut) + "5\r\n" +
                                     chunked_gzip.substr(chunk_cut);
    auto chunked_event = h2_event("compressed-chunked", "R", nlohmann::json::array({
        nlohmann::json::array({0, chunk_cut, "http1.chunk.data"}),
        nlohmann::json::array({chunk_cut, chunk_cut + 3, "http1.chunk.delimiter"}),
        nlohmann::json::array({chunk_cut + 3, chunked_wire.size(), "http1.chunk.data"}),
    }));
    chunked_event["details"]["info"]["L7_payload_start"] = {0, chunk_cut + 3};
    chunked_event["details"]["info"]["L7_payload_end"] = {chunk_cut,
                                                             chunked_wire.size()};
    chunked_event["details"]["info"]["L7_encoding"] = {"gzip", "gzip"};
    const auto chunked_output = enrichment.process(chunked_event, chunked_wire);
    const auto inflated_chunked = std::ranges::find_if(chunked_output, [](const auto& item) {
        return item.metadata.value("operation", "") == "gzip.inflate";
    });
    assert(inflated_chunked != chunked_output.end());
    assert(inflated_chunked->payload == plain_content);
    assert(inflated_chunked->metadata["finished"] == true);
    const auto& decoded_ranges = inflated_chunked->metadata["source"]["decoded_ranges"];
    assert(decoded_ranges.size() == 2);
    assert(decoded_ranges[0][0] == 0);
    assert(decoded_ranges[0][1] == decoded_ranges[1][0]);
    assert(decoded_ranges[1][1] == plain_content.size());

    const auto h2_gzip_one = compress_payload("stream one", 16 + MAX_WBITS);
    const auto h2_gzip_two = compress_payload("stream two", 16 + MAX_WBITS);
    spider::EnrichmentEngine h2_content_decoding;
    const auto h2_one = h2_content_decoding.process(
        compressed_event("compressed-h2", "R", "gzip", h2_gzip_one.size(),
                         "h2.data", 1), h2_gzip_one);
    const auto h2_two = h2_content_decoding.process(
        compressed_event("compressed-h2", "R", "gzip", h2_gzip_two.size(),
                         "h2.data", 3), h2_gzip_two);
    assert(h2_one.size() == 1 && h2_one[0].payload == "stream one");
    assert(h2_two.size() == 1 && h2_two[0].payload == "stream two");
    assert(h2_one[0].metadata["source"]["stream_id"] == 1);
    assert(h2_two[0].metadata["source"]["stream_id"] == 3);

    spider::EnrichmentEngine skipped_content;
    const auto skipped_cut = chunked_gzip.size() / 2;
    assert(skipped_content.process(
        compressed_event("compressed-skipped", "R", "gzip", skipped_cut,
                         "http1.body", 0, false),
        std::string_view(chunked_gzip).substr(0, skipped_cut)).empty());
    assert(skipped_content.process(
        compressed_event("compressed-skipped", "R", "gzip",
                         chunked_gzip.size() - skipped_cut),
        std::string_view(chunked_gzip).substr(skipped_cut)).empty());
    assert(skipped_content.diagnostics()["content_decoding"]["incomplete_context"] >= 1);

    const std::string reset_head =
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n";
    const auto reset_line_end = reset_head.find("\r\n") + 2;
    const auto reset_wire = reset_head + chunked_gzip;
    auto reset_event = h2_event("compressed-skipped", "R", nlohmann::json::array({
        nlohmann::json::array({0, reset_line_end, "http1.start_line"}),
        nlohmann::json::array({reset_line_end, reset_head.size(), "http1.headers"}),
        nlohmann::json::array({reset_head.size(), reset_wire.size(), "http1.body"}),
    }));
    reset_event["details"]["info"]["L7_payload_start"] = {reset_head.size()};
    reset_event["details"]["info"]["L7_payload_end"] = {reset_wire.size()};
    reset_event["details"]["info"]["L7_encoding"] = {"gzip"};
    const auto reset_output = skipped_content.process(reset_event, reset_wire);
    const auto reset_decoded = std::ranges::find_if(reset_output, [](const auto& item) {
        return item.metadata.value("operation", "") == "gzip.inflate";
    });
    assert(reset_decoded != reset_output.end());
    assert(reset_decoded->payload == plain_content);

    const auto concatenated_gzip = compress_payload("first", 16 + MAX_WBITS) +
                                   compress_payload("second", 16 + MAX_WBITS);
    spider::EnrichmentEngine concatenated_decoding;
    const auto concatenated_output = concatenated_decoding.process(
        compressed_event("compressed-concatenated", "R", "gzip",
                         concatenated_gzip.size()), concatenated_gzip);
    assert(concatenated_output.size() == 1);
    assert(concatenated_output[0].payload == "firstsecond");
    assert(concatenated_output[0].metadata["finished"] == true);

    const auto pipelined_first = compress_payload("message A", 16 + MAX_WBITS);
    const auto pipelined_second = compress_payload("message B", 16 + MAX_WBITS);
    const auto pipelined_cut = pipelined_first.size() / 2;
    spider::EnrichmentEngine pipelined_decoding;
    std::string pipelined_plain;
    for (const auto& item : pipelined_decoding.process(
             compressed_event("compressed-pipelined", "R", "gzip", pipelined_cut),
             std::string_view(pipelined_first).substr(0, pipelined_cut)))
        if (item.metadata.value("operation", "") == "gzip.inflate")
            pipelined_plain += item.payload;
    const std::string pipelined_head =
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n";
    const auto pipelined_line_end = pipelined_head.find("\r\n") + 2;
    const auto first_tail = pipelined_first.substr(pipelined_cut);
    const auto second_body_start = first_tail.size() + pipelined_head.size();
    const auto pipelined_wire = first_tail + pipelined_head + pipelined_second;
    auto pipelined_event = h2_event("compressed-pipelined", "R",
        nlohmann::json::array({
            nlohmann::json::array({0, first_tail.size(), "http1.body"}),
            nlohmann::json::array({first_tail.size(),
                                   first_tail.size() + pipelined_line_end,
                                   "http1.start_line"}),
            nlohmann::json::array({first_tail.size() + pipelined_line_end,
                                   second_body_start, "http1.headers"}),
            nlohmann::json::array({second_body_start, pipelined_wire.size(),
                                   "http1.body"}),
        }));
    pipelined_event["details"]["info"]["L7_payload_start"] = {
        0, second_body_start};
    pipelined_event["details"]["info"]["L7_payload_end"] = {
        first_tail.size(), pipelined_wire.size()};
    pipelined_event["details"]["info"]["L7_encoding"] = {"gzip", "gzip"};
    const auto pipelined_output = pipelined_decoding.process(pipelined_event,
                                                             pipelined_wire);
    assert(pipelined_output.size() == 3); // two decoded bodies + parsed H1 head
    for (const auto& item : pipelined_output)
        if (item.metadata.value("operation", "") == "gzip.inflate")
            pipelined_plain += item.payload;
    assert(pipelined_plain == "message Amessage B");

    spider::EnrichmentEngine corrupt_decoding;
    auto corrupt_gzip = compress_payload("payload that must fail its checksum",
                                         16 + MAX_WBITS);
    corrupt_gzip.back() ^= 0x7f;
    assert(corrupt_decoding.process(
        compressed_event("compressed-corrupt", "R", "gzip", corrupt_gzip.size()),
        corrupt_gzip).empty());
    assert(corrupt_decoding.diagnostics()["content_decoding"]["decode_errors"] == 1);

    spider::EnrichmentEngine truncated_decoding;
    [[maybe_unused]] const auto truncated_output = truncated_decoding.process(
        compressed_event("compressed-truncated", "R", "gzip", skipped_cut),
        std::string_view(chunked_gzip).substr(0, skipped_cut));
    truncated_decoding.observe({{"action", "connection-stop"},
                                 {"id", "compressed-truncated"}});
    assert(truncated_decoding.diagnostics()["content_decoding"]["truncated_streams"] == 1);

    const nlohmann::json filter_event = {
        {"action", "connection-content"}, {"id", "filter-session"},
        {"details", {{"info", {{"session", "ssli_192.168.99.1:45678+ssli_142.251.154.4:443"},
                                  {"side", "L"}}}}},
    };
    std::string filter_error;
    auto filter = spider::SessionFilter::compile(
        "tcp and src host 192.168.99.1 and dst port 443 and not side r", filter_error);
    assert(filter && filter->matches(filter_event));
    auto other = spider::SessionFilter::compile("udp or dst host 1.1.1.1", filter_error);
    assert(other && !other->matches(filter_event));
    assert(!spider::SessionFilter::compile("dst banana 443", filter_error));
    assert(!filter_error.empty());

    spider::SessionStore store(2);
    spider::DecisionBroker decisions(std::chrono::milliseconds(100));
    const nlohmann::json start = {
        {"action", "connection-start"}, {"id", "42"},
        {"details", {{"info", {{"session", "tcp 10.0.0.1:1 -> 10.0.0.2:443"}}}}},
    };
    const auto reply = spider::process_webhook(store, decisions, start);
    assert(reply.status == 200);
    assert(store.snapshot()["sessions"].size() == 1);
    assert(store.snapshot()["sessions"][0]["id"] == "42");
    assert(store.status()["callbacks_received"] == 1);
    assert(store.status()["active_sessions"] == 1);
    assert(store.status()["last_callback"]["action"] == "connection-start");
    assert(store.status()["last_callback"]["received_at_ms"].get<std::int64_t>() > 0);
    const auto initial_diagnostics = store.diagnostics();
    assert(initial_diagnostics["callbacks"]["received"] == 1);
    assert(initial_diagnostics["callbacks"]["by_action"]["connection-start"] == 1);
    assert(initial_diagnostics["event_history"]["retained"] == 1);

    assert(spider::process_webhook(store, decisions,
        {{"action", "connection-info"}, {"id", "42"},
         {"details", {{"info", {{"classification", {
             {"sift", {"protocol.http2", "protocol.http2.prior-knowledge"}},
             {"lored", {"service.youtube", "infra.google"}},
             {"lored_status", "matched"}
         }}}}}}}).status == 200);
    assert(store.snapshot()["sessions"][0]["classification"]["sift"].size() == 2);
    assert(store.snapshot()["sessions"][0]["classification"]["lored"].size() == 2);
    assert(store.snapshot()["sessions"][0]["classification"]["lored_status"] == "matched");
    assert(spider::process_webhook(store, decisions, {{"action", "connection-stop"}, {"id", "42"}}).status == 200);
    assert(store.snapshot()["sessions"].empty());
    assert(store.session_history()["sessions"].size() == 1);
    assert(store.session_history()["sessions"][0]["state"] == "completed");
    const auto detail = store.session_detail("42");
    assert(detail.has_value());
    assert((*detail)["events"].size() == 3);
    assert((*detail)["classification"]["sift"][0] == "protocol.http2");
    assert((*detail)["classification"]["lored"][0] == "infra.google");
    assert((*detail)["ended_at_ms"].get<std::int64_t>() > 0);
    assert(store.events_after(0)["events"].size() == 2);
    assert(store.diagnostics()["event_history"]["evicted"] == 1);

    store.apply({{"action", "spider-smithproxy-status"}, {"state", "connected"}});
    assert(store.status()["ready"] == true);
    assert(store.status()["callbacks_received"] == 3);
    assert(store.status()["smithproxy"].contains("spider_received_at_ms"));

    const auto invalid = spider::process_webhook(store, decisions, {{"action", "wat"}});
    assert(invalid.status == 422);
    const auto info = spider::process_webhook(store, decisions, {{"action", "info"}});
    assert(info.status == 200);
    assert(info.body["action"] == "info-response");
    assert(info.body["protocols"]["connection-content"][0] == "sxbn-001");

    const nlohmann::json hostnames = {
        {"action", "hostname-info"},
        {"details", {{"info", {{"list", nlohmann::json::array({
            {{"origin", "dns"}, {"type", "ipv4"}, {"address", {"192.0.2.1"}},
             {"hostname", "long-leaf.example.com"}},
            {{"origin", "sni"}, {"type", "ipv4"}, {"address", {"192.0.2.1"}},
             {"hostname", "a.example.com"}},
            {{"origin", "dns"}, {"type", "ipv4"}, {"address", {"192.0.2.1"}},
             {"hostname", "example.com."}},
            {{"origin", "dns"}, {"type", "ipv4"}, {"address", {"192.0.2.2"}},
             {"hostname", "frontend.example.com"}},
            {{"origin", "dns"}, {"type", "ipv4"}, {"address", {"192.0.2.2"}},
             {"hostname", "api.example.com"}},
        })}}}}},
    };
    assert(spider::process_webhook(store, decisions, hostnames).status == 200);
    const auto reverse = store.reverse_hostnames();
    assert(reverse["revision"] == 1);
    assert(reverse["mappings"]["192.0.2.1"]["preferred"] == "example.com");
    assert(reverse["mappings"]["192.0.2.1"]["candidates"].size() == 3);
    assert(reverse["mappings"]["192.0.2.1"]["entries"][0]["origins"][0] == "dns");
    assert(reverse["mappings"]["192.0.2.2"]["preferred"] == "api.example.com");

    assert(store.clear_completed_sessions() == 1);
    assert(store.session_history()["sessions"].empty());

    spider::SessionStore ring(20, 2);
    for (const char* id : {"1", "2", "3"}) {
        ring.apply({{"action", "connection-start"}, {"id", id}});
        ring.apply({{"action", "connection-stop"}, {"id", id}});
    }
    assert(ring.session_history()["sessions"].size() == 2);
    assert(!ring.session_detail("1").has_value());
    assert(ring.diagnostics()["sessions"]["sessions_evicted"] == 1);
    ring.apply({{"action", "connection-start"}, {"id", "active"}});
    assert(ring.clear_completed_sessions() == 2);
    assert(ring.snapshot()["sessions"].size() == 1);
    assert(ring.session_history()["sessions"].size() == 1);

    spider::DecisionBroker live(std::chrono::seconds(1));
    live.handle_message({{"type", "live-edit"}, {"enabled", true}});
    nlohmann::json content{{"action", "connection-content"}, {"id", "live-1"}};
    const auto ticket = live.prepare(content);
    assert(ticket);
    assert(content["decision"]["state"] == "pending");
    auto waiting = std::async(std::launch::async, [&] { return live.wait(ticket, content); });
    live.handle_message({{"type", "decision"}, {"decision_id", ticket->id},
                         {"action", "accept-session"}});
    assert(waiting.get().body["action"] == "unchanged");
    nlohmann::json next_content{{"action", "connection-content"}, {"id", "live-1"}};
    assert(!live.prepare(next_content));

    spider::DecisionBroker refined(std::chrono::seconds(1));
    refined.handle_message({{"type", "live-edit"}, {"enabled", true}});
    const nlohmann::json rules_message{{"type", "auto-accept-rules"},
                                      {"rules", nlohmann::json::array({
        {{"id", "google-https"},
         {"filter", "src host 192.168.99.1 and dst host 142.251.154.4 and dst port 443"},
         {"enabled", true}},
    })}};
    const auto rule_status = refined.set_auto_accept_rules(rules_message);
    assert(rule_status["accepted"].size() == 1);
    assert(rule_status["errors"].empty());
    auto accepted_event = filter_event;
    assert(!refined.prepare(accepted_event));
    assert(accepted_event["decision"]["state"] == "auto-accepted");
    assert(accepted_event["decision"]["rule_id"] == "google-https");
    assert(refined.auto_accept_rule_status()["counts"][0]["matches"] == 1);
    const auto preserved_status = refined.set_auto_accept_rules(rules_message);
    assert(preserved_status["counts"][0]["matches"] == 1);

    spider::DecisionBroker traffic(std::chrono::seconds(1));
    const auto traffic_status = traffic.set_traffic_rules({{"rules", nlohmann::json::array({
        {{"address", "1.1.1.1"}, {"mode", "forget"}},
        {{"address", "192.168.99.1"}, {"mode", "focus"}},
    })}});
    assert(traffic_status["errors"].empty());
    auto forgotten = filter_event;
    forgotten["details"]["info"]["session"] = "tcp_10.0.0.1:1234+tcp_1.1.1.1:443";
    assert(!traffic.prepare(forgotten));
    assert(forgotten["decision"]["state"] == "forgotten");
    assert(traffic.wait({}, forgotten).body["action"] == "not-interested");

    const auto migrated_status = traffic.set_traffic_rules({{"rules", nlohmann::json::array({
        {{"address", "1.1.1.1"}, {"mode", "ignore"}},
    })}});
    assert(migrated_status["errors"].empty());
    assert(migrated_status["rules"][0]["mode"] == "forget");

    const auto restored_after_migration = traffic.set_traffic_rules({{"rules", nlohmann::json::array({
        {{"address", "1.1.1.1"}, {"mode", "forget"}},
        {{"address", "192.168.99.1"}, {"mode", "focus"}},
    })}});
    assert(restored_after_migration["errors"].empty());
    auto focused = filter_event;
    assert(!traffic.prepare(focused));
    assert(focused["traffic_rule"]["mode"] == "focus");
    auto passed = filter_event;
    passed["details"]["info"]["session"] = "tcp_10.0.0.1:1234+tcp_8.8.8.8:443";
    assert(!traffic.prepare(passed));
    assert(passed["decision"]["state"] == "passed");

    const auto bypass_status = traffic.set_traffic_rules({
        {"bypass_all", true}, {"rules", nlohmann::json::array()}});
    assert(bypass_status["bypass_all"] == true);
    auto bypassed = filter_event;
    assert(!traffic.prepare(bypassed));
    assert(bypassed["decision"]["state"] == "passed");
    assert(bypassed["decision"]["reason"] == "bypass-all");

    spider::DecisionBroker classified(std::chrono::seconds(1));
    const auto classified_status = classified.set_traffic_rules({{"rules", nlohmann::json::array({
        {{"id", "sift-youtube"}, {"kind", "sift"}, {"value", "app.youtube.video"},
         {"mode", "pass"}},
    })}});
    assert(classified_status["errors"].empty());
    auto before_classification = filter_event;
    assert(!classified.prepare(before_classification));
    assert(!before_classification.contains("decision"));
    classified.observe({{"action", "connection-info"}, {"id", "filter-session"},
                        {"details", {{"info", {{"classification", {{"sift",
                            nlohmann::json::array({"app.youtube.video"})}}}}}}}});
    auto after_classification = filter_event;
    assert(!classified.prepare(after_classification));
    assert(after_classification["decision"]["state"] == "passed");

    spider::DecisionBroker classified_glob(std::chrono::seconds(1));
    const auto glob_status = classified_glob.set_traffic_rules({{"rules", nlohmann::json::array({
        {{"id", "sift-http"}, {"kind", "sift-glob"}, {"value", "protocol.http*"},
         {"mode", "pass"}},
    })}});
    assert(glob_status["errors"].empty());
    classified_glob.observe({{"action", "connection-info"}, {"id", "filter-session"},
                             {"details", {{"info", {{"classification", {{"sift",
                                 nlohmann::json::array({"protocol.http2"})}}}}}}}});
    auto globbed = filter_event;
    assert(!classified_glob.prepare(globbed));
    assert(globbed["decision"]["state"] == "passed");

    const auto restored_traffic_status = traffic.set_traffic_rules({{"rules", nlohmann::json::array({
        {{"address", "1.1.1.1"}, {"mode", "forget"}},
        {{"address", "192.168.99.1"}, {"mode", "focus"}},
    })}});
    assert(restored_traffic_status["errors"].empty());
    spider::SessionStore traffic_store(20);
    const auto forgotten_reply = spider::process_webhook(traffic_store, traffic, forgotten);
    assert(forgotten_reply.status == 200);
    assert(forgotten_reply.body["action"] == "not-interested");
    assert(traffic_store.events_after(0)["events"].empty());
    assert(spider::process_webhook(traffic_store, traffic, passed).status == 200);
    assert(traffic_store.events_after(0)["events"].size() == 1);

    spider::DecisionBroker inspection(std::chrono::seconds(1));
    inspection.handle_message({{"type", "script-available"}, {"available", true}});
    const auto inspection_status = inspection.set_traffic_rules({{"rules", nlohmann::json::array({
        {{"address", "192.168.99.1"}, {"mode", "inspect"}},
    })}});
    assert(inspection_status["errors"].empty());
    auto inspected = filter_event;
    const auto inspection_ticket = inspection.prepare(inspected);
    assert(inspection_ticket);
    assert(inspected["decision"]["mode"] == "inspect");
}
