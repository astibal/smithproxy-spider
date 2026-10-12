#include "decision_broker.hpp"
#include "binary_envelope.hpp"
#include "session_filter.hpp"
#include "session_store.hpp"
#include "webhook.hpp"

#include <cassert>
#include <cstdio>
#include <future>

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

    assert(spider::process_webhook(store, decisions,
        {{"action", "connection-info"}, {"id", "42"},
         {"details", {{"info", {{"classification", {{"sift", {
             "protocol.http2", "protocol.http2.prior-knowledge"}}}}}}}}}).status == 200);
    assert(store.snapshot()["sessions"][0]["classification"]["sift"].size() == 2);
    assert(spider::process_webhook(store, decisions, {{"action", "connection-stop"}, {"id", "42"}}).status == 200);
    assert(store.snapshot()["sessions"].empty());
    assert(store.session_history()["sessions"].size() == 1);
    assert(store.session_history()["sessions"][0]["state"] == "completed");
    const auto detail = store.session_detail("42");
    assert(detail.has_value());
    assert((*detail)["events"].size() == 3);
    assert((*detail)["classification"]["sift"][0] == "protocol.http2");
    assert((*detail)["ended_at_ms"].get<std::int64_t>() > 0);
    assert(store.events_after(0)["events"].size() == 2);

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
    auto waiting = std::async(std::launch::async, [&] { return live.wait(ticket); });
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
        {{"address", "1.1.1.1"}, {"mode", "ignore"}},
        {{"address", "192.168.99.1"}, {"mode", "focus"}},
    })}});
    assert(traffic_status["errors"].empty());
    auto ignored = filter_event;
    ignored["details"]["info"]["session"] = "tcp_10.0.0.1:1234+tcp_1.1.1.1:443";
    assert(!traffic.prepare(ignored));
    assert(ignored["decision"]["state"] == "ignored");
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
    classified.observe({{"action", "connection-info"}, {"id", "filter-1"},
                        {"details", {{"info", {{"classification", {{"sift",
                            nlohmann::json::array({"app.youtube.video"})}}}}}}}});
    auto after_classification = filter_event;
    assert(!classified.prepare(after_classification));
    assert(after_classification["decision"]["state"] == "passed");

    spider::SessionStore traffic_store(20);
    assert(spider::process_webhook(traffic_store, traffic, ignored).status == 200);
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
