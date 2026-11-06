#include "inspection.hpp"
#include "webhook.hpp"
#include "session_store.hpp"
#include "decision_broker.hpp"
#include "binary_envelope.hpp"
#include <cassert>
#include <iostream>

using nlohmann::json;

int main() {
    spider::Inspection inspection;
    spider::SessionStore store;
    spider::DecisionBroker decisions(std::chrono::milliseconds(100));
    auto configure = [&](json request) {
        request["revision"] = inspection.status()["revision"];
        return inspection.configure(request);
    };
    auto deploy = [&](const std::string& name, const std::string& script) {
        const auto result = configure({{"operation", "deploy"}, {"name", name},
            {"script", script}, {"scope", "all"}, {"instancing", "flow"},
            {"tls_clienthello", true}});
        const auto id = result["chain"].back()["id"];
        configure({{"operation", "enable"}, {"id", id}, {"enabled", true}});
    };
    deploy("native", R"PY(
def main(api, state):
    if api.tls is None:
        api.state['setup'] = True
        api.state['version'] = api.instance.version
        return
    assert api.state['setup']
    assert api.state['version'] == api.instance.version
    hello = api.tls.client_hello
    hello.sni = 'native.invalid'
    hello.openssl_cipher_list = 'ECDHE+AESGCM'
    return hello.commit()
)PY");
    deploy("second native", R"PY(
def main(api, state):
    if api.tls is not None:
        hello = api.tls.client_hello
        assert hello.sni == 'native.invalid'
        assert hello.openssl_cipher_list == 'ECDHE+AESGCM'
        hello.sni = 'second.invalid'
        return hello.commit()
)PY");

    auto send = [&](const json& event) {
        return spider::process_webhook(store, decisions, event, std::nullopt, nullptr, &inspection);
    };
    const auto setup = send({{"action", "connection-start"}, {"id", "hello-test"},
        {"details", {{"info", {{"session", "tcp_10.0.0.1:1000+tcp_10.0.0.2:443"}}}}}});
    assert(setup.status == 200);
    assert(setup.body["control"]["tls_clienthello_schema"] == 2);

    // Minimal complete TLS ClientHello with one cipher and no extensions.
    std::string hello("\x03\x03", 2);
    hello.append(32, '\0');
    hello.append("\x00\x00\x02\x13\x01\x01\x00", 7);
    const json envelope = {{"version", 1}, {"connection_id", "hello-test"},
        {"attempt", 1U}, {"side", "client"}, {"event", "client-hello"}};
    json observation = {{"envelope", envelope}, {"schema", 2}, {"client_hello", {
        {"original", {{"body_base64", spider::base64_encode(hello)}}},
        {"sni", "original.invalid"}, {"alpn_offers", json::array()},
        {"openssl_cipher_list", nullptr}, {"decision", "continue"}
    }}};
    auto event = json{{"action", "tls-lifecycle"}, {"id", "hello-test"},
        {"details", {{"tls", observation}}}};
    auto result = send(event);
    if(result.status != 200) std::cerr << result.body.dump(2) << '\n';
    assert(result.status == 200);
    assert(result.body["schema"] == 2);
    assert(result.body["client_hello"]["sni"] == "second.invalid");
    assert(result.body["client_hello"]["openssl_cipher_list"] == "ECDHE+AESGCM");
    assert(!result.body.contains("upstream"));
    assert(!result.body["client_hello"].contains("original"));

    auto malformed = event;
    malformed["details"]["tls"]["client_hello"]["alpn_offers"] = "not a list";
    assert(send(malformed).status == 400);

    // Older native producers still use the version-1 body and reply schema.
    send({{"action", "connection-start"}, {"id", "legacy-test"},
        {"details", {{"info", {{"session", "tcp_10.0.0.1:1001+tcp_10.0.0.2:443"}}}}}});
    auto legacy_envelope = envelope;
    legacy_envelope["connection_id"] = "legacy-test";
    const auto legacy = send({{"action", "tls-lifecycle"}, {"id", "legacy-test"},
        {"details", {{"tls", {
            {"envelope", legacy_envelope}, {"client_hello_base64", spider::base64_encode(hello)},
            {"upstream", {{"sni", "original.invalid"}, {"alpn_base64", ""},
                {"openssl_cipher_list", nullptr}}}
        }}}}});
    assert(legacy.status == 200);
    assert(legacy.body["upstream"]["sni"] == "second.invalid");
    assert(!legacy.body.contains("schema"));
    send({{"action", "connection-stop"}, {"id", "legacy-test"}});

    // Duplicate delivery cannot repeat native or addon user code.
    assert(send(event).status == 503);
    send({{"action", "connection-stop"}, {"id", "hello-test"}});
    event["details"]["tls"]["envelope"]["attempt"] = 2U;
    assert(send(event).status == 503);
    std::cout << "PASS: native ClientHello chain, schema and retirement\n";

    // A fresh runtime owns all native TLS notifications; the content state and
    // attempt guards survive interleaved callbacks and independent sides.
    spider::Inspection lifecycle;
    auto deployment = lifecycle.configure({{"revision", lifecycle.status()["revision"]},
        {"operation", "deploy"}, {"name", "native TLS"}, {"scope", "all"},
        {"instancing", "flow"}, {"tls_lifecycle", true}, {"tls_start_server", true},
        {"tls_start_client", true}, {"quic_start_server", true}, {"script", R"PY(
def main(api, state):
    if api.tls is None:
        api.state['ready'] = True
        return
    assert api.state['ready']
    if api.tls.event is TlsEvent.START:
        draft = api.tls.start
        if api.tls.side is TlsSide.SERVER:
            draft.sni = 'meta.invalid'
        return draft.commit()
    draft = api.tls.outcome
    if api.tls.event is TlsEvent.ESTABLISHED:
        draft.decision = TlsDecision.TERMINATE
    return draft.commit()
)PY"}});
    lifecycle.configure({{"revision", lifecycle.status()["revision"]}, {"operation", "enable"},
        {"id", deployment["chain"][0]["id"]}, {"enabled", true}});
    auto notify = [&](const json& input) {
        return spider::process_webhook(store, decisions, input, std::nullopt, nullptr, &lifecycle);
    };

    for(const std::string protocol : {"tls", "quic"}) {
        const auto id = "native-" + protocol;
        const auto initialized = notify({{"action", "connection-start"}, {"id", id},
            {"details", {{"info", {{"session", "tcp_10.0.0.1:1002+tcp_10.0.0.2:443"}}}}}});
        assert(initialized.status == 200);
        assert(initialized.body["control"][protocol + "_schema"] == 2);
        for(const std::string side : {"server", "client"}) {
            json identity = {{"version", 1}, {"connection_id", id}, {"attempt", 1U},
                             {"side", side}, {"event", "start"}};
            json draft = {{"sni", "origin.invalid"}, {"alpn_offers", {"aDI="}},
                          {"openssl_cipher_list", "DEFAULT"}, {"openssl_ciphersuites", nullptr}};
            auto notification = json{{"action", protocol + "-lifecycle"}, {"id", id},
                {"details", {{protocol, {{"envelope", identity}, {"schema", 2}, {"start", draft}}}}}};
            if(protocol != "quic" || side == "server") {
                const auto start_reply = notify(notification);
                if(start_reply.status != 200) std::cerr << start_reply.body.dump(2) << '\n';
                assert(start_reply.status == 200);
                assert(start_reply.body["start"]["sni"] == (side == "server" ? "meta.invalid" : "origin.invalid"));
                assert(notify(notification).status == 503);
            }

            identity["event"] = "established";
            notification["details"][protocol] = {{"schema", 2}, {"envelope", identity},
                {"outcome", {{"sni", "meta.invalid"}, {"alpn", "aDI="},
                    {"cipher", "TLS_AES_128_GCM_SHA256"}, {"tls_version", "TLSv1.3"},
                    {"certificates", json::array()}, {"error", nullptr}}}};
            const auto outcome = notify(notification);
            assert(outcome.status == 200);
            assert(outcome.body["outcome"]["decision"] == "terminate");
            assert(!outcome.body["outcome"].contains("certificates"));
            assert(notify(notification).status == 503);

            // A fresh failed attempt is observable; no fabricated start is
            // required. The notification cannot reverse a native failure.
            notification["details"][protocol]["envelope"]["event"] = "failed";
            notification["details"][protocol]["envelope"]["attempt"] = 2U;
            notification["details"][protocol]["outcome"]["error"] = "handshake timeout";
            const auto failed = notify(notification);
            assert(failed.status == 200);
            assert(failed.body["outcome"]["decision"] == "continue");

            auto unknown = notification;
            unknown["details"][protocol]["schema"] = 3;
            assert(notify(unknown).status == 400);
        }
        notify({{"action", "connection-stop"}, {"id", id}});
    }
    std::cout << "PASS: native TLS/QUIC start, outcomes, schema and duplicate guards\n";
}
