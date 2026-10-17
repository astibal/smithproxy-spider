#include "websocket_hub.hpp"

#include "binary_envelope.hpp"

#include <openssl/evp.h>
#include <openssl/sha.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <limits>
#include <thread>
#include <chrono>

#include <sys/socket.h>
#include <poll.h>

namespace spider {
namespace {

std::int64_t unix_time_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool send_all(const int socket, const unsigned char* data, std::size_t size) {
    while (size > 0) {
        const auto sent = ::send(socket, data, size, MSG_NOSIGNAL);
        if (sent > 0) {
            data += static_cast<std::size_t>(sent);
            size -= static_cast<std::size_t>(sent);
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            pollfd descriptor{socket, POLLOUT, 0};
            if (::poll(&descriptor, 1, 1000) > 0) continue;
        }
        return false;
    }
    return true;
}

std::string websocket_accept(const std::string_view key) {
    const auto source = std::string(key) + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    std::array<unsigned char, SHA_DIGEST_LENGTH> digest{};
    SHA1(reinterpret_cast<const unsigned char*>(source.data()), source.size(), digest.data());
    std::array<unsigned char, 4 * ((SHA_DIGEST_LENGTH + 2) / 3) + 1> encoded{};
    const auto length = EVP_EncodeBlock(encoded.data(), digest.data(), digest.size());
    return std::string(reinterpret_cast<const char*>(encoded.data()), static_cast<std::size_t>(length));
}

bool protocol_has(const std::string_view protocols, const std::string_view expected) {
    std::size_t begin{};
    while (begin < protocols.size()) {
        auto end = protocols.find(',', begin);
        if (end == std::string_view::npos) end = protocols.size();
        auto item = protocols.substr(begin, end - begin);
        while (!item.empty() && item.front() == ' ') item.remove_prefix(1);
        while (!item.empty() && item.back() == ' ') item.remove_suffix(1);
        if (item == expected) return true;
        begin = end + 1;
    }
    return false;
}

} // namespace

struct WebSocketHub::Client {
    int socket{-1};
    MHD_UpgradeResponseHandle* upgrade_handle{};
    std::mutex write_mutex;
    std::atomic_bool active{};

    bool send_frame(const unsigned char opcode, const std::string_view payload) {
        std::array<unsigned char, 10> header{};
        std::size_t header_size{};
        header[header_size++] = static_cast<unsigned char>(0x80U | opcode);
        if (payload.size() <= 125) {
            header[header_size++] = static_cast<unsigned char>(payload.size());
        } else if (payload.size() <= std::numeric_limits<std::uint16_t>::max()) {
            header[header_size++] = 126;
            header[header_size++] = static_cast<unsigned char>((payload.size() >> 8U) & 0xffU);
            header[header_size++] = static_cast<unsigned char>(payload.size() & 0xffU);
        } else {
            header[header_size++] = 127;
            for (int shift = 56; shift >= 0; shift -= 8) {
                header[header_size++] = static_cast<unsigned char>(
                    (payload.size() >> static_cast<unsigned>(shift)) & 0xffU);
            }
        }
        std::scoped_lock lock(write_mutex);
        return send_all(socket, header.data(), header_size) &&
               send_all(socket, reinterpret_cast<const unsigned char*>(payload.data()), payload.size());
    }

    bool send_text(const std::string_view payload) { return send_frame(0x1U, payload); }
};

WebSocketHub::WebSocketHub(std::string token, MessageHandler handler, EmptyHandler empty_handler)
    : token_(std::move(token)), handler_(std::move(handler)),
      empty_handler_(std::move(empty_handler)) {}

WebSocketHub::~WebSocketHub() { stop(); }

bool WebSocketHub::can_upgrade(MHD_Connection* connection) const {
    const char* upgrade_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Upgrade");
    const char* key = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Sec-WebSocket-Key");
    const char* version = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Sec-WebSocket-Version");
    const char* protocols = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Sec-WebSocket-Protocol");
    return upgrade_header != nullptr && strcasecmp(upgrade_header, "websocket") == 0 &&
           key != nullptr && version != nullptr && std::string_view(version) == "13" &&
           protocols != nullptr && protocol_has(protocols, "spider") &&
           (token_.empty() || protocol_has(protocols, token_));
}

int WebSocketHub::queue_upgrade(MHD_Connection* connection) {
    if (!can_upgrade(connection)) return MHD_NO;
    const char* key = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Sec-WebSocket-Key");
    auto* response = MHD_create_response_for_upgrade(&WebSocketHub::upgrade, this);
    if (response == nullptr) return MHD_NO;
    const auto accept = websocket_accept(key);
    MHD_add_response_header(response, "Upgrade", "websocket");
    MHD_add_response_header(response, "Connection", "Upgrade");
    MHD_add_response_header(response, "Sec-WebSocket-Accept", accept.c_str());
    MHD_add_response_header(response, "Sec-WebSocket-Protocol", "spider");
    const auto result = MHD_queue_response(connection, MHD_HTTP_SWITCHING_PROTOCOLS, response);
    MHD_destroy_response(response);
    return result;
}

void WebSocketHub::upgrade(void* cls, MHD_Connection*, void*, const char* extra_in,
                           const std::size_t extra_in_size, const MHD_socket socket,
                           MHD_UpgradeResponseHandle* handle) {
    auto& hub = *static_cast<WebSocketHub*>(cls);
    auto client = std::make_shared<Client>();
    client->socket = socket;
    client->upgrade_handle = handle;
    timeval send_timeout{1, 0};
    ::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, &send_timeout, sizeof(send_timeout));
    std::string initial;
    if (extra_in != nullptr && extra_in_size > 0) initial.assign(extra_in, extra_in_size);
    {
        std::scoped_lock lock(hub.mutex_);
        ++hub.client_threads_;
        ++hub.connections_total_;
        hub.last_connect_at_ms_ = unix_time_ms();
        hub.clients_.push_back(client);
    }
    std::thread([&hub, client, initial = std::move(initial)]() mutable {
        hub.run_client(client, std::move(initial));
        {
            std::scoped_lock lock(hub.mutex_);
            --hub.client_threads_;
        }
        hub.stopped_.notify_all();
    }).detach();
}

void WebSocketHub::publish(const std::uint64_t revision, const nlohmann::json& event,
                           const std::optional<std::string_view> raw_payload,
                           const std::vector<SxbnEnvelope>& enrichments) {
    constexpr unsigned char text_opcode = 0x1U;
    constexpr unsigned char binary_opcode = 0x2U;
    auto opcode = text_opcode;
    std::string wire;
    if (raw_payload && event.value("action", "") == "connection-content") {
        auto wire_event = event;
        wire_event["details"]["info"].erase("content");
        wire = encode_sxbn({{"type", "event"}, {"key", "event:" + std::to_string(revision)},
                            {"revision", revision}, {"event", std::move(wire_event)}},
                           *raw_payload);
        const auto source_key = "event:" + std::to_string(revision);
        for (std::size_t index = 0; index < enrichments.size(); ++index) {
            auto metadata = enrichments[index].metadata;
            metadata["type"] = "enrichment";
            metadata["key"] = source_key + ":enrichment:" + std::to_string(index);
            if (!metadata.contains("source") || !metadata["source"].is_object()) {
                metadata["source"] = nlohmann::json::object();
            }
            metadata["source"]["envelope"] = source_key;
            wire += encode_sxbn(metadata, enrichments[index].payload);
        }
        opcode = binary_opcode;
    } else {
        wire = nlohmann::json{{"type", "event"}, {"revision", revision}, {"event", event}}.dump();
    }
    std::scoped_lock lock(mutex_);
    ++events_published_;
    publish_bytes_ += wire.size();
    last_publish_at_ms_ = unix_time_ms();
    replay_.push_back({revision, opcode, wire});
    replay_bytes_ += wire.size();
    while (replay_.size() > max_replay_events_ || replay_bytes_ > max_replay_bytes_) {
        replay_bytes_ -= replay_.front().wire.size();
        replay_.pop_front();
        ++events_evicted_;
    }
    std::erase_if(clients_, [&](const auto& weak) {
        const auto client = weak.lock();
        if (!client) return true;
        if (client->active.load() && !client->send_frame(opcode, wire)) {
            ++send_failures_;
            ::shutdown(client->socket, SHUT_RDWR);
        }
        return false;
    });
}

void WebSocketHub::subscribe(const std::shared_ptr<Client>& client, std::uint64_t after,
                             const bool tail) {
    std::scoped_lock lock(mutex_);
    ++subscriptions_total_;
    last_subscribe_at_ms_ = unix_time_ms();
    if (tail && !replay_.empty()) after = replay_.back().revision;
    if (!replay_.empty() && after + 1 < replay_.front().revision) {
        ++gaps_total_;
        client->send_text(nlohmann::json{{"type", "gap"}, {"requested_after", after},
                          {"oldest_available", replay_.front().revision}}.dump());
    }
    for (const auto& item : replay_) {
        if (item.revision > after && !client->send_frame(item.opcode, item.wire)) return;
    }
    client->active.store(true);
    client->send_text(nlohmann::json{{"type", "subscribed"},
                      {"revision", replay_.empty() ? 0 : replay_.back().revision}}.dump());
}

void WebSocketHub::handle_message(const std::shared_ptr<Client>& client, const std::string_view message) {
    {
        std::scoped_lock lock(mutex_);
        ++client_messages_;
    }
    const auto json = nlohmann::json::parse(message, nullptr, false);
    if (json.is_discarded() || !json.is_object()) return;
    if (json.value("type", "") == "subscribe") {
        subscribe(client, json.value("after", std::uint64_t{}), json.value("tail", false));
    } else if (client->active.load() && handler_) {
        if (auto response = handler_(json)) client->send_text(response->dump());
    }
}

void WebSocketHub::run_client(const std::shared_ptr<Client>& client, std::string initial) {
    auto receive = [&](unsigned char* output, std::size_t size) {
        while (size > 0 && !initial.empty()) {
            *output++ = static_cast<unsigned char>(initial.front());
            initial.erase(initial.begin());
            --size;
        }
        while (size > 0) {
            const auto count = ::recv(client->socket, output, size, 0);
            if (count > 0) {
                output += static_cast<std::size_t>(count);
                size -= static_cast<std::size_t>(count);
                continue;
            }
            if (count < 0 && errno == EINTR) continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                pollfd descriptor{client->socket, POLLIN, 0};
                if (::poll(&descriptor, 1, 1000) >= 0) continue;
            }
            return false;
        }
        return true;
    };

    while (!stopping_.load()) {
        std::array<unsigned char, 2> header{};
        if (!receive(header.data(), header.size())) break;
        const auto opcode = static_cast<unsigned char>(header[0] & 0x0fU);
        const bool masked = (header[1] & 0x80U) != 0;
        std::uint64_t length = header[1] & 0x7fU;
        if (length == 126) {
            std::array<unsigned char, 2> extended{};
            if (!receive(extended.data(), extended.size())) break;
            length = (static_cast<std::uint64_t>(extended[0]) << 8U) | extended[1];
        } else if (length == 127) {
            std::array<unsigned char, 8> extended{};
            if (!receive(extended.data(), extended.size())) break;
            length = 0;
            for (const auto value : extended) length = (length << 8U) | value;
        }
        if (!masked || length > 1024U * 1024U) break;
        std::array<unsigned char, 4> mask{};
        if (!receive(mask.data(), mask.size())) break;
        std::string payload(static_cast<std::size_t>(length), '\0');
        if (!payload.empty() && !receive(reinterpret_cast<unsigned char*>(payload.data()), payload.size())) break;
        for (std::size_t i = 0; i < payload.size(); ++i) payload[i] ^= static_cast<char>(mask[i % 4]);
        if (opcode == 0x8U) break;
        if (opcode == 0x9U) {
            if (!client->send_frame(0xAU, payload)) break;
        } else if (opcode == 0x1U) {
            handle_message(client, payload);
        }
    }
    remove_client(client);
    MHD_upgrade_action(client->upgrade_handle, MHD_UPGRADE_ACTION_CLOSE);
}

void WebSocketHub::remove_client(const std::shared_ptr<Client>& client) {
    client->active.store(false);
    bool empty{};
    {
        std::scoped_lock lock(mutex_);
        std::erase_if(clients_, [&](const auto& weak) {
            const auto current = weak.lock();
            return !current || current == client;
        });
        ++disconnects_total_;
        last_disconnect_at_ms_ = unix_time_ms();
        empty = std::none_of(clients_.begin(), clients_.end(), [](const auto& weak) {
            const auto current = weak.lock();
            return current && current->active.load();
        });
    }
    if (empty && empty_handler_) empty_handler_();
}

nlohmann::json WebSocketHub::diagnostics() const {
    std::scoped_lock lock(mutex_);
    std::size_t connected{};
    std::size_t subscribed{};
    for (const auto& weak : clients_) {
        if (const auto client = weak.lock()) {
            ++connected;
            if (client->active.load()) ++subscribed;
        }
    }
    return {
        {"clients", {{"connected", connected}, {"subscribed", subscribed},
                     {"threads", client_threads_}, {"connections_total", connections_total_},
                     {"disconnects_total", disconnects_total_}}},
        {"stream", {{"events_published", events_published_}, {"publish_bytes", publish_bytes_},
                    {"send_failures", send_failures_}, {"client_messages", client_messages_},
                    {"subscriptions", subscriptions_total_}, {"gaps", gaps_total_}}},
        {"replay", {{"events", replay_.size()}, {"bytes", replay_bytes_},
                    {"event_limit", max_replay_events_}, {"byte_limit", max_replay_bytes_},
                    {"evicted", events_evicted_},
                    {"oldest_revision", replay_.empty() ? 0 : replay_.front().revision},
                    {"newest_revision", replay_.empty() ? 0 : replay_.back().revision}}},
        {"timestamps", {{"last_connect_at_ms", last_connect_at_ms_},
                        {"last_disconnect_at_ms", last_disconnect_at_ms_},
                        {"last_subscribe_at_ms", last_subscribe_at_ms_},
                        {"last_publish_at_ms", last_publish_at_ms_}}},
    };
}

void WebSocketHub::stop() {
    if (stopping_.exchange(true)) return;
    std::unique_lock lock(mutex_);
    for (const auto& weak : clients_) {
        if (const auto client = weak.lock()) ::shutdown(client->socket, SHUT_RDWR);
    }
    clients_.clear();
    stopped_.wait(lock, [&] { return client_threads_ == 0; });
}

} // namespace spider
