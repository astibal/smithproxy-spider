#include "collection.hpp"
#include <chrono>
#include <cstdlib>
#include <fcntl.h>
#include <unistd.h>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <algorithm>
#include <sys/stat.h>
#include <cctype>
#include <ctime>
#include <set>

namespace spider {
namespace {
std::string directory_name(const std::string& endpoint) {
    // Readable prefix plus deterministic hash; no user-controlled path components.
    std::string prefix;
    std::uint64_t hash = 14695981039346656037ULL;
    for (unsigned char ch : endpoint) {
        hash = (hash ^ ch) * 1099511628211ULL;
        if (prefix.size() < 60) prefix += ((ch >= 'a' && ch <= 'z') ||
            (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '.') ? char(ch) : '_';
    }
    std::ostringstream name; name << "endpoint-" << prefix << '-' << std::hex << hash;
    return name.str();
}
nlohmann::json flow_file(const std::filesystem::path& root, const std::string& id, bool summary) {
    if (id.empty() || id.size() > 80 || !std::all_of(id.begin(), id.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
    })) throw std::runtime_error("Invalid saved session id");
    const int parent = open(root.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (parent < 0) throw std::runtime_error("Collection directory unavailable");
    const int dir = openat(parent, "saved-sessions", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    close(parent);
    if (dir < 0) throw std::runtime_error("Saved sessions unavailable");
    const int fd = openat(dir, (id + ".flow").c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    close(dir);
    if (fd < 0) throw std::runtime_error("Saved session unavailable");
    struct stat info{};
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size > 64 * 1024 * 1024) {
        close(fd); throw std::runtime_error("Invalid or oversized saved session");
    }
    std::string data;
    char buffer[4096];
    for (;;) {
        const auto count = ::read(fd, buffer, sizeof(buffer));
        if (count < 0) { close(fd); throw std::runtime_error("Cannot read saved session"); }
        if (!count) break;
        data.append(buffer, static_cast<std::size_t>(count));
        if (summary && data.find('\n') != std::string::npos) break;
        if (summary && data.size() > 8192) { close(fd); throw std::runtime_error("Invalid session summary"); }
    }
    close(fd);
    const auto separator = data.find('\n');
    if (separator == std::string::npos) throw std::runtime_error("Incomplete saved session");
    return nlohmann::json::parse(summary ? data.substr(0, separator) : data.substr(separator + 1));
}
std::string lowercase(std::string text) {
    for (auto& c : text) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return text;
}
std::size_t content_size(const nlohmann::json& content) {
    if (!content.is_string()) return 0;
    const auto& text = content.get_ref<const std::string&>();
    if (text.empty() || text.size() % 4 != 0) return 0;
    return text.size() / 4 * 3 - (text.back() == '=' ? 1 : 0) -
        (text.size() > 1 && text[text.size() - 2] == '=' ? 1 : 0);
}
nlohmann::json flow_summary(const nlohmann::json& snapshot) {
    std::size_t bytes = 0;
    std::set<std::string> connections;
    for (const auto& record : snapshot.at("records")) {
        const auto event = record.at("event");
        connections.insert(event.value("id", ""));
        bytes += content_size(event.value("details", nlohmann::json::object())
            .value("info", nlohmann::json::object()).value("content", nlohmann::json("")));
    }
    const auto scope = snapshot.at("scope");
    auto description = scope.value("label", "");
    if (scope.value("type", "") != "connection") {
        description = scope.value("sourceHost", "?") + " → " + scope.value("destinationHost", "*");
        if (scope.contains("destinationPort")) description += ":" +
            (scope["destinationPort"].is_string() ? scope["destinationPort"].get<std::string>() : scope["destinationPort"].dump());
    }
    auto end = std::min<std::size_t>(512, description.size());
    while (end && end < description.size() && (static_cast<unsigned char>(description[end]) & 0xc0) == 0x80) --end;
    description.resize(end);
    return {{"id", snapshot.at("id")}, {"name", snapshot.at("name")}, {"saved_at_ms", snapshot.at("saved_at_ms")},
        {"records", snapshot.at("records").size()}, {"bytes", bytes}, {"connections", connections.size()},
        {"description", description}};
}
}
Collection::Collection(std::filesystem::path root, std::uint64_t limit) : root_(std::move(root)), limit_(limit) {
    if (root_.empty()) {
        const char* configured = std::getenv("SPIDER_COLLECTION_DIR");
        root_ = configured ? configured : "collections";
    }
    if (const char* value = std::getenv("SPIDER_COLLECTION_MAX_BYTES")) {
        try { limit_ = std::stoull(value); } catch (...) { last_error_ = "Invalid SPIDER_COLLECTION_MAX_BYTES"; limit_ = 0; }
    }
    try {
        if (std::filesystem::exists(root_))
            for (const auto& entry : std::filesystem::recursive_directory_iterator(root_))
                if (entry.is_regular_file()) bytes_ += entry.file_size();
    } catch (const std::exception& e) { last_error_ = e.what(); limit_ = 0; }
}
void Collection::capture(const nlohmann::json& event, const nlohmann::json& enrichments,
                         const nlohmann::json& session) {
    if (!event.contains("collections")) return;
    std::scoped_lock lock(mutex_);
    for (const auto& target : event["collections"]) {
        std::string temporary;
        int fd = -1;
        try {
            const auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
            const auto data = nlohmann::json{{"format", "spider-sample-v1"}, {"captured_at_ms", timestamp},
                {"collection", target}, {"event", event}, {"enrichments", enrichments},
                {"session_context", session}, {"capture_stage", "before-inspection"},
                {"context_note", "Available bounded session history at capture time; not a complete connection replay"}}.dump();
            if (bytes_ >= limit_ || data.size() > limit_ - bytes_) throw std::runtime_error("Collection disk budget exhausted");
            const auto directory = root_ / directory_name(target.at("endpoint").get<std::string>());
            if (std::filesystem::create_directories(root_))
                std::filesystem::permissions(root_, std::filesystem::perms::owner_all);
            if (std::filesystem::create_directory(directory))
                std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
            temporary = (directory / (std::to_string(timestamp) + "-XXXXXX")).string();
            fd = mkstemp(temporary.data()); // exclusive, 0600; never overwrite samples
            if (fd < 0) throw std::runtime_error("Cannot create collection sample");
            std::size_t offset = 0;
            while (offset < data.size()) {
                const auto size = write(fd, data.data() + offset, data.size() - offset);
                if (size <= 0) throw std::runtime_error("Cannot write collection sample");
                offset += size;
            }
            if (fsync(fd) != 0) throw std::runtime_error("Cannot flush collection sample");
            close(fd); fd = -1;
            std::filesystem::rename(temporary, temporary + ".json");
            bytes_ += data.size(); ++saved_; last_error_.clear();
        } catch (const std::exception& e) {
            if (fd >= 0) close(fd);
            if (!temporary.empty()) unlink(temporary.c_str());
            ++errors_; last_error_ = e.what();
        }
    }
}
nlohmann::json Collection::status() const {
    std::scoped_lock lock(mutex_);
    return {{"directory", root_.string()}, {"bytes", bytes_}, {"limit_bytes", limit_},
        {"saved", saved_}, {"errors", errors_}, {"last_error", last_error_}};
}
nlohmann::json Collection::describe(const std::string& id) const {
    try {
        const auto modified = std::filesystem::last_write_time(root_ / id);
        const auto size = std::filesystem::file_size(root_ / id);
        {
            std::scoped_lock lock(summary_mutex_);
            const auto cached = summaries_.find(id);
            if (cached != summaries_.end() && cached->second.modified == modified && cached->second.size == size)
                return cached->second.value;
        }
        const auto sample = read(id);
        const auto event = sample.value("event", nlohmann::json::object());
        const auto info = event.value("details", nlohmann::json::object()).value("info", nlohmann::json::object());
        const auto clipped = [](const std::string& text) {
            auto end = std::min<std::size_t>(512, text.size());
            while (end && end < text.size() && (static_cast<unsigned char>(text[end]) & 0xc0) == 0x80) --end;
            return text.substr(0, end);
        };
        std::set<std::string> protocols, operations, types, encodings;
        std::set<std::uint32_t> streams;
        std::string method, target, status, authority;
        auto messages = nlohmann::json::array();
        for (const auto& annotation : info.value("content_annotations", nlohmann::json::array())) {
            if (!annotation.is_array() || annotation.size() < 3 || !annotation[2].is_string()) continue;
            const auto kind = annotation[2].get<std::string>();
            if (kind.starts_with("h2.")) protocols.insert("HTTP/2");
            else if (kind.starts_with("http1.")) protocols.insert("HTTP/1");
            else protocols.insert(clipped(kind.substr(0, kind.find('.'))));
        }
        std::size_t decoded_bytes = 0;
        for (const auto& item : sample.value("enrichments", nlohmann::json::array())) {
            method.clear(); target.clear(); status.clear(); authority.clear();
            const auto metadata = item.value("metadata", nlohmann::json::object());
            const auto operation = metadata.value("operation", "");
            const auto source = metadata.value("source", nlohmann::json::object());
            if (source.contains("stream_id") && source["stream_id"].is_number_unsigned())
                streams.insert(source["stream_id"].get<std::uint32_t>());
            if (!operation.empty()) operations.insert(clipped(operation));
            if (operation == "hpack.decode") protocols.insert("HTTP/2");
            if (operation == "http1.parse-head") protocols.insert("HTTP/1");
            if (operation == "gzip.inflate" || operation == "deflate.inflate")
                decoded_bytes += content_size(item.value("content", nlohmann::json("")));
            const auto message = metadata.value("message", nlohmann::json::object());
            if (message.contains("method")) method = message.value("method", "");
            if (message.contains("target")) target = message.value("target", "");
            if (message.contains("status")) status = message["status"].is_string()
                ? message["status"].get<std::string>() : message["status"].dump();
            for (const auto& field : metadata.value("headers", message.value("headers", nlohmann::json::array()))) {
                const auto name = lowercase(field.value("name", ""));
                const auto value = clipped(field.value("value", ""));
                if (name == ":method") method = value;
                if (name == ":path") target = value;
                if (name == ":status") status = value;
                if (name == ":authority" || name == "host") authority = value;
                if (name == "content-type") types.insert(value);
                if (name == "content-encoding") encodings.insert(value);
            }
            const auto encoding = metadata.value("content_encoding", "");
            if (!encoding.empty()) encodings.insert(clipped(encoding));
            const auto type = metadata.value("content_type", "");
            if (!type.empty() && type != "application/http-fields+json" && type != "application/octet-stream")
                types.insert(clipped(type));
            if ((!method.empty() || !status.empty()) && messages.size() < 64)
                messages.push_back({{"method", clipped(method)}, {"target", clipped(target)},
                    {"status", clipped(status)}, {"authority", clipped(authority)}});
        }
        method.clear(); target.clear(); status.clear(); authority.clear();
        if (!messages.empty()) {
            method = messages[0]["method"]; target = messages[0]["target"];
            status = messages[0]["status"]; authority = messages[0]["authority"];
        }
        const auto timestamp = sample.value("captured_at_ms", std::int64_t{0});
        const std::time_t seconds = timestamp / 1000;
        std::tm utc{};
        std::ostringstream date;
        if (gmtime_r(&seconds, &utc)) date << std::put_time(&utc, "%Y-%m-%d %H:%M:%S UTC");
        auto title = !method.empty() ? method + " " + target : !status.empty() ? "HTTP " + status : "Payload";
        if (messages.size() > 1) title += " (+" + std::to_string(messages.size() - 1) + " HTTP messages)";
        nlohmann::json result{{"id", id}, {"endpoint", clipped(sample.value("collection", nlohmann::json::object()).value("endpoint", ""))},
            {"captured_at_ms", timestamp}, {"captured_at", date.str()}, {"session_id", clipped(event.value("id", ""))},
            {"session", clipped(info.value("session", ""))}, {"side", info.value("side", "?")},
            {"bytes", content_size(info.value("content", nlohmann::json("")))}, {"decoded_bytes", decoded_bytes},
            {"title", clipped(title)}, {"authority", authority}, {"protocols", protocols}, {"operations", operations},
            {"content_types", types}, {"encodings", encodings}, {"stream_ids", streams}, {"http_messages", messages}};
        {
            std::scoped_lock lock(summary_mutex_);
            if (summaries_.size() >= 4096) summaries_.erase(summaries_.begin());
            summaries_.insert_or_assign(id, CachedSummary{modified, size, result});
        }
        return result;
    } catch (const std::exception& error) {
        return {{"id", id}, {"endpoint", id.substr(0, id.find('/'))}, {"title", "Unreadable sample"},
                {"error", error.what()}};
    }
}
nlohmann::json Collection::list(std::size_t offset, const std::string& query) const {
    if (query.size() > 800) throw std::runtime_error("Sample query is too long");
    std::vector<std::string> ids;
    if (std::filesystem::exists(root_)) {
        for (const auto& directory : std::filesystem::directory_iterator(root_)) {
            if (directory.is_symlink() || !directory.is_directory() ||
                !directory.path().filename().string().starts_with("endpoint-")) continue;
            for (const auto& file : std::filesystem::directory_iterator(directory)) {
                if (!file.is_symlink() && file.is_regular_file() && file.path().extension() == ".json")
                    ids.push_back(directory.path().filename().string() + "/" + file.path().filename().string());
            }
        }
    }
    std::sort(ids.begin(), ids.end(), [](const auto& a, const auto& b) {
        const auto af = a.substr(a.find('/') + 1), bf = b.substr(b.find('/') + 1);
        return af == bf ? a < b : af > bf;
    });
    const auto all = ids.size();
    if (!query.empty()) {
        std::istringstream words(lowercase(query));
        std::vector<std::string> terms;
        for (std::string term; words >> term;) terms.push_back(term);
        std::erase_if(ids, [&](const auto& id) {
            const auto text = lowercase(describe(id).dump());
            return std::any_of(terms.begin(), terms.end(), [&](const auto& term) { return text.find(term) == std::string::npos; });
        });
    }
    auto items = nlohmann::json::array();
    const auto end = offset >= ids.size() ? ids.size() : offset + std::min<std::size_t>(100, ids.size() - offset);
    for (auto i = offset; i < end; ++i) items.push_back(describe(ids[i]));
    return {{"items", items}, {"total", ids.size()}, {"all", all}, {"next", end < ids.size() ? nlohmann::json(end) : nlohmann::json(nullptr)}};
}
nlohmann::json Collection::read(const std::string& id) const {
    const auto slash = id.find('/');
    if (slash == std::string::npos || id.find('/', slash + 1) != std::string::npos ||
        !id.starts_with("endpoint-") || !id.ends_with(".json") ||
        id.find('\0') != std::string::npos)
        throw std::runtime_error("Invalid sample id");
    const int root = open(root_.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (root < 0) throw std::runtime_error("Collection directory unavailable");
    const int dir = openat(root, id.substr(0, slash).c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    close(root);
    if (dir < 0) throw std::runtime_error("Collection endpoint unavailable");
    const int fd = openat(dir, id.substr(slash + 1).c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    close(dir);
    if (fd < 0) throw std::runtime_error("Sample unavailable");
    struct stat stat{};
    if (fstat(fd, &stat) != 0 || !S_ISREG(stat.st_mode) || stat.st_size < 0 || stat.st_size > 64 * 1024 * 1024) {
        close(fd); throw std::runtime_error("Sample is not a regular file or exceeds 64 MiB");
    }
    std::string data(static_cast<std::size_t>(stat.st_size), '\0');
    std::size_t offset = 0;
    while (offset < data.size()) {
        const auto count = ::read(fd, data.data() + offset, data.size() - offset);
        if (count <= 0) { close(fd); throw std::runtime_error("Cannot read sample"); }
        offset += count;
    }
    close(fd);
    auto sample = nlohmann::json::parse(data);
    if (sample.value("format", "") != "spider-sample-v1") throw std::runtime_error("Unsupported sample format");
    return sample;
}
nlohmann::json Collection::save_flow(nlohmann::json snapshot) {
    const auto name = snapshot.value("name", "");
    if (name.empty() || name.size() > 800 || name.find('\0') != std::string::npos)
        throw std::runtime_error("Session name required (maximum 800 UTF-8 bytes)");
    if (!snapshot.contains("records") || !snapshot["records"].is_array() ||
        snapshot["records"].empty() || snapshot["records"].size() > 10000 ||
        !snapshot.contains("scope") || !snapshot["scope"].is_object())
        throw std::runtime_error("Session requires a scope and 1–10000 payload records");
    for (const auto& record : snapshot["records"]) {
        if (!record.is_object() || !record.contains("event") || !record["event"].is_object() ||
            !record["event"].value("details", nlohmann::json::object())
                .value("info", nlohmann::json::object()).contains("content"))
            throw std::runtime_error("Session record is missing payload content");
    }
    std::scoped_lock lock(mutex_);
    snapshot["format"] = "spider-flow-v1";
    snapshot["saved_at_ms"] = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto directory = root_ / "saved-sessions";
    if (std::filesystem::create_directories(root_))
        std::filesystem::permissions(root_, std::filesystem::perms::owner_all);
    if (std::filesystem::create_directory(directory))
        std::filesystem::permissions(directory, std::filesystem::perms::owner_all);
    std::string temporary = (directory / (std::to_string(snapshot["saved_at_ms"].get<std::int64_t>()) + "-XXXXXX")).string();
    int fd = mkstemp(temporary.data());
    if (fd < 0) throw std::runtime_error("Cannot create saved session");
    try {
        const auto id = std::filesystem::path(temporary).filename().string();
        snapshot["id"] = id;
        const auto summary = flow_summary(snapshot);
        const auto data = summary.dump() + "\n" + snapshot.dump();
        if (data.size() > 64 * 1024 * 1024 || bytes_ >= limit_ || data.size() > limit_ - bytes_)
            throw std::runtime_error("Saved session exceeds the 64 MiB or collection disk budget");
        std::size_t offset = 0;
        while (offset < data.size()) {
            const auto count = write(fd, data.data() + offset, data.size() - offset);
            if (count <= 0) throw std::runtime_error("Cannot write saved session");
            offset += count;
        }
        if (fsync(fd)) throw std::runtime_error("Cannot flush saved session");
        close(fd); fd = -1;
        std::filesystem::rename(temporary, temporary + ".flow");
        bytes_ += data.size();
        return summary;
    } catch (...) {
        if (fd >= 0) close(fd);
        unlink(temporary.c_str());
        throw;
    }
}
nlohmann::json Collection::list_flows(std::size_t offset) const {
    std::vector<std::string> ids;
    const auto directory = root_ / "saved-sessions";
    if (std::filesystem::exists(directory))
        for (const auto& file : std::filesystem::directory_iterator(directory))
            if (!file.is_symlink() && file.is_regular_file() && file.path().extension() == ".flow")
                ids.push_back(file.path().stem().string());
    std::sort(ids.rbegin(), ids.rend());
    auto items = nlohmann::json::array();
    const auto end = offset >= ids.size() ? ids.size() : offset + std::min<std::size_t>(100, ids.size() - offset);
    for (auto i = offset; i < end; ++i) {
        auto summary = flow_file(root_, ids[i], true);
        if (!summary.contains("bytes")) summary = flow_summary(read_flow(ids[i]));
        items.push_back(std::move(summary));
    }
    return {{"items", items}, {"total", ids.size()}, {"next", end < ids.size() ? nlohmann::json(end) : nlohmann::json(nullptr)}};
}
nlohmann::json Collection::read_flow(const std::string& id) const {
    auto result = flow_file(root_, id, false);
    if (result.value("format", "") != "spider-flow-v1") throw std::runtime_error("Unsupported saved session format");
    return result;
}
}
