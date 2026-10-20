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
nlohmann::json Collection::list(std::size_t offset) const {
    std::vector<std::string> ids;
    if (std::filesystem::exists(root_)) {
        for (const auto& directory : std::filesystem::directory_iterator(root_)) {
            if (directory.is_symlink() || !directory.is_directory()) continue;
            for (const auto& file : std::filesystem::directory_iterator(directory)) {
                if (!file.is_symlink() && file.is_regular_file() && file.path().extension() == ".json")
                    ids.push_back(directory.path().filename().string() + "/" + file.path().filename().string());
            }
        }
    }
    std::sort(ids.begin(), ids.end());
    auto items = nlohmann::json::array();
    const auto end = offset >= ids.size() ? ids.size() : offset + std::min<std::size_t>(100, ids.size() - offset);
    for (auto i = offset; i < end; ++i) items.push_back({{"id", ids[i]}, {"endpoint", ids[i].substr(0, ids[i].find('/'))}});
    return {{"items", items}, {"total", ids.size()}, {"next", end < ids.size() ? nlohmann::json(end) : nlohmann::json(nullptr)}};
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
}
