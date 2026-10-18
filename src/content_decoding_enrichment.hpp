#pragma once

#include "binary_envelope.hpp"

#include <memory>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace spider {

class ContentDecodingEnrichment {
public:
    ContentDecodingEnrichment();
    ~ContentDecodingEnrichment();

    ContentDecodingEnrichment(const ContentDecodingEnrichment&) = delete;
    ContentDecodingEnrichment& operator=(const ContentDecodingEnrichment&) = delete;

    [[nodiscard]] std::vector<SxbnEnvelope> process(const nlohmann::json& event,
                                                    std::string_view payload,
                                                    bool selected);
    void observe_http2_headers(const nlohmann::json& event,
                               const std::vector<SxbnEnvelope>& enrichments);
    void forget(const nlohmann::json& event);
    [[nodiscard]] nlohmann::json diagnostics() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace spider
