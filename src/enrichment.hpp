#pragma once

#include "binary_envelope.hpp"
#include "content_decoding_enrichment.hpp"
#include "http2_enrichment.hpp"

#include <atomic>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace spider {

class EnrichmentEngine {
public:
    [[nodiscard]] std::vector<SxbnEnvelope> process(const nlohmann::json& event,
                                                    std::string_view payload);
    void observe(const nlohmann::json& event);
    [[nodiscard]] nlohmann::json diagnostics() const;
    // Isolated replay: no live decoder, decisions, scripts or collection writes.
    [[nodiscard]] static std::string replay(const std::vector<SxbnEnvelope>& records);

private:
    mutable std::atomic_uint64_t content_seen_{};
    mutable std::atomic_uint64_t selected_{};
    mutable std::atomic_uint64_t outputs_{};
    mutable std::atomic_uint64_t http1_heads_{};
    Http2Enrichment http2_;
    ContentDecodingEnrichment content_decoding_;
};

} // namespace spider
