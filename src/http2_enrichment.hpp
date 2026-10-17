#pragma once

#include "binary_envelope.hpp"

#include <memory>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace spider {

class Http2Enrichment {
public:
    Http2Enrichment();
    ~Http2Enrichment();

    Http2Enrichment(const Http2Enrichment&) = delete;
    Http2Enrichment& operator=(const Http2Enrichment&) = delete;

    [[nodiscard]] std::vector<SxbnEnvelope> process(const nlohmann::json& event,
                                                    std::string_view payload,
                                                    bool selected);
    void forget(const nlohmann::json& event);
    [[nodiscard]] nlohmann::json diagnostics() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace spider
