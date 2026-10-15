// =============================================================================
// FILE: include/phishguard/analyzers/url_analyzer.hpp
// WHAT   Full analysis of ONE link: parse it, run the domain analyzer, then check the rest of the
//        URL (unusual scheme, '@' trick, very long URL, %xx encoding, redirect-like parameters,
//        suspicious keywords in the host/path/query).
// WHY    Splits responsibility: DomainAnalyzer = "who is the site", UrlAnalyzer = "how is the
//        link written". Returns a UrlAnalysis (parsed parts + indicators + impersonation match).
// =============================================================================
#pragma once
#include <optional>
#include <string>
#include <vector>

#include "phishguard/analyzers/domain_analyzer.hpp"
#include "phishguard/analyzers/url_parser.hpp"
#include "phishguard/common/types.hpp"
#include "phishguard/security/detection_data.hpp"

namespace phishguard {

struct UrlAnalysis {
    ParsedUrl parsed;
    std::vector<Indicator> indicators;
    std::optional<ImpersonationMatch> impersonation;
};

class UrlAnalyzer {
public:
    explicit UrlAnalyzer(const DetectionData& data) : data_(data), parser_(&data.publicSuffixes), domain_(data) {}
    UrlAnalysis analyze(const std::string& rawUrl) const;

private:
    const DetectionData& data_;
    UrlParser parser_;
    DomainAnalyzer domain_;
};

}  // namespace phishguard
