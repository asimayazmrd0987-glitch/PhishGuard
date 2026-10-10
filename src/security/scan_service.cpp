// =============================================================================
// FILE: src/security/scan_service.cpp
// WHAT   Wires analyzers and the risk engine together and collects "findings" (links, websites,
//        IP addresses, keywords, known-threat domains, best look-alike match) for the graph and UI.
// HOW    finish() moves the analyzer's raw indicators through the risk engine, then derives the
//        keyword and threat-domain lists from the FINAL indicators (so capped/removed keywords are
//        not reported as findings).
// =============================================================================

#include "phishguard/security/scan_service.hpp"

namespace phishguard {

void ScanService::collectFindings(const UrlAnalysis& ua, AnalysisResult& r) const {
    r.findings.urls.push_back(ua.parsed.original);
    r.findings.domains.push_back(ua.parsed.valid ? ua.parsed.host : "");
    if (ua.parsed.valid && ua.parsed.hostIsIp) r.findings.ips.push_back(ua.parsed.host);
    if (ua.impersonation &&
        (!r.findings.impersonation || ua.impersonation->distance < r.findings.impersonation->distance))
        r.findings.impersonation = ua.impersonation;
}

void ScanService::finish(AnalysisResult& r) const {
    std::vector<Indicator> raw = std::move(r.indicators);
    AnalysisResult scored = engine_.evaluate(std::move(raw));
    r.score = scored.score;
    r.level = scored.level;
    r.indicators = std::move(scored.indicators);
    r.recommendation = std::move(scored.recommendation);
    for (const auto& ind : r.indicators) {
        if (ind.category == IndicatorCategory::Keyword) r.findings.keywords.push_back(ind.detail);
        if (ind.id == "known_threat") r.findings.threatDomains.push_back(ind.detail);
    }
}

AnalysisResult ScanService::scanUrl(const std::string& url) const {
    AnalysisResult r;
    r.type = InputType::Url;
    r.input = url;
    UrlAnalysis ua = urls_.analyze(url);
    collectFindings(ua, r);
    r.indicators = std::move(ua.indicators);
    finish(r);
    return r;
}

AnalysisResult ScanService::scanMessage(const std::string& text, InputType type) const {
    AnalysisResult r;
    r.type = type;
    r.input = text;
    MessageAnalysis ma = messages_.analyze(text);
    for (const auto& ua : ma.urls) collectFindings(ua, r);
    r.indicators = std::move(ma.indicators);
    finish(r);
    return r;
}

}  // namespace phishguard
