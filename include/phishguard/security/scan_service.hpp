// =============================================================================
// FILE: include/phishguard/security/scan_service.hpp
// WHAT   The single front door of the engine (a "facade"): give it a URL or a message, get back a
//        complete AnalysisResult.
// HOW    scanUrl()  : UrlAnalyzer -> findings -> RiskEngine.
//        scanMessage(): MessageAnalyzer (which also analyzes every link inside) -> RiskEngine.
//        Invalid text (empty, too long, control characters) throws std::invalid_argument; a
//        malformed URL is NOT an error: it becomes a "malformed link" indicator.
// WHY    The UI, the batch tool, the demos and the tests all call this one class, so the rules
//        cannot drift apart. A future web or mobile front end only needs to call these two methods.
// =============================================================================
#pragma once
#include <string>

#include "phishguard/analyzers/message_analyzer.hpp"
#include "phishguard/analyzers/url_analyzer.hpp"
#include "phishguard/common/types.hpp"
#include "phishguard/security/detection_data.hpp"
#include "phishguard/security/risk_engine.hpp"

namespace phishguard {

// Facade: input -> analyzers -> risk engine -> AnalysisResult.
class ScanService {
public:
    explicit ScanService(const DetectionData& data) : data_(data), urls_(data), messages_(data), engine_(data.config) {}

    AnalysisResult scanUrl(const std::string& url) const;
    // Throws std::invalid_argument for empty / oversized / unreadable input.
    AnalysisResult scanMessage(const std::string& text, InputType type = InputType::Message) const;

private:
    void collectFindings(const UrlAnalysis& ua, AnalysisResult& r) const;
    void finish(AnalysisResult& r) const;

    const DetectionData& data_;
    UrlAnalyzer urls_;
    MessageAnalyzer messages_;
    RiskEngine engine_;
};

}  // namespace phishguard
