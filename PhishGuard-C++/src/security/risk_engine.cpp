// =============================================================================
// FILE: src/security/risk_engine.cpp
// WHAT   Implementation of the scoring policy and the user-facing recommendation texts.
// HOW    Sorting by weight BEFORE capping means the strongest keywords survive the cap. The CRITICAL
//        recommendation is deliberately blunt capital-letter advice; LOW still says "stay careful"
//        because the tool must never promise that something is safe.
// =============================================================================

#include "phishguard/security/risk_engine.hpp"

#include <algorithm>

#include "phishguard/algorithms/sorting.hpp"
#include "phishguard/ds/custom_set.hpp"

namespace phishguard {

AnalysisResult RiskEngine::evaluate(std::vector<Indicator> raw) const {
    CustomSet<std::string> seen;
    std::vector<Indicator> unique;
    for (auto& ind : raw)
        if (seen.insert(ind.id)) unique.push_back(std::move(ind));

    mergeSort(unique, [](const Indicator& a, const Indicator& b) { return a.weight > b.weight; });  // stable

    AnalysisResult result;
    int keywordBudget = config_.value("cap.keyword");
    int total = 0;
    for (auto& ind : unique) {
        if (ind.category == IndicatorCategory::Keyword) {
            if (keywordBudget <= 0) continue;
            if (ind.weight > keywordBudget) ind.weight = keywordBudget;
            keywordBudget -= ind.weight;
        }
        if (ind.weight <= 0) continue;
        total += ind.weight;
        result.indicators.push_back(ind);
    }
    result.score = std::min(100, total);
    result.level = config_.levelFor(result.score);
    result.recommendation = recommendationFor(result.level);
    return result;
}

std::string RiskEngine::recommendationFor(RiskLevel level) {
    switch (level) {
        case RiskLevel::Low:
            return "Probably safe based on the checks we ran, but stay careful. If you did not expect this, "
                   "confirm it through an official website or app.";
        case RiskLevel::Medium:
            return "Some suspicious signs were found. Do not enter passwords or payment details until you have "
                   "checked through the official website or app.";
        case RiskLevel::High:
            return "Several suspicious signs were found. Do not click the link or share personal information. "
                   "Contact the company using the phone number on its official website.";
        case RiskLevel::Critical:
            return "DO NOT ENTER YOUR PASSWORD.\nDO NOT PROVIDE OTP OR PAYMENT INFORMATION.\n"
                   "VERIFY THE SENDER THROUGH AN OFFICIAL SOURCE.";
    }
    return "";
}

}  // namespace phishguard
