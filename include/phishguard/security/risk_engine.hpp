// =============================================================================
// FILE: include/phishguard/security/risk_engine.hpp
// WHAT   Turns a pile of Indicators into the final Risk Score, level and recommendation.
// HOW    1. De-duplicate by indicator id with a hash set (each reason counts once).
//        2. Sort strongest first (stable merge sort).
//        3. Apply the keyword CAP (default 25 points) so a message stuffed with scam words cannot
//           reach 100 on its own.
//        4. Add the weights, clamp to 100, map to a level with the configurable thresholds.
// WHY    Keeping scoring separate from detection means you can change the policy (caps, weights,
//        levels) without touching any analyzer, and every point is still traceable to a reason.
// =============================================================================
#pragma once
#include <string>
#include <vector>

#include "phishguard/common/types.hpp"
#include "phishguard/security/risk_config.hpp"

namespace phishguard {

// Turns raw indicators into a Risk Score:
//  1. de-duplicate by indicator id (each reason counts once)
//  2. sort strongest first, then apply the keyword cap so keyword stuffing cannot reach 100
//  3. sum weights, clamp to 100, map to a level with the configurable thresholds
// The score is a heuristic, NOT a probability.
class RiskEngine {
public:
    explicit RiskEngine(const RiskConfig& config) : config_(config) {}
    AnalysisResult evaluate(std::vector<Indicator> indicators) const;
    static std::string recommendationFor(RiskLevel level);

private:
    const RiskConfig& config_;
};

}  // namespace phishguard
