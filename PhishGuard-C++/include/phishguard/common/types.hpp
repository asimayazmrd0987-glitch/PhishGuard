// =============================================================================
// FILE: include/phishguard/common/types.hpp
// WHAT   The shared "vocabulary" of the whole project: the small data types every other
//        module passes around (RiskLevel, InputType, Indicator, AnalysisResult ...).
// HOW    These are plain structs/enums with no logic. An analyzer produces a list of
//        `Indicator`s (a reason + points); the risk engine adds them up into an
//        `AnalysisResult` (score, level, reasons, recommendation, findings).
// WHY    Keeping the types in one tiny header means modules depend on a common
//        language instead of on each other. It also enforces the key design rule:
//        EVERY point of the score must come from an Indicator that has a plain-language
//        description, so the result is always explainable.
// NOTE   `score` is a heuristic Risk Score, NOT a probability of being malicious.
// READ   Start here: every other file uses these types.
// =============================================================================
#pragma once
#include <optional>
#include <string>
#include <vector>

namespace phishguard {

enum class RiskLevel { Low, Medium, High, Critical };
const char* toString(RiskLevel level);
bool parseRiskLevel(const std::string& s, RiskLevel& out);  // case-insensitive

enum class InputType { Url, Message, Email };
const char* toString(InputType type);
bool parseInputType(const std::string& s, InputType& out);

enum class IndicatorCategory { Threat, Domain, Url, Keyword, Message, Similarity };

// One reason that adds to the risk score. Every point of the score is traceable
// to an Indicator: this is what makes the result explainable.
struct Indicator {
    std::string id;           // stable key, e.g. "lookalike_domain" (used for de-duplication)
    std::string description;  // beginner-friendly explanation
    int weight = 0;           // points contributed
    IndicatorCategory category = IndicatorCategory::Url;
    std::string detail;       // optional machine detail (keyword, domain...)
};

struct ImpersonationMatch {
    std::string inputPart;      // the part of the input that looks suspicious
    std::string trustedDomain;  // the trusted domain it resembles
    int distance = 0;           // Levenshtein distance
    double similarity = 0.0;    // 0..1
    bool usedLookalikeChars = false;  // e.g. 0 for o, 1 for l
    bool embedded = false;      // trusted name hidden inside a different address
};

struct ScanFindings {
    std::vector<std::string> urls;     // urls[i] pairs with domains[i] ("" if unparseable)
    std::vector<std::string> domains;
    std::vector<std::string> ips;
    std::vector<std::string> keywords;
    std::vector<std::string> threatDomains;
    std::optional<ImpersonationMatch> impersonation;
};

struct AnalysisResult {
    InputType type = InputType::Url;
    std::string input;
    int score = 0;  // 0..100, heuristic Risk Score (NOT a probability)
    RiskLevel level = RiskLevel::Low;
    std::vector<Indicator> indicators;
    std::string recommendation;
    ScanFindings findings;
};

}  // namespace phishguard
