// =============================================================================
// FILE: src/common/types.cpp
// WHAT   Converts the enums in types.hpp to and from text ("HIGH" <-> RiskLevel::High).
// HOW    A switch per enum for printing; a case-insensitive comparison for parsing.
// WHY    The data files and the history file store levels as words, so we need a safe,
//        forgiving parser (returns false instead of crashing on unknown words).
// =============================================================================

#include "phishguard/common/types.hpp"

#include "phishguard/common/text_utils.hpp"

namespace phishguard {

const char* toString(RiskLevel level) {
    switch (level) {
        case RiskLevel::Low:      return "LOW";
        case RiskLevel::Medium:   return "MEDIUM";
        case RiskLevel::High:     return "HIGH";
        case RiskLevel::Critical: return "CRITICAL";
    }
    return "UNKNOWN";
}

bool parseRiskLevel(const std::string& s, RiskLevel& out) {
    const std::string t = text::toLower(text::trim(s));
    if (t == "low") out = RiskLevel::Low;
    else if (t == "medium") out = RiskLevel::Medium;
    else if (t == "high") out = RiskLevel::High;
    else if (t == "critical") out = RiskLevel::Critical;
    else return false;
    return true;
}

const char* toString(InputType type) {
    switch (type) {
        case InputType::Url:     return "URL";
        case InputType::Message: return "MESSAGE";
        case InputType::Email:   return "EMAIL";
    }
    return "UNKNOWN";
}

bool parseInputType(const std::string& s, InputType& out) {
    const std::string t = text::toLower(text::trim(s));
    if (t == "url") out = InputType::Url;
    else if (t == "message") out = InputType::Message;
    else if (t == "email") out = InputType::Email;
    else return false;
    return true;
}

}  // namespace phishguard
