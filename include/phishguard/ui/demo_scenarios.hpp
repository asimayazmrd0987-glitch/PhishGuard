// =============================================================================
// FILE: include/phishguard/ui/demo_scenarios.hpp
// WHAT   The 14 demonstration scenarios: input, expected level RANGE, which algorithms are involved
//        and a note. Used by the demo screen (`phishguard --demo`) and by an automated test.
// WHY    Expected ranges were written BEFORE the results were looked at, so the demos are an honest
//        check and not a table of whatever the program happened to print.
// =============================================================================
#pragma once
#include <string>
#include <vector>

#include "phishguard/common/types.hpp"

namespace phishguard {

struct DemoScenario {
    std::string title;
    InputType type;
    std::string input;       // synthetic / documentation-range data only
    RiskLevel minLevel;      // expected range (heuristic, documented in the report)
    RiskLevel maxLevel;
    std::string algorithms;  // DSA involved
    std::string note;
};

const std::vector<DemoScenario>& demoScenarios();

}  // namespace phishguard
