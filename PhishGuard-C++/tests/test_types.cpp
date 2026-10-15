// =============================================================================
// FILE: tests/test_types.cpp
// WHAT   Tests for types.hpp: level names and neutral defaults of an empty result.
// =============================================================================

#include <string>

#include "phishguard/common/types.hpp"
#include "test_harness.hpp"

using namespace phishguard;

TEST(risk_level_names) {
    CHECK_EQ(std::string(toString(RiskLevel::Low)), std::string("LOW"));
    CHECK_EQ(std::string(toString(RiskLevel::Medium)), std::string("MEDIUM"));
    CHECK_EQ(std::string(toString(RiskLevel::High)), std::string("HIGH"));
    CHECK_EQ(std::string(toString(RiskLevel::Critical)), std::string("CRITICAL"));
}

TEST(analysis_result_defaults_are_neutral) {
    AnalysisResult r;
    CHECK_EQ(r.score, 0);
    CHECK(r.level == RiskLevel::Low);
    CHECK(r.indicators.empty());
}
