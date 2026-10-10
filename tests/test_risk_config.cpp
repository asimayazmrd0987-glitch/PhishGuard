// =============================================================================
// FILE: tests/test_risk_config.cpp
// WHAT   Tests for RiskConfig: default weights equal the specification, unknown keys throw, level
//        thresholds at every boundary (20/21, 40/41, 70/71), clamping, file overrides, bad files.
// =============================================================================

#include <cstdio>
#include <fstream>
#include <string>

#include "phishguard/security/risk_config.hpp"
#include "test_harness.hpp"

using namespace phishguard;

TEST(config_default_weights_match_spec) {
    RiskConfig c;
    CHECK_EQ(c.weight("weight.known_threat"), 50);
    CHECK_EQ(c.weight("weight.lookalike"), 30);
    CHECK_EQ(c.weight("weight.ip_host"), 20);
}

TEST(config_unknown_key_throws) {
    RiskConfig c;
    CHECK_THROWS(c.weight("weight.does_not_exist"));
}

TEST(level_thresholds_at_boundaries) {
    RiskConfig c;
    CHECK(c.levelFor(0) == RiskLevel::Low);
    CHECK(c.levelFor(20) == RiskLevel::Low);
    CHECK(c.levelFor(21) == RiskLevel::Medium);
    CHECK(c.levelFor(40) == RiskLevel::Medium);
    CHECK(c.levelFor(41) == RiskLevel::High);
    CHECK(c.levelFor(70) == RiskLevel::High);
    CHECK(c.levelFor(71) == RiskLevel::Critical);
    CHECK(c.levelFor(100) == RiskLevel::Critical);
}

TEST(level_clamps_out_of_range_scores) {
    RiskConfig c;
    CHECK(c.levelFor(-50) == RiskLevel::Low);
    CHECK(c.levelFor(9999) == RiskLevel::Critical);
}

TEST(config_file_overrides_defaults) {
    const std::string path = "tmp_cfg_ok.txt";
    {
        std::ofstream f(path);
        f << "# comment\n\nweight.lookalike = 35\nthreshold.low_max=10\n";
    }
    RiskConfig c = RiskConfig::loadFromFile(path);
    std::remove(path.c_str());
    CHECK_EQ(c.weight("weight.lookalike"), 35);
    CHECK_EQ(c.weight("weight.ip_host"), 20);  // untouched default
    CHECK(c.levelFor(15) == RiskLevel::Medium);  // new threshold applied
}

TEST(config_file_errors_are_reported) {
    CHECK_THROWS(RiskConfig::loadFromFile("no_such_file.txt"));

    const std::string path = "tmp_cfg_bad.txt";
    {
        std::ofstream f(path);
        f << "weight.lookalike=abc\n";
    }
    CHECK_THROWS(RiskConfig::loadFromFile(path));
    std::remove(path.c_str());
}
