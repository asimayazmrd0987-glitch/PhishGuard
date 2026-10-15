// =============================================================================
// FILE: tests/test_integration.cpp
// WHAT   End-to-end tests: all 14 demo scenarios land in their expected level ranges, and scripted
//        menu sessions work (including bad menu choices and end-of-input).
// =============================================================================

#include <sstream>
#include <string>

#include "phishguard/security/scan_service.hpp"
#include "phishguard/ui/demo_scenarios.hpp"
#include "phishguard/ui/interface.hpp"
#include "test_harness.hpp"
#include "test_support.hpp"

using namespace phishguard;

TEST(all_demo_scenarios_land_in_expected_levels) {
    ScanService s(testData());
    CHECK(demoScenarios().size() >= 10);
    for (const auto& d : demoScenarios()) {
        const auto r = d.type == InputType::Url ? s.scanUrl(d.input) : s.scanMessage(d.input, d.type);
        const int lv = static_cast<int>(r.level);
        if (lv < static_cast<int>(d.minLevel) || lv > static_cast<int>(d.maxLevel))
            std::cerr << "    scenario '" << d.title << "' scored " << r.score << " (" << toString(r.level) << ")\n";
        CHECK(lv >= static_cast<int>(d.minLevel));
        CHECK(lv <= static_cast<int>(d.maxLevel));
    }
}

TEST(ui_scripted_session_scans_and_exits) {
    DetectionData data = DetectionData::loadFromDirectory(PG_DATA_DIR);
    std::istringstream in("1\nhttps://paypa1.com/signin\n2\nUrgent! Verify your account at http://bank-verify-now.test\n7\n4\n1\n0\n99\n8\n");
    std::ostringstream out;
    Interface ui(data, in, out, "tmp_ui_history.txt");
    CHECK_EQ(ui.run(), 0);
    const std::string o = out.str();
    CHECK(o.find("POSSIBLE DOMAIN IMPERSONATION") != std::string::npos);
    CHECK(o.find("paypal.com") != std::string::npos);
    CHECK(o.find("Risk Score") != std::string::npos);
    CHECK(o.find("CRITICAL") != std::string::npos);
    CHECK(o.find("Total scans: 2") != std::string::npos);
    CHECK(o.find("Please type a number") != std::string::npos);
    CHECK(o.find("not a guarantee") != std::string::npos);  // honesty disclaimer
    CHECK(o.find("definitely safe") == std::string::npos);
    std::remove("tmp_ui_history.txt");
}

TEST(ui_survives_end_of_input_and_bad_input) {
    DetectionData data = DetectionData::loadFromDirectory(PG_DATA_DIR);
    std::istringstream in("abc\n2\n\n");  // invalid option, empty message, then EOF
    std::ostringstream out;
    Interface ui(data, in, out, "tmp_ui_history2.txt");
    CHECK_EQ(ui.run(), 0);
    CHECK(out.str().find("Nothing was entered") != std::string::npos);
    std::remove("tmp_ui_history2.txt");
}
