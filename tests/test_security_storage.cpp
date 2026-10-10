// =============================================================================
// FILE: tests/test_security_storage.cpp
// WHAT   Tests for the threat database, trusted domains, privacy redaction (secrets never stored),
//        history (sort/filter/remove/statistics/file round-trip with damaged lines) and the graph
//        builder (two scans linked through a shared website).
// =============================================================================

#include <cstdio>
#include <fstream>
#include <string>

#include "phishguard/common/text_utils.hpp"
#include "phishguard/security/graph_builder.hpp"
#include "phishguard/security/scan_service.hpp"
#include "phishguard/security/threat_database.hpp"
#include "phishguard/security/trusted_domains.hpp"
#include "phishguard/storage/history_manager.hpp"
#include "test_harness.hpp"
#include "test_support.hpp"

using namespace phishguard;

TEST(threat_db_crud_and_categories) {
    ThreatDatabase db;
    CHECK(db.add({"Bad-One.test", "credential", RiskLevel::High, "sample"}));
    CHECK(!db.add({"bad-one.test", "credential", RiskLevel::Critical, "dup"}));  // case-insensitive key, replaced
    CHECK_EQ(db.size(), 1u);
    CHECK(db.add({"prize.test", "prize_scam", RiskLevel::Medium, "sample"}));
    CHECK(db.find("BAD-ONE.test") != nullptr);
    CHECK(db.findForHost("login.prize.test") != nullptr);
    CHECK(db.findForHost("other.test") == nullptr);
    CHECK(db.update("prize.test", {"ignored", "delivery_scam", RiskLevel::High, "changed"}));
    CHECK_EQ(db.find("prize.test")->category, std::string("delivery_scam"));
    CHECK(!db.update("nothere.test", {"x", "y", RiskLevel::Low, ""}));
    CHECK_EQ(db.byCategory("delivery_scam").size(), 1u);
    CHECK_EQ(db.all()[0].domain, std::string("bad-one.test"));  // Critical first
    CHECK(db.remove("bad-one.test"));
    CHECK(!db.remove("bad-one.test"));
    CHECK_THROWS(db.add({"", "x", RiskLevel::Low, ""}));
}

TEST(threat_db_file_round_trip) {
    ThreatDatabase db;
    db.add({"a.test", "credential", RiskLevel::High, "n1"});
    db.add({"b.test", "prize_scam", RiskLevel::Low, "n2"});
    const std::string path = "tmp_threats.txt";
    db.saveToFile(path);
    const auto loaded = ThreatDatabase::loadFromFile(path);
    std::remove(path.c_str());
    CHECK_EQ(loaded.size(), 2u);
    CHECK(loaded.find("b.test")->risk == RiskLevel::Low);
    CHECK_THROWS(ThreatDatabase::loadFromFile("missing_file.txt"));
}

TEST(trusted_store_matches_subdomains_not_lookalikes) {
    TrustedDomainStore t;
    t.add({"paypal.com", "paypal", "payments"});
    CHECK(t.isTrustedHost("paypal.com"));
    CHECK(t.isTrustedHost("www.paypal.com"));
    CHECK(!t.isTrustedHost("paypal.com.evil.test"));
    CHECK(!t.isTrustedHost("notpaypal.com"));
    CHECK(t.remove("paypal.com"));
    CHECK(!t.isTrustedHost("paypal.com"));
}

TEST(redaction_hides_secrets) {
    CHECK_EQ(text::redactSensitive("my password is hunter2 ok"), std::string("my password is [hidden] ok"));
    CHECK_EQ(text::redactSensitive("pin:4821"), std::string("pin:[hidden]"));
    CHECK_EQ(text::redactSensitive("your OTP is 482913 thanks"), std::string("your OTP is [hidden] thanks"));
    CHECK_EQ(text::redactSensitive("call 03001234567 now"), std::string("call [digits] now"));
    CHECK(text::redactSensitive("share your otp and pin").find("[hidden]") == std::string::npos);  // no secret value present
    CHECK_EQ(text::redactUrl("https://user:pw@a.test/p?token=abc#x"), std::string("https://[hidden]@a.test/p?[query hidden]"));
}

TEST(history_add_sort_filter_remove_stats) {
    ScanService s(testData());
    HistoryManager h;
    const int a = h.add(s.scanUrl("https://www.google.com"));
    const int b = h.add(s.scanUrl("https://paypa1.com/signin"));
    const int c = h.add(s.scanMessage("Your OTP is 123456. Pay the fee now http://bank-verify-now.test"));
    CHECK_EQ(h.size(), 3u);
    CHECK_EQ(h.sorted(SortKey::Newest)[0].id, c);
    CHECK_EQ(h.sorted(SortKey::Oldest)[0].id, a);
    CHECK_EQ(h.sorted(SortKey::ScoreHigh)[0].id, c);
    CHECK_EQ(h.sorted(SortKey::ScoreLow)[0].id, a);
    CHECK_EQ(h.filter(RiskLevel::High, std::nullopt, "").size(), 2u);
    CHECK_EQ(h.filter(std::nullopt, InputType::Url, "").size(), 2u);
    CHECK_EQ(h.filter(std::nullopt, std::nullopt, "paypa1").size(), 1u);
    CHECK_EQ(h.topRisk(2)[0].id, c);
    CHECK_EQ(h.topRisk(100).size(), 3u);
    CHECK(h.find(c)->input.find("123456") == std::string::npos);  // OTP never stored
    const auto st = h.stats();
    CHECK_EQ(st.total, 3u);
    CHECK(st.averageScore > 0);
    CHECK(!st.topIndicators.empty());
    CHECK(h.remove(b));
    CHECK(!h.remove(b));
    CHECK_EQ(h.size(), 2u);
}

TEST(history_file_round_trip_and_bad_lines) {
    ScanService s(testData());
    HistoryManager h;
    h.add(s.scanUrl("https://paypa1.com/signin?session=SECRET"));
    h.add(s.scanMessage("hello there"));
    const std::string path = "tmp_history.txt";
    h.save(path);
    {
        std::ofstream f(path, std::ios::app);
        f << "garbage line\n1|x\n";
    }
    const auto loaded = HistoryManager::load(path);
    std::remove(path.c_str());
    CHECK_EQ(loaded.size(), 2u);
    CHECK(loaded.records()[0].input.find("SECRET") == std::string::npos);
    CHECK_EQ(HistoryManager::load("does_not_exist.txt").size(), 0u);
    HistoryManager next = HistoryManager::load("does_not_exist.txt");
    CHECK_EQ(next.add(s.scanMessage("hi")), 1);
}

TEST(graph_builder_links_scans_through_shared_domains) {
    ScanService s(testData());
    Graph g;
    const auto r1 = s.scanMessage("Verify now http://bank-verify-now.test/a");
    const auto r2 = s.scanMessage("Another one http://bank-verify-now.test/b");
    addScanToGraph(g, 1, r1);
    addScanToGraph(g, 2, r2);
    const int d = g.indexOf("bank-verify-now.test");
    CHECK(d >= 0);
    CHECK(g.node(d).type == NodeType::SuspiciousDomain);
    bool reachesScan2 = false;
    for (const auto& v : g.bfs(g.indexOf("Scan #1"))) reachesScan2 = reachesScan2 || g.node(v.node).label == "Scan #2";
    CHECK(reachesScan2);  // scan 1 and scan 2 are connected via the shared website
    const auto lookalike = s.scanUrl("https://paypa1.com");
    addScanToGraph(g, 3, lookalike);
    CHECK(g.indexOf("paypal.com") >= 0);
    CHECK(g.node(g.indexOf("paypal.com")).type == NodeType::TrustedDomain);
}

TEST(config_data_file_loads_and_matches_spec) {
    const auto& c = testData().config;
    CHECK_EQ(c.weight("weight.known_threat"), 50);
    CHECK_EQ(c.weight("weight.lookalike"), 30);
    CHECK_EQ(c.weight("weight.ip_host"), 20);
    CHECK(testData().keywords.contains("password"));
    CHECK(testData().trusted.size() >= 5);
    CHECK(testData().threats.size() >= 4);
}
