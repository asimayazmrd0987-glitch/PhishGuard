// =============================================================================
// FILE: tests/test_analyzers.cpp
// WHAT   Tests for the URL parser and the URL/message analyzers: valid, malformed, IP, long, many
//        subdomains, odd endings, '@' trick, shorteners, punycode, redirects, look-alikes, hidden
//        brand names, trusted sites staying LOW, every scam type, keyword cap, de-duplication and
//        input validation.
// =============================================================================

#include <string>

#include "phishguard/analyzers/url_parser.hpp"
#include "phishguard/security/scan_service.hpp"
#include "test_harness.hpp"
#include "test_support.hpp"

using namespace phishguard;

namespace {
bool hasIndicator(const AnalysisResult& r, const std::string& id) {
    for (const auto& i : r.indicators)
        if (i.id == id) return true;
    return false;
}
int levelInt(const AnalysisResult& r) { return static_cast<int>(r.level); }
}  // namespace

TEST(parser_splits_a_full_url) {
    UrlParser p(&testData().publicSuffixes);
    const auto u = p.parse("HTTPS://user:pw@Login.Example.co.uk:8443/a/b?x=1&y=2#frag");
    CHECK(u.valid);
    CHECK_EQ(u.scheme, std::string("https"));
    CHECK_EQ(u.userinfo, std::string("user:pw"));
    CHECK_EQ(u.host, std::string("login.example.co.uk"));
    CHECK_EQ(u.port, 8443);
    CHECK_EQ(u.path, std::string("/a/b"));
    CHECK_EQ(u.query, std::string("x=1&y=2"));
    CHECK_EQ(u.fragment, std::string("frag"));
    CHECK_EQ(u.registeredDomain, std::string("example.co.uk"));
    CHECK_EQ(u.subdomainCount, 1);
    CHECK_EQ(u.tld, std::string("uk"));
}

TEST(parser_handles_missing_scheme_ip_and_malformed) {
    UrlParser p(&testData().publicSuffixes);
    const auto noScheme = p.parse("example.com/path");
    CHECK(noScheme.valid && !noScheme.hadScheme);
    const auto ip = p.parse("http://203.0.113.9/x");
    CHECK(ip.valid && ip.hostIsIp);
    CHECK(!p.parse("http://999.1.1.1/").valid);
    CHECK(!p.parse("").valid);
    CHECK(!p.parse("http://exa mple.com").valid);
    CHECK(!p.parse("http://bad..com").valid);
    CHECK(!p.parse("http://example.com:99999").valid);
    CHECK(!p.parse("http://-bad.com").valid);
    CHECK(!p.parse(std::string(3000, 'a')).valid);
    CHECK(p.parse("http://[::1]:80/").hostIsIp);
}

TEST(extract_urls_from_text) {
    const auto urls = UrlParser::extractUrls("Visit https://a.test/x, or www.b.test. Also paypa1-login.xyz/verify! Mail me@x.com e.g. Hi.There", testData().knownTlds);
    CHECK_EQ(urls.size(), 3u);
    CHECK_EQ(urls[0], std::string("https://a.test/x"));
    CHECK_EQ(urls[1], std::string("www.b.test"));
    CHECK_EQ(urls[2], std::string("paypa1-login.xyz/verify"));
}

TEST(url_safe_looking_trusted_site_is_low) {
    ScanService s(testData());
    const auto r = s.scanUrl("https://accounts.google.com/login");  // "login" must NOT count on a trusted domain
    CHECK_EQ(r.score, 0);
    CHECK(r.level == RiskLevel::Low);
}

TEST(url_lookalike_domain_is_detected) {
    ScanService s(testData());
    const auto r = s.scanUrl("https://paypa1.com/");
    CHECK(hasIndicator(r, "lookalike_domain"));
    CHECK(r.findings.impersonation.has_value());
    CHECK_EQ(r.findings.impersonation->trustedDomain, std::string("paypal.com"));
    CHECK_EQ(r.findings.impersonation->distance, 1);
    CHECK(r.score >= 30);
    CHECK(hasIndicator(s.scanUrl("https://g00gle.com/"), "lookalike_domain"));
    CHECK(hasIndicator(s.scanUrl("https://secure-paypa1-login.example.xyz"), "lookalike_domain"));
}

TEST(url_brand_embedded_is_detected) {
    ScanService s(testData());
    CHECK(hasIndicator(s.scanUrl("https://paypal.com.evil-check.example.xyz/"), "brand_embedded"));
    CHECK(hasIndicator(s.scanUrl("https://secure-amazon-login.example.top"), "brand_embedded"));
    CHECK(!hasIndicator(s.scanUrl("https://www.amazon.com/deals"), "brand_embedded"));
}

TEST(url_ip_long_subdomains_tld_and_userinfo) {
    ScanService s(testData());
    CHECK(hasIndicator(s.scanUrl("http://203.0.113.45/login"), "ip_host"));
    CHECK(hasIndicator(s.scanUrl("http://a.b.c.d.example.com/"), "many_subdomains"));
    CHECK(hasIndicator(s.scanUrl("http://shop.example.top/"), "suspicious_tld"));
    CHECK(hasIndicator(s.scanUrl("http://www.google.com@evil.example.net/"), "userinfo_trick"));
    CHECK(hasIndicator(s.scanUrl("http://a-b-c-d.example.net/"), "many_hyphens"));
    CHECK(hasIndicator(s.scanUrl("http://bit.ly/abc123"), "url_shortener"));
    CHECK(hasIndicator(s.scanUrl("http://xn--pypal-4ve.example.net/"), "punycode"));
    CHECK(hasIndicator(s.scanUrl("http://example.net/go?url=http://other.example.org"), "redirect_param"));
    CHECK(hasIndicator(s.scanUrl("http://example.net/a%20b%41%42%43"), "encoded_chars"));
    const std::string longUrl = "http://example.net/" + std::string(100, 'a');
    CHECK(hasIndicator(s.scanUrl(longUrl), "long_url"));
}

TEST(url_malformed_is_flagged_not_crashed) {
    ScanService s(testData());
    const auto r = s.scanUrl("http://bad..domain.com");
    CHECK(hasIndicator(r, "malformed_url"));
    CHECK(r.score > 0 && r.score <= 100);
    CHECK(hasIndicator(s.scanUrl(""), "malformed_url"));
}

TEST(known_threat_adds_big_score) {
    ScanService s(testData());
    const auto r = s.scanUrl("http://login.secure-login-demo.test/x");  // subdomain of a listed domain
    CHECK(hasIndicator(r, "known_threat"));
    CHECK(r.score >= 50);
}

TEST(message_scam_types_are_flagged) {
    ScanService s(testData());
    CHECK(hasIndicator(s.scanMessage("You have won a lottery! Claim your prize today"), "phrase_prize"));
    CHECK(hasIndicator(s.scanMessage("Your parcel could not be delivered, pay the fee"), "phrase_delivery"));
    CHECK(hasIndicator(s.scanMessage("Please share your OTP with our agent"), "phrase_credential"));
    CHECK(hasIndicator(s.scanMessage("Send money by gift card"), "phrase_financial"));
    CHECK(hasIndicator(s.scanMessage("Act now or the account will be blocked"), "phrase_urgency"));
    CHECK(hasIndicator(s.scanMessage("WIN BIG!!!! CLICK HERE NOW TO GET YOUR FREE GIFT"), "excessive_punct"));
    CHECK(hasIndicator(s.scanMessage("THIS IS AN IMPORTANT NOTICE FOR EVERYONE HERE"), "all_caps"));
    CHECK(hasIndicator(s.scanMessage("heyyyyy call me"), "repeated_chars"));
    CHECK(hasIndicator(s.scanMessage("code aGVsbG8gd29ybGQ4NzY1NDMyMXh5eg99 now"), "encoded_text"));
}

TEST(message_normal_text_is_low) {
    ScanService s(testData());
    const auto r = s.scanMessage("Hi, are we still meeting for lunch tomorrow at 1pm?");
    CHECK_EQ(r.score, 0);
    CHECK(r.level == RiskLevel::Low);
}

TEST(message_keyword_points_are_capped) {
    ScanService s(testData());
    const auto r = s.scanMessage("password otp pin cvv login signin verify verification credentials account bank payment refund");
    int kw = 0;
    for (const auto& i : r.indicators)
        if (i.category == IndicatorCategory::Keyword) kw += i.weight;
    CHECK(kw <= testData().config.value("cap.keyword"));
}

TEST(message_input_validation) {
    ScanService s(testData());
    CHECK_THROWS(s.scanMessage(""));
    CHECK_THROWS(s.scanMessage("   \n  "));
    CHECK_THROWS(s.scanMessage(std::string(20000, 'a')));
    CHECK_THROWS(s.scanMessage(std::string("bad\x01text")));
}

TEST(message_links_are_analyzed_and_raise_score) {
    ScanService s(testData());
    const auto plain = s.scanMessage("Please check this");
    const auto withLink = s.scanMessage("Please check this http://203.0.113.5/login");
    CHECK(withLink.score > plain.score);
    CHECK(hasIndicator(withLink, "ip_host"));
    CHECK_EQ(withLink.findings.urls.size(), 1u);
    CHECK_EQ(withLink.findings.ips.size(), 1u);
}

TEST(risk_score_never_exceeds_100_and_levels_are_ordered) {
    ScanService s(testData());
    const auto r = s.scanMessage("URGENT!!! Act now: verify your account and share your OTP and PIN. You have won a prize, pay the fee at http://bank-verify-now.test/login");
    CHECK(r.score <= 100);
    CHECK(r.level == RiskLevel::Critical);
    CHECK(levelInt(r) >= levelInt(s.scanUrl("https://paypa1.com")));
}

TEST(indicators_are_deduplicated) {
    ScanService s(testData());
    const auto r = s.scanMessage("login login login http://x.example.top/login");
    int loginCount = 0;
    for (const auto& i : r.indicators)
        if (i.id == "keyword:login") ++loginCount;
    CHECK_EQ(loginCount, 1);
}
