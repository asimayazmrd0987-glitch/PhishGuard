// =============================================================================
// FILE: src/analyzers/url_analyzer.cpp
// WHAT   Implementation of link-level checks.
// HOW    * Malformed link: one indicator, then stop (nothing else is reliable).
//        * Trusted website: wording checks are SKIPPED, because "login" and "account" are normal
//          on accounts.google.com. (Trade-off: a hijacked trusted site would be missed.)
//        * Redirect check: a parameter named url/redirect/next/goto/... whose value contains
//          "http", "//" or "%2f%2f" (found with KMP) means "another address is hidden inside".
//        * Keywords: the Trie scans host + path + query once; each distinct word is one indicator.
// =============================================================================

#include "phishguard/analyzers/url_analyzer.hpp"

#include "phishguard/algorithms/string_match.hpp"
#include "phishguard/common/text_utils.hpp"
#include "phishguard/ds/custom_set.hpp"

namespace phishguard {

namespace {

int countPercentEncoded(const std::string& s) {
    int n = 0;
    auto hex = [](char c) { return text::isDigitChar(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); };
    for (std::size_t i = 0; i + 2 < s.size(); ++i)
        if (s[i] == '%' && hex(s[i + 1]) && hex(s[i + 2])) ++n;
    return n;
}

bool isRedirectKey(const std::string& k) {
    static const char* keys[] = {"url", "redirect", "redirect_uri", "redirecturl", "next", "return",
                                 "returnurl", "goto", "dest", "destination", "continue", "link"};
    for (const char* x : keys)
        if (k == x) return true;
    return false;
}

}  // namespace

UrlAnalysis UrlAnalyzer::analyze(const std::string& rawUrl) const {
    UrlAnalysis res;
    res.parsed = parser_.parse(rawUrl);
    const ParsedUrl& p = res.parsed;
    const RiskConfig& cfg = data_.config;
    auto& out = res.indicators;

    if (!p.valid) {
        out.push_back({"malformed_url", "The link is not formatted like a normal web address (" + p.error + ").",
                       cfg.weight("weight.malformed"), IndicatorCategory::Url, p.error});
        return res;
    }

    if (p.scheme != "http" && p.scheme != "https" && p.scheme != "ftp")
        out.push_back({"unusual_scheme", "The link uses an unusual type (\"" + p.scheme + "://\") instead of a normal web link.",
                       cfg.weight("weight.unusual_scheme"), IndicatorCategory::Url, p.scheme});
    if (!p.userinfo.empty())
        out.push_back({"userinfo_trick", "The link has an \"@\" sign before the real website name, a trick that hides where it leads.",
                       cfg.weight("weight.userinfo_trick"), IndicatorCategory::Url, p.host});

    for (auto& ind : domain_.analyze(p, res.impersonation)) out.push_back(std::move(ind));

    // Genuine trusted sites skip the wording heuristics ("login", "account" are normal there).
    if (!p.hostIsIp && data_.trusted.isTrustedHost(p.host)) return res;

    const std::string trimmed = text::trim(rawUrl);
    if (static_cast<int>(trimmed.size()) > cfg.value("limit.long_url"))
        out.push_back({"long_url", "The link is very long, which can hide where it really goes.", cfg.weight("weight.long_url"),
                       IndicatorCategory::Url, std::to_string(trimmed.size())});
    if (countPercentEncoded(trimmed) >= cfg.value("limit.encoded_chars"))
        out.push_back({"encoded_chars", "The link contains unusual characters that are commonly seen in suspicious URLs.",
                       cfg.weight("weight.encoded_chars"), IndicatorCategory::Url, ""});

    for (const auto& pair : text::split(p.query, '&')) {
        const auto eq = pair.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = text::toLower(pair.substr(0, eq));
        const std::string val = text::toLower(pair.substr(eq + 1));
        if (isRedirectKey(key) && (!kmpSearch(val, "http").empty() || !kmpSearch(val, "//").empty() || !kmpSearch(val, "%2f%2f").empty())) {
            out.push_back({"redirect_param", "The link contains another web address inside it, which can send you somewhere else.",
                           cfg.weight("weight.redirect_param"), IndicatorCategory::Url, key});
            break;
        }
    }

    // Keyword scan over host + path + query using the Trie (one pass per word start).
    CustomSet<std::string> seen;
    for (const auto& m : data_.keywords.scanText(p.host + " " + p.path + " " + p.query)) {
        if (!seen.insert(m.word)) continue;
        const int w = m.info.weight > 0 ? m.info.weight : cfg.weight("weight.keyword");
        out.push_back({"keyword:" + m.word, "The link contains the word \"" + m.word + "\", which scammers often use to look trustworthy or create pressure.",
                       w, IndicatorCategory::Keyword, m.word});
    }
    return res;
}

}  // namespace phishguard
