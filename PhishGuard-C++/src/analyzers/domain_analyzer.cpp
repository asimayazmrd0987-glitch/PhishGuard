// =============================================================================
// FILE: src/analyzers/domain_analyzer.cpp
// WHAT   Implementation of the domain checks and the impersonation search.
// HOW    consider() keeps the match with the smallest edit distance (an "embedded" match wins ties).
//        Each indicator carries a plain-language sentence for the user. Costs: for one URL the
//        impersonation search does about (tokens + 1) x (trusted domains) edit-distance
//        calculations of short strings, which is fast for hundreds of trusted entries but would need
//        an index (for example a BK-tree) for millions.
// FALSE POSITIVES  Real sites with names close to a brand (an edit distance of 1 from "apple")
//        can be flagged; that is why the result says "possible" and the score is only one signal.
// =============================================================================

#include "phishguard/analyzers/domain_analyzer.hpp"

#include "phishguard/algorithms/levenshtein.hpp"
#include "phishguard/algorithms/string_match.hpp"
#include "phishguard/common/text_utils.hpp"

namespace phishguard {

int DomainAnalyzer::allowedEdits(std::size_t length) {
    if (length <= 4) return 0;  // very short names: any edit makes a different word
    return length <= 8 ? 1 : 2;
}

std::optional<ImpersonationMatch> DomainAnalyzer::findImpersonation(const ParsedUrl& p) const {
    if (!p.valid || p.hostIsIp || data_.trusted.isTrustedHost(p.host)) return std::nullopt;
    const auto trusted = data_.trusted.snapshot();
    std::optional<ImpersonationMatch> best;
    auto consider = [&best](ImpersonationMatch m) {
        if (!best || m.distance < best->distance || (m.distance == best->distance && m.embedded && !best->embedded))
            best = std::move(m);
    };

    for (const auto& t : trusted) {
        // (1) the whole trusted domain appears inside a different host: paypal.com.evil.example
        if (!rabinKarpSearch(p.host, t.domain).empty()) consider({p.host, t.domain, 0, 1.0, false, true});

        // (2) registered domain vs trusted domain (paypa1.com vs paypal.com)
        const int raw = editDistance(p.registeredDomain, t.domain);
        const bool folded = editDistance(text::normalizeLookalikes(p.registeredDomain), t.domain) == 0;
        if (raw >= 1 && (raw <= allowedEdits(t.domain.size()) || folded))
            consider({p.registeredDomain, t.domain, raw, similarity(p.registeredDomain, t.domain), folded && raw > 0, false});
    }

    // (3) token by token: secure-paypa1-login.example.xyz -> secure | paypa1 | login | example | xyz
    for (const auto& token : text::splitAny(p.host, ".-_")) {
        if (token.size() < 4) continue;
        const std::string folded = text::normalizeLookalikes(token);
        for (const auto& t : trusted) {
            const std::string& brand = t.brand;
            if (brand.size() < 4) continue;
            if (token == brand) {
                consider({token, t.domain, 0, 1.0, false, true});
                continue;
            }
            const int d = editDistance(token, brand);
            if (folded == brand) consider({token, t.domain, d, similarity(token, brand), true, false});
            else if (d >= 1 && d <= allowedEdits(brand.size())) consider({token, t.domain, d, similarity(token, brand), false, false});
            else if (brand.size() >= 5 && !kmpSearch(folded, brand).empty()) consider({token, t.domain, 0, 1.0, folded != token, true});
        }
    }
    return best;
}

std::vector<Indicator> DomainAnalyzer::analyze(const ParsedUrl& p, std::optional<ImpersonationMatch>& impersonation) const {
    std::vector<Indicator> out;
    impersonation.reset();
    if (!p.valid) return out;
    const RiskConfig& cfg = data_.config;

    if (const ThreatEntry* t = data_.threats.findForHost(p.host))
        out.push_back({"known_threat",
                       "This website address is in our local list of known scam examples (" + t->category + ").",
                       cfg.weight("weight.known_threat"), IndicatorCategory::Threat, t->domain});

    if (p.hostIsIp) {
        out.push_back({"ip_host", "The link uses a number address instead of a normal website name. Real companies rarely do this.",
                       cfg.weight("weight.ip_host"), IndicatorCategory::Domain, p.host});
        return out;
    }
    if (data_.trusted.isTrustedHost(p.host)) return out;

    if (data_.suspiciousTlds.contains(p.tld))
        out.push_back({"suspicious_tld", "The website ends in \"." + p.tld + "\", an ending that is often used by throw-away scam sites.",
                       cfg.weight("weight.suspicious_tld"), IndicatorCategory::Domain, p.tld});
    if (data_.urlShorteners.contains(p.registeredDomain))
        out.push_back({"url_shortener", "The link is shortened, so you cannot see where it really leads.",
                       cfg.weight("weight.url_shortener"), IndicatorCategory::Domain, p.registeredDomain});
    if (p.subdomainCount >= cfg.value("limit.many_subdomains"))
        out.push_back({"many_subdomains", "The website name has many parts before the main name, which is a common way to look official.",
                       cfg.weight("weight.many_subdomains"), IndicatorCategory::Domain, std::to_string(p.subdomainCount)});

    int hyphens = 0;
    for (char c : p.host) hyphens += (c == '-');
    if (hyphens >= cfg.value("limit.many_hyphens"))
        out.push_back({"many_hyphens", "The website name contains many hyphens, which is unusual for genuine sites.",
                       cfg.weight("weight.many_hyphens"), IndicatorCategory::Domain, std::to_string(hyphens)});
    if (static_cast<int>(p.host.size()) > cfg.value("limit.long_host"))
        out.push_back({"long_host", "The website name is unusually long.", cfg.weight("weight.long_host"),
                       IndicatorCategory::Domain, std::to_string(p.host.size())});

    int digits = 0, letters = 0;
    for (char c : p.registeredLabel) {
        digits += text::isDigitChar(c);
        letters += text::isAlphaChar(c);
    }
    if (digits >= 1 && letters >= 3)
        out.push_back({"digits_in_domain", "The main website name mixes numbers into a word, a trick used to imitate real names.",
                       cfg.weight("weight.digits_in_domain"), IndicatorCategory::Domain, p.registeredLabel});

    bool puny = false;
    for (const auto& l : p.labels) puny = puny || text::startsWith(l, "xn--");
    for (char c : p.host) puny = puny || static_cast<unsigned char>(c) >= 0x80;
    if (puny)
        out.push_back({"punycode", "The website name uses special or foreign characters that can imitate normal letters.",
                       cfg.weight("weight.punycode"), IndicatorCategory::Domain, p.host});

    impersonation = findImpersonation(p);
    if (impersonation) {
        if (impersonation->embedded)
            out.push_back({"brand_embedded",
                           "The name of a trusted website (" + impersonation->trustedDomain +
                               ") appears inside this address, but the site itself is different. Scammers do this to look official.",
                           cfg.weight("weight.brand_embedded"), IndicatorCategory::Similarity, impersonation->trustedDomain});
        else
            out.push_back({"lookalike_domain",
                           "This website name is very similar to a trusted website (" + impersonation->trustedDomain +
                               "), which may indicate impersonation.",
                           cfg.weight("weight.lookalike"), IndicatorCategory::Similarity, impersonation->trustedDomain});
    }
    return out;
}

}  // namespace phishguard
