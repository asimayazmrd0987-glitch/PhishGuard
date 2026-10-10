// =============================================================================
// FILE: include/phishguard/analyzers/domain_analyzer.hpp
// WHAT   Looks at the WEBSITE NAME only (not the path): known-threat match, IP address, suspicious
//        ending, shortener, many subdomains/hyphens, long name, digits mixed into a word,
//        punycode, and IMPERSONATION of trusted sites.
// HOW    Impersonation uses three checks and keeps the closest match:
//        1. Rabin-Karp: is a whole trusted domain hidden inside the host? (paypal.com.evil.test)
//        2. Levenshtein: registered domain vs every trusted domain (paypa1.com vs paypal.com),
//           after also trying the look-alike-folded form (g00gle -> google).
//        3. Token by token (split on . - _): each word vs each brand name; KMP finds a brand
//           glued inside a longer word ("paypalsecure").
//        Allowed edits depend on length (<=4 letters: none, <=8: one, longer: two) to avoid
//        false alarms on short words.
// WHY    Look-alike domains are one of the most common phishing tricks and cannot be caught by a
//        simple blocklist. Trusted hosts return no indicators at all.
// =============================================================================
#pragma once
#include <optional>
#include <vector>

#include "phishguard/analyzers/url_parser.hpp"
#include "phishguard/common/types.hpp"
#include "phishguard/security/detection_data.hpp"

namespace phishguard {

class DomainAnalyzer {
public:
    explicit DomainAnalyzer(const DetectionData& data) : data_(data) {}

    // Domain-level indicators. Trusted hosts yield none. 'impersonation' is filled when a
    // look-alike / embedded trusted name is found.
    std::vector<Indicator> analyze(const ParsedUrl& url, std::optional<ImpersonationMatch>& impersonation) const;

    // Compares the host with trusted domains/brands using Levenshtein (DP), look-alike
    // character folding, Rabin-Karp (full trusted domain hidden in the host) and KMP
    // (brand hidden inside a token). Similarity alone does NOT prove malicious intent.
    std::optional<ImpersonationMatch> findImpersonation(const ParsedUrl& url) const;

    static int allowedEdits(std::size_t length);  // 0 for <=4 chars, 1 for <=8, else 2

private:
    const DetectionData& data_;
};

}  // namespace phishguard
