// =============================================================================
// FILE: src/ui/demo_scenarios.cpp
// WHAT   The scenario data. Only synthetic data is used: .test domains, documentation IP ranges
//        (203.0.113.0/24, 192.0.2.0/24) and fictional messages.
// INCLUDES  Two deliberate failure cases: demo 12 (a genuine-looking urgent bank alert that scores
//        MEDIUM = false positive) and demo 14 (a polite scam that scores LOW = false negative).
// =============================================================================

#include "phishguard/ui/demo_scenarios.hpp"

namespace phishguard {

const std::vector<DemoScenario>& demoScenarios() {
    using L = RiskLevel;
    static const std::vector<DemoScenario> demos = {
        {"1. Normal URL", InputType::Url, "https://www.google.com/search?q=cats", L::Low, L::Low,
         "Hash table (trusted-domain lookup), URL parser", "Trusted website: wording heuristics are skipped."},
        {"2. Suspicious URL", InputType::Url, "http://secure-account-verify.example.top/login/update-password", L::Medium, L::High,
         "Trie (keywords), hash set (TLD list), URL parser", "Several scam words plus an unusual ending."},
        {"3. Look-alike domain", InputType::Url, "https://paypa1.com/signin", L::Medium, L::High,
         "Levenshtein DP, look-alike folding, trusted-domain hash table", "paypa1 vs paypal: edit distance 1."},
        {"4. Typosquatting", InputType::Url, "https://micr0soft.com/support", L::Medium, L::High,
         "Levenshtein DP, look-alike folding", "0 used instead of o."},
        {"5. Brand hidden in address", InputType::Url, "https://paypal.com.account-check.example.xyz/login", L::High, L::Critical,
         "Rabin-Karp (domain inside host), Trie, hash set", "The trusted name is only a subdomain of another site."},
        {"6. IP-address link", InputType::Url, "http://203.0.113.45/login/verify", L::Medium, L::High,
         "URL parser (IPv4), Trie", "Documentation-range IP (203.0.113.0/24)."},
        {"7. Prize scam message", InputType::Message,
         "CONGRATULATIONS!!! You are the WINNER of a free reward. Claim your prize now: http://free-prize-claim.test/win", L::Critical, L::Critical,
         "KMP (phrases), Trie, hash table (threat DB), heap, graph", "Link is in the synthetic threat list."},
        {"8. Bank phishing message", InputType::Message,
         "Dear customer, your bank account has been suspended. Verify your account immediately at http://bank-verify-now.test to avoid permanent closure.",
         L::Critical, L::Critical, "KMP, Trie, hash table, risk engine", "Credential + urgency + known threat."},
        {"9. Delivery scam", InputType::Message,
         "Your parcel could not be delivered. Pay a small delivery fee at http://parcel-fee-pay.test/pay to reschedule delivery.",
         L::High, L::Critical, "KMP, hash table, risk engine", "Delivery + fee request + known threat."},
        {"10. Account suspension scam", InputType::Message,
         "Your account will be suspended within 24 hours. Confirm your identity at http://192.0.2.15/verify now.", L::High, L::Critical,
         "KMP, Trie, URL parser (IPv4)", "Urgency + credential request + IP link."},
        {"11. OTP scam", InputType::Message,
         "Your bank needs verification. Please share your OTP and PIN with our agent right away.", L::Medium, L::High,
         "KMP, Trie, risk engine (keyword cap)", "No link at all: scams can be text only."},
        {"12. Legitimate urgent message (false-positive risk)", InputType::Message,
         "URGENT: Your bank card payment of $50 failed. Please update your payment details in the official app.", L::Medium, L::High,
         "Trie, risk engine", "A real alert can look suspicious: documented false positive."},
        {"13. Malformed URL", InputType::Url, "http://bad..domain.com/page", L::Low, L::Medium,
         "URL parser validation", "Parser rejects an empty label."},
        {"14. Polite scam (false-negative risk)", InputType::Message,
         "Hi Mum, I dropped my phone in water. This is my new number, can you text me here?", L::Low, L::Low,
         "Trie, KMP (nothing matches)", "No keywords or links: heuristics miss it (documented false negative)."},
    };
    return demos;
}

}  // namespace phishguard
