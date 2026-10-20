"""Fourteen deterministic demo scenarios from the C++ edition."""
from dataclasses import dataclass
from .types import InputType, RiskLevel

@dataclass
class DemoScenario:
    title: str
    type: InputType
    input: str
    min_level: RiskLevel
    max_level: RiskLevel
    algorithms: str
    note: str


def demo_scenarios() -> list[DemoScenario]:
    L = RiskLevel
    M = InputType.MESSAGE
    U = InputType.URL
    return [
        DemoScenario('1. Normal URL', U, 'https://www.google.com/search?q=cats', L.LOW, L.LOW, 'Hash table, URL parser', 'Trusted website: wording heuristics are skipped.'),
        DemoScenario('2. Suspicious URL', U, 'http://secure-account-verify.example.top/login/update-password', L.MEDIUM, L.HIGH, 'Trie, custom set, URL parser', 'Several scam words plus an unusual ending.'),
        DemoScenario('3. Look-alike domain', U, 'https://paypa1.com/signin', L.MEDIUM, L.HIGH, 'Levenshtein DP, look-alike folding', 'paypa1 vs paypal: edit distance 1.'),
        DemoScenario('4. Typosquatting', U, 'https://micr0soft.com/support', L.MEDIUM, L.HIGH, 'Levenshtein DP, look-alike folding', '0 used instead of o.'),
        DemoScenario('5. Brand hidden in address', U, 'https://paypal.com.account-check.example.xyz/login', L.HIGH, L.CRITICAL, 'Rabin-Karp, Trie, custom set', 'The trusted name is only a subdomain of another site.'),
        DemoScenario('6. IP-address link', U, 'http://203.0.113.45/login/verify', L.MEDIUM, L.HIGH, 'URL parser (IPv4), Trie', 'Documentation-range IP (203.0.113.0/24).'),
        DemoScenario('7. Prize scam message', M, 'CONGRATULATIONS!!! You are the WINNER of a free reward. Claim your prize now: http://free-prize-claim.test/win', L.CRITICAL, L.CRITICAL, 'KMP, Trie, hash table, heap, graph', 'Link is in the synthetic threat list.'),
        DemoScenario('8. Bank phishing message', M, 'Dear customer, your bank account has been suspended. Verify your account immediately at http://bank-verify-now.test to avoid permanent closure.', L.CRITICAL, L.CRITICAL, 'KMP, Trie, hash table, risk engine', 'Credential + urgency + known threat.'),
        DemoScenario('9. Delivery scam', M, 'Your parcel could not be delivered. Pay a small delivery fee at http://parcel-fee-pay.test/pay to reschedule delivery.', L.HIGH, L.CRITICAL, 'KMP, hash table, risk engine', 'Delivery + fee request + known threat.'),
        DemoScenario('10. Account suspension scam', M, 'Your account will be suspended within 24 hours. Confirm your identity at http://192.0.2.15/verify now.', L.HIGH, L.CRITICAL, 'KMP, Trie, URL parser (IPv4)', 'Urgency + credential request + IP link.'),
        DemoScenario('11. OTP scam', M, 'Your bank needs verification. Please share your OTP and PIN with our agent right away.', L.MEDIUM, L.HIGH, 'KMP, Trie, risk engine', 'No link at all: scams can be text only.'),
        DemoScenario('12. Legitimate urgent message (false-positive risk)', M, 'URGENT: Your bank card payment of $50 failed. Please update your payment details in the official app.', L.MEDIUM, L.HIGH, 'Trie, risk engine', 'A real alert can look suspicious: documented false positive.'),
        DemoScenario('13. Malformed URL', U, 'http://bad..domain.com/page', L.LOW, L.MEDIUM, 'URL parser validation', 'Parser rejects an empty label.'),
        DemoScenario('14. Polite scam (false-negative risk)', M, 'Hi Mum, I dropped my phone in water. This is my new number, can you text me here?', L.LOW, L.LOW, 'Trie, KMP', 'No keywords or links: heuristics miss it (documented false negative).'),
    ]
