# Demo scenarios

Run `python main.py --demo` to try the 14 deterministic examples. The program prints the matched indicators, score band and recommendation. The same scenarios are available from interactive menu option 12.

```bash
python main.py --demo
python -m phishguard demo --json
python -m phishguard demo --strict   # exit 1 if any scenario leaves its expected band
```

`--strict` is the quick regression check to run after changing weights, thresholds or detectors.

| # | Scenario | Expected result band | Main concept |
|---:|---|---|---|
| 1 | Normal trusted URL | LOW | Trusted-domain hash lookup |
| 2 | Suspicious URL | MEDIUM–HIGH | TLD + keyword heuristics |
| 3 | `paypa1.com` | MEDIUM–HIGH | Edit distance and look-alike folding |
| 4 | `micr0soft.com` | MEDIUM–HIGH | Digit-to-letter look-alike mapping |
| 5 | Trusted name embedded in a different host | HIGH–CRITICAL | Rabin–Karp / embedded brand |
| 6 | Documentation IP address link | MEDIUM–HIGH | URL parser and IP indicator |
| 7 | Synthetic prize scam | CRITICAL | Text + listed threat domain |
| 8 | Synthetic bank phishing message | CRITICAL | Phrase matching and threat database |
| 9 | Synthetic delivery scam | HIGH–CRITICAL | Delivery and fee phrases |
| 10 | Suspension message with IP link | HIGH–CRITICAL | Urgency + credential request + IP |
| 11 | OTP message without a link | MEDIUM–HIGH | Message-only indicators |
| 12 | Genuine-looking urgent bank message | MEDIUM–HIGH | Deliberate false-positive example |
| 13 | Malformed URL | LOW–MEDIUM | Parser validation |
| 14 | Polite social-engineering message | LOW | Deliberate false-negative example |

All sample links use the reserved `.test` TLD or documentation-only IP ranges. The demo classifications are not a measurement of real-world detector accuracy.
