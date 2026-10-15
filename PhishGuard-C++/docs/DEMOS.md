# Demonstration Scenarios (14)

Generated from `phishguard --demo`. All inputs are synthetic or use documentation-range data. Each scenario's expected level range was fixed in `src/ui/demo_scenarios.cpp` *before* looking at the results; all 14 landed in range (also checked by an automated test).

## 1. Normal URL
- **Input:** `https://www.google.com/search?q=cats`
- **Algorithms involved:** Hash table (trusted-domain lookup), URL parser
- **Detected indicators:** none
- **Result:** Risk Score: 0 / 100   Level: LOW   (expected LOW: OK)
- **Recommendation:** Probably safe based on the checks we ran, but stay careful. If you did not expect this, confirm it through an official website or app.
- **Note:** Trusted website: wording heuristics are skipped.

## 2. Suspicious URL
- **Input:** `http://secure-account-verify.example.top/login/update-password`
- **Algorithms involved:** Trie (keywords), hash set (TLD list), URL parser
- **Detected indicators:** [+10] suspicious_tld, [+10] keyword:password, [+8] keyword:verify, [+7] keyword:login, [+5] long_host
- **Result:** Risk Score: 40 / 100   Level: MEDIUM   (expected MEDIUM-HIGH: OK)
- **Recommendation:** Some suspicious signs were found. Do not enter passwords or payment details until you have checked through the official website or app.
- **Note:** Several scam words plus an unusual ending.

## 3. Look-alike domain
- **Input:** `https://paypa1.com/signin`
- **Algorithms involved:** Levenshtein DP, look-alike folding, trusted-domain hash table
- **Detected indicators:** [+30] lookalike_domain, [+7] keyword:signin, [+5] digits_in_domain
- **Result:** Risk Score: 42 / 100   Level: HIGH   (expected MEDIUM-HIGH: OK)
- **Recommendation:** Several suspicious signs were found. Do not click the link or share personal information. Contact the company using the phone number on its official website.
- **Note:** paypa1 vs paypal: edit distance 1.

## 4. Typosquatting
- **Input:** `https://micr0soft.com/support`
- **Algorithms involved:** Levenshtein DP, look-alike folding
- **Detected indicators:** [+30] lookalike_domain, [+5] digits_in_domain
- **Result:** Risk Score: 35 / 100   Level: MEDIUM   (expected MEDIUM-HIGH: OK)
- **Recommendation:** Some suspicious signs were found. Do not enter passwords or payment details until you have checked through the official website or app.
- **Note:** 0 used instead of o.

## 5. Brand hidden in address
- **Input:** `https://paypal.com.account-check.example.xyz/login`
- **Algorithms involved:** Rabin-Karp (domain inside host), Trie, hash set
- **Detected indicators:** [+25] brand_embedded, [+10] suspicious_tld, [+10] many_subdomains, [+7] keyword:login, [+5] long_host, [+5] keyword:account
- **Result:** Risk Score: 62 / 100   Level: HIGH   (expected HIGH-CRITICAL: OK)
- **Recommendation:** Several suspicious signs were found. Do not click the link or share personal information. Contact the company using the phone number on its official website.
- **Note:** The trusted name is only a subdomain of another site.

## 6. IP-address link
- **Input:** `http://203.0.113.45/login/verify`
- **Algorithms involved:** URL parser (IPv4), Trie
- **Detected indicators:** [+20] ip_host, [+8] keyword:verify, [+7] keyword:login
- **Result:** Risk Score: 35 / 100   Level: MEDIUM   (expected MEDIUM-HIGH: OK)
- **Recommendation:** Some suspicious signs were found. Do not enter passwords or payment details until you have checked through the official website or app.
- **Note:** Documentation-range IP (203.0.113.0/24).

## 7. Prize scam message
- **Input:** `CONGRATULATIONS!!! You are the WINNER of a free reward. Claim your prize now: http://free-prize-claim.test/win`
- **Algorithms involved:** KMP (phrases), Trie, hash table (threat DB), heap, graph
- **Detected indicators:** [+50] known_threat, [+10] phrase_prize, [+8] keyword:winner, [+8] keyword:prize, [+6] keyword:reward, [+3] keyword:claim, [+5] excessive_punct
- **Result:** Risk Score: 90 / 100   Level: CRITICAL   (expected CRITICAL: OK)
- **Recommendation:** DO NOT ENTER YOUR PASSWORD.
- **Note:** Link is in the synthetic threat list.

## 8. Bank phishing message
- **Input:** `Dear customer, your bank account has been suspended. Verify your account immediately at http://bank-verify-now.test to avoid permanent closure.`
- **Algorithms involved:** KMP, Trie, hash table, risk engine
- **Detected indicators:** [+50] known_threat, [+15] phrase_credential, [+10] phrase_urgency, [+8] keyword:suspended, [+8] keyword:verify, [+6] keyword:bank, [+3] keyword:account
- **Result:** Risk Score: 100 / 100   Level: CRITICAL   (expected CRITICAL: OK)
- **Recommendation:** DO NOT ENTER YOUR PASSWORD.
- **Note:** Credential + urgency + known threat.

## 9. Delivery scam
- **Input:** `Your parcel could not be delivered. Pay a small delivery fee at http://parcel-fee-pay.test/pay to reschedule delivery.`
- **Algorithms involved:** KMP, hash table, risk engine
- **Detected indicators:** [+50] known_threat, [+15] phrase_financial, [+10] phrase_delivery
- **Result:** Risk Score: 75 / 100   Level: CRITICAL   (expected HIGH-CRITICAL: OK)
- **Recommendation:** DO NOT ENTER YOUR PASSWORD.
- **Note:** Delivery + fee request + known threat.

## 10. Account suspension scam
- **Input:** `Your account will be suspended within 24 hours. Confirm your identity at http://192.0.2.15/verify now.`
- **Algorithms involved:** KMP, Trie, URL parser (IPv4)
- **Detected indicators:** [+20] ip_host, [+15] phrase_credential, [+10] phrase_urgency, [+8] keyword:suspended, [+8] keyword:verify, [+6] keyword:confirm, [+3] keyword:account
- **Result:** Risk Score: 70 / 100   Level: HIGH   (expected HIGH-CRITICAL: OK)
- **Recommendation:** Several suspicious signs were found. Do not click the link or share personal information. Contact the company using the phone number on its official website.
- **Note:** Urgency + credential request + IP link.

## 11. OTP scam
- **Input:** `Your bank needs verification. Please share your OTP and PIN with our agent right away.`
- **Algorithms involved:** KMP, Trie, risk engine (keyword cap)
- **Detected indicators:** [+15] phrase_credential, [+10] phrase_urgency, [+10] keyword:otp, [+10] keyword:pin, [+5] keyword:verification
- **Result:** Risk Score: 50 / 100   Level: HIGH   (expected MEDIUM-HIGH: OK)
- **Recommendation:** Several suspicious signs were found. Do not click the link or share personal information. Contact the company using the phone number on its official website.
- **Note:** No link at all: scams can be text only.

## 12. Legitimate urgent message (false-positive risk)
- **Input:** `URGENT: Your bank card payment of $50 failed. Please update your payment details in the official app.`
- **Algorithms involved:** Trie, risk engine
- **Detected indicators:** [+8] keyword:urgent, [+7] keyword:payment, [+6] keyword:bank, [+4] keyword:update
- **Result:** Risk Score: 25 / 100   Level: MEDIUM   (expected MEDIUM-HIGH: OK)
- **Recommendation:** Some suspicious signs were found. Do not enter passwords or payment details until you have checked through the official website or app.
- **Note:** A real alert can look suspicious: documented false positive.

## 13. Malformed URL
- **Input:** `http://bad..domain.com/page`
- **Algorithms involved:** URL parser validation
- **Detected indicators:** [+10] malformed_url
- **Result:** Risk Score: 10 / 100   Level: LOW   (expected LOW-MEDIUM: OK)
- **Recommendation:** Probably safe based on the checks we ran, but stay careful. If you did not expect this, confirm it through an official website or app.
- **Note:** Parser rejects an empty label.

## 14. Polite scam (false-negative risk)
- **Input:** `Hi Mum, I dropped my phone in water. This is my new number, can you text me here?`
- **Algorithms involved:** Trie, KMP (nothing matches)
- **Detected indicators:** none
- **Result:** Risk Score: 0 / 100   Level: LOW   (expected LOW: OK)
- **Recommendation:** Probably safe based on the checks we ran, but stay careful. If you did not expect this, confirm it through an official website or app.
- **Note:** No keywords or links: heuristics miss it (documented false negative).
