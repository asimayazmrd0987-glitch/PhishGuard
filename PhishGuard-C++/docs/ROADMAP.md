# From semester project to a tool real people can use

Be clear about the goal: PhishGuard today is an **explainable, offline heuristic assistant**. It is not a
security guarantee. The steps below make it more accurate, easier for non-technical people to use, and safer.

## 0. Before you change anything: freeze the submission
```
git tag v1.0-submission
git push origin v1.0-submission
git switch -c develop        # do all new work here; main stays the presented version
```
Present from the tag so later experiments can never break what your examiner sees.

## 1. Make the detection trustworthy (most important)
| Step | Why | How |
|---|---|---|
| Build a **labelled test set** (hundreds of scam and genuine messages/links, anonymised) | Right now the weights are judgement. You cannot claim accuracy without measurement. | Put them in `data/eval/`, write a small tool that prints precision, recall and a confusion matrix; re-run it after every weight change. |
| Report false positives and false negatives with numbers | Honest evaluation, and it shows which rules hurt. | Track them per indicator to find noisy rules. |
| Real threat intelligence | The sample list is synthetic. | Consider public phishing feeds (for example PhishTank or OpenPhish) **after reading each one's licence and terms**; add a script that refreshes `sample_threats.txt` and records the source and date of each entry. |
| Full **Public Suffix List** | Our two-part suffix list is tiny, so `x.com.pk`-style names can be misparsed. | Load publicsuffix.org data instead of `public_suffixes.txt`. |
| **Unicode look-alikes** (Cyrillic "a" vs Latin "a") and Damerau-Levenshtein | Only ASCII swaps and plain edits are caught today. | Add a confusables table; count a transposition as one edit. |
| **Local languages** (for example Urdu script and Roman Urdu) | Scammers use the language of the victim; the phrase lists are English only. | Collect phrases from real scam messages people report; add them to `suspicious_phrases.txt`. No code change needed. |
| Index for impersonation search | Comparing against every trusted domain is O(T). Fine for hundreds, slow for millions. | A BK-tree over edit distance, or a trie of brand names. |
| Fix the known weak spots | `securelogin` (no word boundary) is missed; hijacked subdomains of trusted sites are trusted. | Substring brand search with KMP on tokens; optional "do not trust subdomains" list. |

## 2. Make it usable by laymen
Today it is a terminal program, which most ordinary users will not open. Options, easiest first:
1. **Web page (WebAssembly):** compile `phishguard_core` with Emscripten and put a simple page in front (a text box, a big coloured result). It runs in the browser, so messages never leave the user's device. Host on GitHub Pages or Vercel.
2. **Small local web service:** wrap `ScanService` in a tiny HTTP server; a mobile app or browser extension calls it.
3. **Browser extension:** warn before a link is opened (needs the WebAssembly build).
4. **Android "Share" target:** share a suspicious SMS/WhatsApp message to the app to scan it.
Design rules for laymen: very large text, colour AND words for the level (not colour alone), one clear action ("Do not click. Call your bank on the number printed on your card"), no jargon, local language, works offline.

## 3. Privacy, safety and abuse
* Keep analysis **on the device**; do not upload messages. If you ever add a server, say so plainly and let users opt out.
* Keep the redaction rules (`text_utils.cpp`) and add tests for every new secret format (card numbers, CNIC/ID numbers, bank IBANs).
* Never present a result as a guarantee. Keep the disclaimer and the wording "indicators detected".
* Think about attackers: published rules can be studied and evaded. That is normal for heuristics; layer them with feeds and keep rules updated.
* Have someone else review the code for security before real use (the parser handles hostile input).

## 4. Engineering quality
* CI is already set up (`.github/workflows/ci.yml`). Add: `clang-tidy`/`cppcheck`, a code-coverage report, and **fuzz testing** of `UrlParser::parse` and `MessageAnalyzer::analyze` (libFuzzer) because they take untrusted text.
* Replace the `std::vector`-based queue/stack helpers only if profiling shows a need; do not optimise without measurements.
* Version the data files and the scoring weights (put a `version=` line in `risk_config.txt`) so results can be reproduced.
* Add a `CHANGELOG.md`, and tag releases (`v1.1.0` ...); `release.yml` then builds downloads for Windows, Linux and macOS.

## 5. Suggested order of work
1. Evaluation tool + labelled set (so every later change is measured).
2. Public Suffix List + Unicode look-alikes.
3. WebAssembly web page with big-text UI.
4. Local-language phrases from real reports.
5. Browser extension / Android share target.
6. Threat feeds (with licence check) and fuzzing.

## 6. For the final presentation
Show: the tag `v1.0-submission`, the green CI badge, the demo run, the benchmark honesty (hash vs binary), the two deliberate failures (demos 12 and 14), and this roadmap as "what real use requires".
