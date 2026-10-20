# PhishGuard — Interactive Menu User Guide

This guide explains how to use every option in the PhishGuard terminal menu, what to enter, what the results mean, and how to use the extra tools.

> **Important safety note:** PhishGuard is an educational, local rule-based analyzer. It analyzes the text you provide; it does **not** open the link, visit the website, perform DNS lookups, or check live online reputation services. A LOW score does not guarantee safety, and a HIGH or CRITICAL score is not proof that a scam has occurred. Do not enter real passwords, OTPs, payment details, or other secrets into test messages.

---

## 1. Start PhishGuard

1. Download and extract the PhishGuard Python project ZIP.
2. Open a terminal/Command Prompt in the extracted `PhishGuard-Python` folder—the folder that contains `main.py` and `data/`.
3. Check that Python 3.10 or newer is installed:

   ```bash
   python --version
   ```

4. Start the interactive menu:

   ```bash
   python main.py
   ```

   On some systems, use `python3 main.py`. On Windows, you can also run `run_phishguard.bat`.

You should see the PHISHGUARD banner and menu. At `Choose an option:`, type a number from **1 to 13** and press Enter. Option **8** exits.

---

## 2. Understand the scan result

After a scan, PhishGuard displays:

- **Risk Score (0–100):** the sum of the weights for the indicators that matched, after the configured caps and score limit are applied.
- **Risk Level:** LOW, MEDIUM, HIGH, or CRITICAL, based on the thresholds in `data/risk_config.txt`.
- **Why this score:** the indicators that matched and the weight each contributed.
- **Domain impersonation details:** when a possible look-alike or embedded trusted name is detected, the report may show the candidate part, trusted domain, edit distance, and similarity label.
- **Recommendation:** a suggested response based on the detected signs.
- **Related items:** when relevant, links and other items connected to the scan in the current session's graph.

The supplied default risk bands are LOW **0–20**, MEDIUM **21–40**, HIGH **41–70**, and CRITICAL **71–100**. They can be changed in `data/risk_config.txt`, so your configuration may show different thresholds.

**Interpretation tip:** treat the score as an explanation of which configured rules matched, not as a probability that a link is malicious.

---

## 3. Menu option 1 — Scan a link (URL)

### What it does
Analyzes one URL for suspicious URL structure, domain patterns, trusted-brand look-alikes, suspicious terms/TLDs, local threat-list matches, and other configured indicators.

### How to use it
1. Type `1` at `Choose an option:`.
2. At `Enter link:`, paste one URL and press Enter.
3. Read the score, risk level, matched indicators, and recommendation.

### Practice examples
Use these as text-only classroom examples; PhishGuard will not visit them.

```text
https://paypa1.com/signin
https://example.test/account/verify
https://www.wikipedia.org/
```

`paypa1.com` is intended to demonstrate a look-alike spelling (`1` in place of `l`). A domain's spelling alone does not prove intent, and a benign-looking URL is not guaranteed to be safe.

### What to look at
Focus on the **Why this score** section. Each indicator should name a suspicious characteristic instead of merely saying “bad link.” Use the recommendation as guidance, then independently verify important links through a known official channel.

---

## 4. Menu option 2 — Scan a message (SMS / WhatsApp / social)

### What it does
Analyzes one message for suspicious words and phrases. If the text contains links, PhishGuard also extracts and checks links found in the message (up to five extracted links per message in this implementation).

### How to use it
1. Type `2`.
2. At `Enter message:`, paste or type the message on one line and press Enter.
3. Review the result and the indicators that contributed to it.

### Example

```text
URGENT: Your account will be suspended. Verify your details at https://example.test/verify
```

### Signs to learn to recognize
- Unusual urgency or threats of account closure.
- Requests to verify an account, reveal credentials, or make a payment.
- Unexpected prize, delivery-fee, refund, or security-alert claims.
- A link whose host does not match the organization named in the message.

These are warning signs, not proof by themselves. Real organizations can send legitimate alerts, and a scam message can avoid the keywords the tool watches for.

---

## 5. Menu option 3 — Scan email text

### What it does
Scans a complete email body, including the sender's wording and any links included in the text. This option accepts multiple lines.

### How to use it
1. Type `3`.
2. When prompted, paste the email text. Include the subject or sender line if useful to the analysis.
3. Finish by typing `END` alone on a new line, then press Enter.

Example input:

```text
Subject: Action required
Your mailbox will be disabled unless you verify your account today.
Open this link: https://example.test/mail-check
END
```

Do **not** paste a real private email if it contains confidential information, passwords, personal identifiers, or private links. Use a sanitized sample instead.

---

## 6. Menu option 4 — View scan history

The history menu has its own sub-menu:

```text
1) view  2) sort  3) filter  4) inspect  5) remove  6) clear all  0) back
```

### 4.1 View
Choose `1` to list stored scans with an ID, time, type, score, level, and shortened input.

### 4.2 Sort
Choose `2`, then choose one of the available sort orders:

1. Newest first
2. Oldest first
3. Highest score first
4. Lowest score first
5. Risk level

### 4.3 Filter
Choose `3`, then enter any combination of:

- Minimum risk level: `low`, `medium`, `high`, or `critical`; leave blank for any level.
- Input type: `url`, `message`, or `email`; leave blank for any type.
- Text to search for in the input; leave blank to match any text.

For example, entering `high`, `url`, and `paypal` filters to URL scans at HIGH or above whose saved input contains `paypal`.

### 4.4 Inspect a scan
Choose `4`, then enter the scan ID shown in the history list. The details include the score, level, input (with selected sensitive parts hidden), and indicator IDs.

### 4.5 Remove one scan
Choose `5`, enter its scan ID, and confirm the displayed action. This removes that history record.

### 4.6 Clear history
Choose `6`. Type exactly `yes` when asked to confirm deletion of all history.

Choose `0` or press Enter to return to the main menu.

### Where is history saved?
The default file is `phishguard_history.txt` in the working directory. History is loaded at startup and saved after scans and history changes. Selected sensitive patterns are redacted, but **do not treat redaction as a guarantee of anonymization**. Review files before sharing them.

---

## 7. Menu option 5 — View threat database

### What it shows
Displays the locally stored sample threat entries. The bundled entries are **synthetic examples**, not a verified live threat-intelligence feed.

The submenu offers:

- `a` — add an entry
- `u` — update an entry
- `d` — delete an entry
- `s` — search for a domain
- `c` — list entries by category
- `0` — go back

### Add an entry (`a`)
Enter the domain, category, risk (`low`, `medium`, `high`, or `critical`), and a short note when prompted.

### Update an entry (`u`)
Enter the existing domain as the lookup key, then the replacement entry's domain, category, risk, and note. If the existing domain cannot be found, the program reports that no such domain exists.

### Delete an entry (`d`)
Enter the domain to remove.

### Search (`s`)
Enter a domain. The program checks its local list and reports a match if found. **Not found does not mean safe**; it only means the domain was not present in this local list.

### Category (`c`)
Enter a category to list matching entries.

Changes from add, update, and delete are saved to `data/sample_threats.txt`. Only add entries from sources you have a reason to trust; do not label a domain malicious based on a guess.

---

## 8. Menu option 6 — View trusted websites

This is the local list used for trusted-brand and look-alike comparisons. It is not a universal allow-list and does not establish that a site is safe.

Submenu:

- `a` — add a trusted-domain entry
- `d` — delete a trusted-domain entry
- `0` — go back

### Add (`a`)
Enter the canonical domain, brand name, and category. The prompt gives `mybank.com` and `mybank` as examples.

### Delete (`d`)
Enter the domain to remove.

Changes are saved to `data/trusted_domains.txt`. Only add a domain after checking the official domain through a reliable, independent source. Do not add a suspicious domain simply to make its score lower.

---

## 9. Menu option 7 — View statistics

This view summarizes the stored scan history and the current application's data structures. It displays:

- Total scans in history.
- Count of scans at each risk level.
- Average risk score.
- Most common matched indicators.
- Up to five highest-risk history entries, retrieved using the max-heap.
- Counts for trusted sites, local threat samples, watched keywords, trie nodes, and the current graph's nodes/edges.

The history totals can include previous runs because history is loaded from disk. The **relationship graph is built during the current application session**, so its node/edge counts do not represent a persistent graph database.

If the statistics are empty, perform a few test scans first and open option `7` again.

---

## 10. Menu option 8 — Exit

Type `8` at the main menu. PhishGuard exits with a goodbye message. History is normally saved after each scan or history change; you do not need to choose a separate save command.

---

## 11. Extra tool 9 — Batch scan a file

### What it does
Reads inputs from a text file and processes them in one run. Each non-empty line is treated as one URL or one message; lines starting with `#` are ignored. The results are ranked by risk score, highest first.

### Prepare a file
Create a text file such as `samples.txt` in the project folder:

```text
# PhishGuard practice examples
https://paypa1.com/signin
URGENT: verify your account at https://example.test/check
Your delivery is waiting. Pay a fee now.
https://www.wikipedia.org/
```

### Run it
1. Type `9` at the main menu.
2. At `File with one link or message per line:`, enter the path to the file. For a file in the current directory, enter:

   ```text
   samples.txt
   ```

3. Review the ranked output.

The file must be readable as UTF-8 text. Blank lines and lines beginning with `#` are skipped. The current input detector is deliberately simple: a line with a dot or URL scheme and no spaces is treated as a URL; other lines are treated as messages. Therefore, keep each URL or message on a single line and avoid mixing several messages into one line.

Batch results are added to history. The tool does not open links or send file contents to a remote service.

---

## 12. Extra tool 10 — Explore related indicators

### What it does
Explores relationships in a graph built from scans during the current session. PhishGuard may connect scan records with URLs, domains, and keywords detected in them.

### How to use it
1. First perform one or more scans during this same run.
2. Type `10`.
3. Enter a label to search for, such as a domain, link, keyword, or `Scan #1` (use a scan ID that exists in the current session).
4. Read the two views:
   - **Breadth-first search (BFS):** displays nearest related items first.
   - **Depth-first search (DFS):** displays a deeper traversal of the connected chain.

If the app says that nothing like that has been scanned in this session, scan an example first or enter a label exactly as it appears in the result. Graph relationships are not stored across restarts in this version, even though scan history is persisted.

---

## 13. Extra tool 11 — Keyword prefix search

### What it does
Uses the keyword trie to list watched keywords that begin with the prefix you enter.

### How to use it
1. Type `11`.
2. At `Keyword prefix (e.g. verif):`, enter a starting fragment such as:

   ```text
   verif
   ```

3. PhishGuard lists watched words that start with that prefix and their categories, if available.

This is a **prefix** search, not a general “contains these letters anywhere” search. For example, `verif` can match a word such as `verification`, while `ification` will not match that word because it is not the beginning.

If no words are shown, try a shorter prefix or review the local keyword data in `data/suspicious_keywords.txt`.

---

## 14. Extra tool 12 — Demo scenarios

### What it does
Runs 14 built-in, deterministic examples and shows the scenario description, input, relevant algorithms, matched indicators, score, expected risk band, and recommendation.

### How to use it
Type `12` at the main menu, or run the demos directly without opening the menu:

```bash
python main.py --demo
```

The examples include trusted-looking URLs, suspicious URL patterns, look-alike domains, synthetic prize/bank/delivery messages, an IP-address link, an OTP message, and examples meant to demonstrate possible false positives or false negatives.

The examples use reserved `.test` names or documentation-only IP ranges wherever sample links are needed. Demo results are designed to exercise the rules; they are **not evidence of real-world detection accuracy**.

---

## 15. Extra tool 13 — Benchmarks

### What it does
Runs small performance exercises for the project's data structures and algorithms. These are useful for illustrating how run time changes as input size changes and for discussing algorithmic complexity in a DSA presentation.

### How to use it
Type `13` in the main menu, or launch benchmarks directly:

```bash
python main.py --bench
```

Benchmark timings depend on the computer, Python version, current load, and input sizes. Use them as demonstrations, not as universal comparisons or proof that a custom implementation is faster than Python's built-in data structures.

---

## 16. Other ways to run a scan from the terminal

You can run a single scan without opening the interactive menu:

```bash
python main.py --url "https://paypa1.com/signin"
python main.py --message "Urgent: verify your account at https://example.test/check"
```

These one-shot scans print a result and record the scan in the configured history file.

You can also specify another history file:

```bash
python main.py --history my_practice_history.txt
```

Or specify a data folder if running from a different working directory:

```bash
python main.py --data ./data
```

The `data/` directory must contain `risk_config.txt` and the other expected data files. The default configuration is auto-detected when you launch from the project folder.

---

## 17. Suggested first-time walkthrough

For a short class demonstration, use this order:

1. **Option 1:** Scan `https://paypa1.com/signin` to demonstrate a possible look-alike domain.
2. **Option 2:** Scan a sample urgent message containing `https://example.test/verify`.
3. **Option 3:** Paste a short multi-line sample email and finish with `END` on its own line.
4. **Option 4:** Open history and inspect one scan ID.
5. **Option 5:** Search for a domain in the local sample threat database.
6. **Option 6:** View the trusted-domain list and explain how it supports brand-look-alike checks.
7. **Option 7:** Show the score distribution and the most common indicators.
8. **Option 9:** Batch scan a prepared text file.
9. **Option 10:** Explore relationships after several scans in the same session.
10. **Option 11:** Search the trie using the prefix `verif`.
11. **Option 12:** Run the deterministic demo scenarios.
12. **Option 13:** Show how the DSA implementations are benchmarked.
13. **Option 8:** Exit.

You do not have to demo every option. For a short presentation, options **1, 2, 4, 7, 10, 11, and 12** show the user-facing analysis as well as the project's DSA concepts.

---

## 18. Troubleshooting

### “Could not find data/ (risk_config.txt)”
Run the application from the extracted project folder that contains both `main.py` and `data/`, or specify the correct folder using `--data`.

### The result is LOW, but I'm sure the message is suspicious
The analyzer only uses its configured local rules, keywords, trusted domains, and sample threat list. A low score means few configured indicators matched; it does not mean the content is safe. Check the link through an independently verified official source.

### A legitimate message gets a high score
Urgent language, unusual URLs, or words like “verify” can appear in genuine messages too. This is a heuristic tool and can produce false positives. Inspect the reasons shown and do not treat the score as a verdict.

### A website is missing from the threat database
The local list is not a live or comprehensive threat feed. “Not in the local list” is not a safety verdict.

### Option 10 cannot find a label
The relationship graph covers scans in the current running session only. Perform a scan before exploring, and use a domain, link, keyword, or current-session label such as `Scan #1`.

### Option 9 cannot open my file
Use a valid path, check spelling, and ensure the file is saved as UTF-8 text. Each item should occupy one line.

### I want to run the tests
From the project folder, run:

```bash
python -m unittest discover -s tests -v
```

---

## 19. Final reminders

- PhishGuard analyzes provided text; it does not visit websites or confirm real-time reputation.
- Treat outputs as warning indicators to investigate, not as a final verdict.
- Do not paste passwords, OTPs, banking details, private tokens, or confidential messages into sample inputs.
- Review and sanitize `phishguard_history.txt` before sharing it. Redaction is helpful but not a guarantee that every identifying detail is removed.
- Keep the `data/` folder with the Python source files.

**Stay alert, verify links independently, and never use a risk score as the only basis for trusting a website.**
