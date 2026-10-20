# Suggested project presentation

1. **Title / problem:** everyday phishing links and scam messages.
2. **Goal:** local analysis with explanations, not a final verdict.
3. **Architecture:** input → parser/analyzer → indicators → risk engine → history/graph.
4. **URL parsing:** scheme, host, user-info, port, path/query/fragment.
5. **Data structures:** chained hash table, trie, custom set, max-heap and graph.
6. **Algorithms:** KMP, Rabin–Karp, Levenshtein DP, merge sort and BFS/DFS.
7. **Risk policy:** de-duplication, keyword cap, 0–100 score bands.
8. **Demonstration:** `paypa1.com`, synthetic `.test` threat example, and a normal trusted URL.
9. **Privacy:** history redaction and no network access.
10. **Limitations:** rule-based false positives/negatives, limited lists and non-probabilistic score.
11. **Testing:** run the unittest suite and all 14 demos.
12. **Conclusion / future work:** labelled-data evaluation, better Unicode handling and reviewed reference lists.

Useful live commands:

```bash
python main.py --url "https://paypa1.com/signin"
python main.py --message "Your account will be suspended within 24 hours. Verify now"
python main.py --demo
python -m unittest discover -s tests -v
```
