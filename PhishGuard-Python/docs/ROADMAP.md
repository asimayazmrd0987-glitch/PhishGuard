# Roadmap

## Completed in this educational Python port

- Local URL parsing and extracted-link scanning.
- Domain heuristics and possible trusted-brand impersonation checks.
- Phrase and whole-word message analysis.
- Explainable risk indicators and configurable weights/caps/thresholds.
- Custom DSA implementations, history redaction, scan graph, interactive UI, batch mode, demos, benchmarks and unit tests.

## Recommended before real-world deployment

- Build and test against a carefully labelled corpus, and report false positives, false negatives, precision and recall.
- Review trusted/threat list sources and provide update provenance and timestamps.
- Use a maintained public-suffix source, with clear versioning.
- Improve Unicode/IDN confusable handling and add more languages.
- Add schema validation for config keys and safe atomic file updates.
- Have security practitioners review threat heuristics, data handling and user-facing language.
- Consider packaging, accessibility and a UI only after the detection policy has been evaluated.

Do not describe this prototype as a production security scanner or its score as a probability.
