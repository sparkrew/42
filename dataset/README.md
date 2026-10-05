# Workflow security labels

Evidence-linked multi-label annotations of security weaknesses in public GitHub Actions workflows.

## Files

| File | Format |
|------|--------|
| `workflow_security_labels.json` | Grouped by workflow (primary) |
| `workflow_security_labels.jsonl` | One finding (or clean row) per line |
| `workflow_security_labels.csv` | Flat table |

**Size:** 474 workflows (467 with findings, 7 clean), 2 424 findings.

Each finding has `workflow_blob_url`, `line_number`, `weakness_type` / `weakness_code`, `evidence`, and `explanation`. Clean workflows have `is_clean: true` and no findings.

## How the data were produced

1. **Corpus.** Public GHA workflows from Boost’s industrial corpus (~1.05M files).
2. **Sample.** Stratified sample of 500 workflows on structural complexity, trigger risk, action-dependency profile, and security surface.
3. **Reference labels.** 100 workflows (33 simple / 33 medium / 34 complex) were labeled manually with cross-review and adjudication.
4. **Helper labeling.** Deterministic [detectors](../detectors/) encoding the same criteria were run on the remaining workflows. Every detector output was manually reviewed; false positives were removed. Workflows where all outputs were rejected are kept as the 7 clean cases.
