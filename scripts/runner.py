"""Scan corpus workflows with all detectors → detector_predictions.csv."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from detectors.parse import load_context
from detectors.registry import detect_all

BASE = Path(__file__).resolve().parent
INDEX = BASE / "corpus_index.csv"
OUT = BASE / "detector_predictions.csv"


def main() -> None:
    index = pd.read_csv(INDEX)
    rows = []
    errors = []

    for _, r in index.iterrows():
        url = str(r["workflow_blob_url"])
        local = BASE / str(r["local_path"])
        purpose = "" if pd.isna(r.get("purpose")) else str(r["purpose"])
        if not local.exists():
            errors.append(f"missing {local}")
            continue
        text = local.read_text(encoding="utf-8", errors="replace")
        ctx = load_context(url, text, purpose=purpose)
        try:
            labels = detect_all(ctx)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{local.name}: {exc}")
            continue
        for lab in labels:
            rows.append(lab.to_row())

    out = pd.DataFrame(
        rows,
        columns=[
            "workflow_blob_url",
            "line_number",
            "weakness_type",
            "evidence",
            "explanation",
        ],
    )
    out.to_csv(OUT, index=False)
    print(f"Scanned {len(index)} workflows -> {len(out)} predicted labels -> {OUT}")
    if errors:
        print(f"[WARN] {len(errors)} errors:")
        for e in errors[:15]:
            print(" ", e)


if __name__ == "__main__":
    main()
