"""Build corpus_index.csv: workflow_blob_url ↔ local YAML path for all 100 workflows."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

BASE = Path(__file__).resolve().parent
OUT = BASE / "corpus_index.csv"

ENVOY = (
    "https://github.com/envoyproxy/envoy-openssl/blob/"
    "bfe0463d44a2e58911345edcf5fa52d3c97d3a65/.github/workflows/envoy-prechecks.yml"
)


def main() -> None:
    labels = pd.read_csv(BASE / "workflow_security_labels.csv")
    map1 = pd.read_csv(BASE / "workflow_file_label_map.csv")
    sel2 = pd.read_csv(BASE / "batch2_selection.csv")

    rows = []
    seen = set()

    # Pilot workflows
    for _, r in map1.iterrows():
        url = r.get("workflow_blob_url")
        local = r.get("local_file")
        if pd.isna(local):
            continue
        path = BASE / "workflows" / str(local)
        if not path.exists():
            continue
        if pd.isna(url) or str(url).strip() in ("", "nan"):
            # envoy-prechecks unmatched
            if str(local) == "envoy-prechecks.yml":
                url = ENVOY
            else:
                continue
        url = str(url)
        if url in seen:
            continue
        seen.add(url)
        rows.append(
            {
                "workflow_blob_url": url,
                "local_path": str(path.relative_to(BASE)).replace("\\", "/"),
                "batch": "pilot",
                "purpose": "",
            }
        )

    # Batch2
    for _, r in sel2.iterrows():
        url = str(r["workflow_blob_url"])
        local = r.get("local_file")
        if pd.isna(local):
            continue
        path = BASE / "workflows_batch2" / str(local)
        if not path.exists():
            print(f"[WARN] missing {path}")
            continue
        if url in seen:
            continue
        seen.add(url)
        rows.append(
            {
                "workflow_blob_url": url,
                "local_path": str(path.relative_to(BASE)).replace("\\", "/"),
                "batch": "batch2",
                "purpose": "" if pd.isna(r.get("workflow_purpose")) else str(r["workflow_purpose"]),
            }
        )

    out = pd.DataFrame(rows)
    out.to_csv(OUT, index=False)

    gold_urls = set(labels["workflow_blob_url"].dropna().astype(str)) | {ENVOY}
    missing = gold_urls - seen
    print(f"Wrote {OUT}: {len(out)} workflows")
    print(f"Gold-related URLs covered: {len(seen & gold_urls)} / {len(gold_urls)}")
    if missing:
        print(f"[WARN] {len(missing)} gold URLs not in corpus:")
        for u in sorted(missing)[:10]:
            print(" ", u)


if __name__ == "__main__":
    main()
