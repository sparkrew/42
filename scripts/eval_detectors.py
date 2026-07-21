"""Evaluate detector predictions against workflow_security_labels.csv."""

from __future__ import annotations

from pathlib import Path

import pandas as pd

from detectors.models import ALL_TYPES

BASE = Path(__file__).resolve().parent
GOLD = BASE / "workflow_security_labels.csv"
PRED = BASE / "detector_predictions.csv"
REPORT = BASE / "eval_report.csv"


def _type_sets(df: pd.DataFrame) -> dict[str, set[str]]:
    """Map weakness_type → set of workflow URLs that have that type."""
    out: dict[str, set[str]] = {t: set() for t in ALL_TYPES}
    for _, r in df.iterrows():
        t = str(r["weakness_type"])
        url = str(r["workflow_blob_url"])
        if t in out:
            out[t].add(url)
    return out


def _line_keys(df: pd.DataFrame) -> dict[str, set[tuple[str, int]]]:
    out: dict[str, set[tuple[str, int]]] = {t: set() for t in ALL_TYPES}
    for _, r in df.iterrows():
        t = str(r["weakness_type"])
        if t not in out:
            continue
        try:
            ln = int(r["line_number"])
        except (TypeError, ValueError):
            ln = -1
        out[t].add((str(r["workflow_blob_url"]), ln))
    return out


def _prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    p = tp / (tp + fp) if (tp + fp) else 0.0
    r = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * p * r / (p + r) if (p + r) else 0.0
    return p, r, f1


def _read_csv(path: Path) -> pd.DataFrame:
    for encoding in ("utf-8", "utf-8-sig", "cp1252", "latin-1"):
        try:
            return pd.read_csv(path, encoding=encoding)
        except UnicodeDecodeError:
            continue
    return pd.read_csv(path, encoding="utf-8", encoding_errors="replace")


def main() -> None:
    gold = _read_csv(GOLD)
    pred = _read_csv(PRED)

    g_types = _type_sets(gold)
    p_types = _type_sets(pred)
    g_lines = _line_keys(gold)
    p_lines = _line_keys(pred)

    report_rows = []
    print("=== Primary: (workflow_blob_url, weakness_type) ===")
    print(f"{'type':<45} {'P':>6} {'R':>6} {'F1':>6} {'TP':>4} {'FP':>4} {'FN':>4}")

    micro_tp = micro_fp = micro_fn = 0
    # Macro averages only types with gold support (exclude empty classes like CFW).
    f1s_supported: list[float] = []
    skipped_no_support: list[str] = []

    for t in ALL_TYPES:
        g = g_types[t]
        p = p_types[t]
        tp_urls = g & p
        fp_urls = p - g
        fn_urls = g - p
        tp, fp, fn = len(tp_urls), len(fp_urls), len(fn_urls)
        prec, rec, f1 = _prf(tp, fp, fn)
        short = t.split("(")[-1].rstrip(")") if "(" in t else t
        print(f"{short:<45} {prec:6.3f} {rec:6.3f} {f1:6.3f} {tp:4d} {fp:4d} {fn:4d}")
        micro_tp += tp
        micro_fp += fp
        micro_fn += fn
        if len(g) > 0:
            f1s_supported.append(f1)
        else:
            skipped_no_support.append(short)

        for url in sorted(fp_urls)[:5]:
            evidence = pred[(pred.workflow_blob_url == url) & (pred.weakness_type == t)]
            ev = evidence.iloc[0]["evidence"] if len(evidence) else ""
            report_rows.append(
                {
                    "match_level": "url_type",
                    "kind": "FP",
                    "weakness_type": t,
                    "workflow_blob_url": url,
                    "line_number": "",
                    "evidence": str(ev)[:200],
                }
            )
        for url in sorted(fn_urls)[:5]:
            evidence = gold[(gold.workflow_blob_url == url) & (gold.weakness_type == t)]
            ev = evidence.iloc[0]["evidence"] if len(evidence) else ""
            ln = evidence.iloc[0]["line_number"] if len(evidence) else ""
            report_rows.append(
                {
                    "match_level": "url_type",
                    "kind": "FN",
                    "weakness_type": t,
                    "workflow_blob_url": url,
                    "line_number": ln,
                    "evidence": str(ev)[:200],
                }
            )

    mp, mr, mf = _prf(micro_tp, micro_fp, micro_fn)
    macro_f1 = sum(f1s_supported) / len(f1s_supported) if f1s_supported else 0.0
    print(f"{'MICRO':<45} {mp:6.3f} {mr:6.3f} {mf:6.3f} {micro_tp:4d} {micro_fp:4d} {micro_fn:4d}")
    print(
        f"{'MACRO-F1':<45} {'':>6} {'':>6} {macro_f1:6.3f}"
        f"  (avg over {len(f1s_supported)} types with gold support)"
    )
    if skipped_no_support:
        print(f"  excluded from MACRO (no gold labels): {', '.join(skipped_no_support)}")

    print("\n=== Secondary: (url, type, line_number) ===")
    print(f"{'type':<45} {'P':>6} {'R':>6} {'F1':>6} {'TP':>4} {'FP':>4} {'FN':>4}")
    f1s_line: list[float] = []
    for t in ALL_TYPES:
        g = g_lines[t]
        p = p_lines[t]
        tp = len(g & p)
        fp = len(p - g)
        fn = len(g - p)
        prec, rec, f1 = _prf(tp, fp, fn)
        short = t.split("(")[-1].rstrip(")") if "(" in t else t
        print(f"{short:<45} {prec:6.3f} {rec:6.3f} {f1:6.3f} {tp:4d} {fp:4d} {fn:4d}")
        if len(g) > 0:
            f1s_line.append(f1)
    macro_line = sum(f1s_line) / len(f1s_line) if f1s_line else 0.0
    print(
        f"{'MACRO-F1':<45} {'':>6} {'':>6} {macro_line:6.3f}"
        f"  (avg over {len(f1s_line)} types with gold support)"
    )
    pd.DataFrame(report_rows).to_csv(REPORT, index=False)
    print(f"\nWrote sample FP/FN examples -> {REPORT}")


if __name__ == "__main__":
    main()
