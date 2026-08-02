"""AIW — Artifact Integrity Weakness."""

from __future__ import annotations

import re

from detectors.models import AIW, Label, WorkflowContext
from detectors.parse import extract_triggers, extract_uses_with_lines, split_ref

DOWNLOAD_ARTIFACT = re.compile(r"actions/download-artifact", re.I)
CURL_WGET = re.compile(
    r"(?:curl|wget)\s+[^\n]*(?:https?://|\.sh|\.bin|\.exe|\.tar|\.zip|\.deb|\.rpm)",
    re.I,
)
CHECKSUM = re.compile(r"sha256sum|shasum|openssl\s+dgst|checksum|gpg\s+--verify|cosign\s+verify", re.I)
CACHE_ACTION = re.compile(r"actions/cache(?:/restore)?", re.I)
PR_TRIGGERS = {"pull_request", "pull_request_target"}


def detect(ctx: WorkflowContext) -> list[Label]:
    labels: list[Label] = []
    text = ctx.text
    triggers = set(extract_triggers(ctx.data))

    for line_no, uses_val in extract_uses_with_lines(text):
        path, _ = split_ref(uses_val)
        if DOWNLOAD_ARTIFACT.search(path):
            # Rough: look for checksum nearby in whole file
            if not CHECKSUM.search(text):
                labels.append(
                    Label(
                        workflow_blob_url=ctx.url,
                        line_number=line_no,
                        weakness_type=AIW,
                        evidence=f"uses: {uses_val}",
                        explanation=(
                            "Downloads artifacts without subsequent checksum/signature "
                            "verification, enabling supply-chain tampering."
                        ),
                    )
                )
        if CACHE_ACTION.search(path) and (triggers & PR_TRIGGERS):
            if not CHECKSUM.search(text):
                labels.append(
                    Label(
                        workflow_blob_url=ctx.url,
                        line_number=line_no,
                        weakness_type=AIW,
                        evidence=f"uses: {uses_val}",
                        explanation=(
                            "Restores cache on a pull_request-triggered workflow without "
                            "integrity checks, enabling cache poisoning."
                        ),
                    )
                )

    for i, line in enumerate(ctx.lines, 1):
        if CURL_WGET.search(line) and not CHECKSUM.search(line):
            # Skip pure API/json fetches that look non-binary if obvious
            if re.search(r"\.(json|yml|yaml|txt|md)(\s|$|[\"'])", line, re.I):
                continue
            window = "\n".join(ctx.lines[i - 1 : min(len(ctx.lines), i + 8)])
            if CHECKSUM.search(window):
                continue
            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=i,
                    weakness_type=AIW,
                    evidence=line.strip()[:120],
                    explanation=(
                        "Downloads a remote binary/script via curl/wget without verifying "
                        "checksum or signature."
                    ),
                )
            )

    # Dedupe by line+type
    seen = set()
    out = []
    for lab in labels:
        key = (lab.line_number, lab.evidence[:80])
        if key in seen:
            continue
        seen.add(key)
        out.append(lab)
    return out
