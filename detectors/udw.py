"""UDW — Unpinned Dependency Weakness."""

from __future__ import annotations

from detectors.models import UDW, Label, WorkflowContext
from detectors.parse import extract_uses_with_lines, is_local_ref, is_sha, split_ref


def detect(ctx: WorkflowContext) -> list[Label]:
    labels: list[Label] = []
    for line_no, uses_val in extract_uses_with_lines(ctx.text):
        path, ver = split_ref(uses_val)
        if is_local_ref(path):
            continue
        if is_sha(ver):
            continue
        labels.append(
            Label(
                workflow_blob_url=ctx.url,
                line_number=line_no,
                weakness_type=UDW,
                evidence=f"uses: {uses_val}",
                explanation=(
                    f"Action/workflow referenced by mutable version '{ver or 'missing'}' "
                    "instead of a pinned commit SHA, exposing the workflow to tag substitution attacks."
                ),
            )
        )
    return labels
