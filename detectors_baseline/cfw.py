"""CFW — Control Flow Weakness."""

from __future__ import annotations

import re

from detectors.models import CFW, Label, WorkflowContext

# if: > (folded, keep newline) followed by ${{ ... }} — dangerous truthiness
IF_FOLDED = re.compile(r"^(\s*)if:\s*>\s*$")
IF_INLINE_FOLDED = re.compile(r"^(\s*)if:\s*>\s*\$\{\{")
ALWAYS_TRUE = re.compile(
    r"if:\s*['\"]?(?:true|\$\{\{\s*true\s*\}\}|\$\{\{\s*!\s*false\s*\}\})['\"]?\s*$",
    re.I,
)


def detect(ctx: WorkflowContext) -> list[Label]:
    labels: list[Label] = []
    lines = ctx.lines

    for i, line in enumerate(lines):
        line_no = i + 1
        if IF_INLINE_FOLDED.match(line):
            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=line_no,
                    weakness_type=CFW,
                    evidence=line.strip()[:120],
                    explanation=(
                        "if: > with ${{ }} appends a trailing newline, making string "
                        "'false\\n' truthy and bypassing intended conditions."
                    ),
                )
            )
            continue

        if IF_FOLDED.match(line):
            # Look at following non-empty lines for ${{
            chunk = []
            for j in range(i + 1, min(len(lines), i + 6)):
                if lines[j].strip() == "":
                    continue
                chunk.append(lines[j])
                break
            joined = "\n".join(chunk)
            if "${{" in joined and ">-" not in line:
                labels.append(
                    Label(
                        workflow_blob_url=ctx.url,
                        line_number=line_no,
                        weakness_type=CFW,
                        evidence=(line.strip() + " " + joined.strip())[:120],
                        explanation=(
                            "if: > (non-strip) with ${{ }} appends a trailing newline, "
                            "making a false string truthy and bypassing safeguards."
                        ),
                    )
                )
            continue

        if ALWAYS_TRUE.search(line):
            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=line_no,
                    weakness_type=CFW,
                    evidence=line.strip()[:120],
                    explanation=(
                        "Condition is always true, defeating intended control-flow safeguards."
                    ),
                )
            )

    return labels
