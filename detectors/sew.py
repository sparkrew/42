"""SEW — Secrets Exposure Weakness."""

from __future__ import annotations

import re

from detectors.models import SEW, Label, WorkflowContext
from detectors.parse import extract_triggers, is_local_ref, split_ref

INHERIT_RE = re.compile(r"""secrets\s*:\s*['\"]?inherit['\"]?\s*(?:#.*)?$""", re.I)
USES_RE = re.compile(r"""uses:\s*['\"]?([^'\"\s#]+)""")
NAMED_SECRET_RE = re.compile(r"\bsecrets\.\w+")
ID_TOKEN_WRITE_RE = re.compile(r"id-token\s*:\s*write", re.I)


def _associated_uses(lines: list[str], inherit_line: int) -> str | None:
    """Find the ``uses:`` for a ``secrets: inherit`` line.

    GitHub Actions allows either order under a job (``uses`` then ``secrets``,
    or ``secrets`` then ``uses``). Prefer a nearby following ``uses:``; otherwise
    fall back to the nearest preceding one.
    """
    # Same-job style: secrets: inherit then uses: on a following line
    forward = "\n".join(lines[inherit_line - 1 : min(len(lines), inherit_line + 10)])
    fwd_matches = list(USES_RE.finditer(forward))
    if fwd_matches:
        return fwd_matches[0].group(1).strip()

    window = "\n".join(lines[max(0, inherit_line - 40) : inherit_line])
    matches = list(USES_RE.finditer(window))
    if not matches:
        return None
    return matches[-1].group(1).strip()


def _local_inherit_is_exposure(ctx: WorkflowContext) -> bool:
    """Local reusable-workflow inherit is labeled SEW when secrets are in play.

    Gold treats local ``secrets: inherit`` as SEW when the workflow also
    references named secrets or uses OIDC write outside ``pull_request_target``
    (where inherit is often deployment wiring). Pure local orchestrators with
    neither signal are left unlabeled.
    """
    if NAMED_SECRET_RE.search(ctx.text):
        return True
    if not ID_TOKEN_WRITE_RE.search(ctx.text):
        return False
    triggers = set(extract_triggers(ctx.data))
    return "pull_request_target" not in triggers


def detect(ctx: WorkflowContext) -> list[Label]:
    labels: list[Label] = []
    lines = ctx.lines
    local_ok = _local_inherit_is_exposure(ctx)

    for i, line in enumerate(lines, 1):
        if not INHERIT_RE.search(line.strip()):
            continue
        target = _associated_uses(lines, i)
        if not target:
            continue
        path, _ = split_ref(target)
        local = is_local_ref(path)
        if local and not local_ok:
            continue

        kind = "local" if local else "external"
        labels.append(
            Label(
                workflow_blob_url=ctx.url,
                line_number=i,
                weakness_type=SEW,
                evidence="secrets: inherit",
                explanation=(
                    f"secrets: inherit forwards all repository secrets to the {kind} "
                    f"reusable workflow ({target}), exposing every secret."
                ),
            )
        )

    for i, line in enumerate(lines, 1):
        if not re.search(r"secrets\.\w+", line):
            continue
        if re.search(
            r"GITHUB_ENV|GITHUB_OUTPUT|echo\s+[\"'].*\$\{\{\s*secrets",
            line,
        ):
            labels.append(
                Label(
                    workflow_blob_url=ctx.url,
                    line_number=i,
                    weakness_type=SEW,
                    evidence=line.strip()[:120],
                    explanation=(
                        "Secret value written to environment files or logged, "
                        "risking credential leakage."
                    ),
                )
            )
    return labels
