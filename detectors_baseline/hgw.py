"""HGW — Hardening Gap Weakness."""

from __future__ import annotations

import re

from detectors.models import HGW, Label, WorkflowContext
from detectors.parse import (
    BUILD_TEST_HINTS,
    effectively_reusable_orchestrator,
    job_is_reusable_only,
    looks_like_ci,
    solely_reusable_orchestrator,
    text_has_security_scan,
    walk_jobs,
)


def _is_delegated_deploy_orchestrator(ctx: WorkflowContext) -> bool:
    """PR/environment deploy workflows that do not build or test sources locally.

    The callable reusable workflows may contain scanning, but this file only
    wires deployment. Decision-tree HGW does not apply when content is not
    inspectable here and there is no local CI build/test surface.
    """
    m = re.search(r"^name:\s*['\"]?(.+?)['\"]?\s*$", ctx.text, re.M)
    wf_name = (m.group(1) if m else "").lower()
    # Match deploy/deployment/preview env workflows (not bare "test" jobs).
    if not re.search(r"\b(deploy|preview|environment)", wf_name):
        return False
    if re.search(r"\b(build|test|publish|package|lint|compile|unittest|pytest)\b", wf_name):
        return False
    if re.search(r"actions/checkout@", ctx.text):
        return False

    # Local build/test commands (ignore strings only inside reusable `with:`)
    for _, job in walk_jobs(ctx.data):
        if job_is_reusable_only(job):
            continue
        for step in job.get("steps") or []:
            if not isinstance(step, dict) or not step.get("run"):
                continue
            run = str(step["run"])
            if any(re.search(p, run, re.I) for p in BUILD_TEST_HINTS):
                return False

    jobs = walk_jobs(ctx.data)
    if not jobs:
        return False
    reusable = sum(1 for _, job in jobs if job_is_reusable_only(job))
    # Allow a single local setup job; the rest must be reusable calls.
    return reusable >= 1 and reusable >= len(jobs) - 1


def detect(ctx: WorkflowContext) -> list[Label]:
    if solely_reusable_orchestrator(ctx.data):
        return []
    if effectively_reusable_orchestrator(ctx.data):
        return []
    if _is_delegated_deploy_orchestrator(ctx):
        return []
    if not looks_like_ci(ctx.text, ctx.purpose, ctx.data):
        return []
    if text_has_security_scan(ctx.text):
        return []

    return [
        Label(
            workflow_blob_url=ctx.url,
            line_number=1,
            weakness_type=HGW,
            evidence="CI build/test/deploy without security scanning",
            explanation=(
                "CI/CD pipeline builds or tests code without integrated security scanning "
                "(SAST, dependency audit, or secret scan), leaving a hardening gap."
            ),
        )
    ]
