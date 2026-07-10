"""
Scan standalone GitHub Actions for vulnerabilities.

Reads actions_used.csv, filters to non-official standalone actions (excluding
actions/*, github/*, and reusable workflows), fetches source code at each
used ref (from tag_versions and sha_versions) via the GitHub API, scans for
dangerous patterns, checks for known CVEs, and outputs vulnerable_actions.csv.

For composite actions, also discovers nested `uses:` references and recursively
scans those transitive actions (unlimited depth, cycle detection). Official
owners are recorded as deps but not scanned.
"""

import base64
import csv
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

import yaml

sys.stdout.reconfigure(encoding="utf-8")

BASE_DIR = Path(__file__).parent
ACTIONS_CSV = BASE_DIR / "actions_used.csv"
OUTPUT_CSV = BASE_DIR / "vulnerable_actions.csv"
CACHE_DIR = BASE_DIR / "action_cache"
CACHE_DIR.mkdir(exist_ok=True)

OFFICIAL_OWNERS = {"actions", "github"}

# ---------------------------------------------------------------------------
# Dangerous-pattern definitions
# ---------------------------------------------------------------------------

# Category A: Input injection sinks
JS_INJECTION_PATTERNS = [
    (r'exec(?:Sync)?\s*\([^)]*getInput', "exec/execSync with getInput"),
    (r'eval\s*\([^)]*getInput', "eval with getInput"),
    (r'Function\s*\([^)]*getInput', "Function constructor with getInput"),
    (r'exec(?:Sync)?\s*\([^)]*context\.payload', "exec/execSync with context.payload"),
    (r'exec(?:Sync)?\s*\([^)]*github\.event', "exec/execSync with github.event"),
    (r'exec(?:Sync)?\s*\(\s*[`"\'].*\$\{.*getInput', "exec with template literal input"),
    (r'child_process.*exec.*getInput', "child_process exec with getInput"),
    (r'execCommand.*getInput', "execCommand with getInput"),
]

COMPOSITE_INJECTION_PATTERNS = [
    (r'^\s*run:\s*[|>]?\s*.*\$\{\{\s*inputs\.', "run block with ${{ inputs.* }} interpolation"),
    (r'^\s*run:\s*[|>]?\s*.*\$\{\{\s*github\.event\.', "run block with ${{ github.event.* }} interpolation"),
    (r'^\s*run:\s*[|>]?\s*.*\$\{\{\s*github\.head_ref', "run block with ${{ github.head_ref }} interpolation"),
]

DOCKER_INJECTION_PATTERNS = [
    (r'(?:eval|exec)\s+.*\$(?:INPUT_|GITHUB_)', "eval/exec with unquoted INPUT_/GITHUB_ vars"),
    (r'\$INPUT_\w+\s', "unquoted $INPUT_ variable in shell"),
    (r'echo\s+\$INPUT_', "echo of unquoted INPUT_ variable"),
]

# Category B: Suspicious network activity
NETWORK_PATTERNS = [
    (r'(?:fetch|axios\.(?:get|post)|http\.request|https\.request)\s*\(.*(?:process\.env|secret|password|credential)', "network request with sensitive data"),
    (r'curl\s+.*(?:\$\{?(?:INPUT_|GITHUB_|SECRET)|secret|password)', "curl with sensitive data"),
    (r'wget\s+.*(?:\$\{?(?:INPUT_|GITHUB_|SECRET)|secret|password)', "wget with sensitive data"),
]

# Category C: Insecure downloads
INSECURE_DOWNLOAD_PATTERNS = [
    (r'(?:curl|wget)\s+["\']?http://', "download over plain HTTP"),
    (r'(?:curl|wget)\s+[^|]*\|\s*(?:bash|sh|sudo)', "pipe download to shell"),
    (r'(?:curl|wget)\s+[^;]*;\s*(?:bash|sh|sudo)', "download then execute"),
    (r'(?:curl|wget)\s+.*\.(?:sh|py|rb|pl)\b.*[|;]\s*(?:bash|sh|python|ruby|perl)', "download script and execute"),
]

# Category D: Unsafe credential handling
UNSAFE_CRED_PATTERNS = [
    (r'console\.log\s*\(.*getInput\s*\(', "console.log of action input"),
    (r'core\.info\s*\(.*getInput\s*\(', "core.info logging action input"),
    (r'echo\s+.*\$\{\{\s*secrets\..*>>\s*\$GITHUB_(?:OUTPUT|ENV)', "writing secrets to GITHUB_OUTPUT/ENV"),
    (r'echo\s+.*\$\{\{\s*inputs\..*>>\s*\$GITHUB_(?:OUTPUT|ENV)', "writing inputs to GITHUB_OUTPUT/ENV"),
    (r'::set-output\s+name=.*\$\{\{.*secret', "set-output with secret"),
]


SCAN_PROFILES = {
    "javascript": {
        "patterns": JS_INJECTION_PATTERNS + NETWORK_PATTERNS + UNSAFE_CRED_PATTERNS,
        "categories": {
            **{p[1]: "input_injection" for p in JS_INJECTION_PATTERNS},
            **{p[1]: "network_exfil" for p in NETWORK_PATTERNS},
            **{p[1]: "unsafe_cred_handling" for p in UNSAFE_CRED_PATTERNS},
        },
    },
    "composite": {
        "patterns": COMPOSITE_INJECTION_PATTERNS + INSECURE_DOWNLOAD_PATTERNS + UNSAFE_CRED_PATTERNS,
        "categories": {
            **{p[1]: "input_injection" for p in COMPOSITE_INJECTION_PATTERNS},
            **{p[1]: "insecure_download" for p in INSECURE_DOWNLOAD_PATTERNS},
            **{p[1]: "unsafe_cred_handling" for p in UNSAFE_CRED_PATTERNS},
        },
    },
    "docker": {
        "patterns": DOCKER_INJECTION_PATTERNS + INSECURE_DOWNLOAD_PATTERNS + NETWORK_PATTERNS + UNSAFE_CRED_PATTERNS,
        "categories": {
            **{p[1]: "input_injection" for p in DOCKER_INJECTION_PATTERNS},
            **{p[1]: "insecure_download" for p in INSECURE_DOWNLOAD_PATTERNS},
            **{p[1]: "network_exfil" for p in NETWORK_PATTERNS},
            **{p[1]: "unsafe_cred_handling" for p in UNSAFE_CRED_PATTERNS},
        },
    },
}

SEVERITY_MAP = {
    "input_injection": "high",
    "known_cve": "high",
    "network_exfil": "medium",
    "insecure_download": "medium",
    "unsafe_cred_handling": "low",
    "deprecated_runtime": "low",
}

# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def gh_api(endpoint: str, accept: str = "") -> dict | list | None:
    """Call gh api and return parsed JSON, or None on error."""
    cmd = ["gh", "api", endpoint]
    if accept:
        cmd += ["-H", f"Accept: {accept}"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            return None
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return None


def fetch_file_raw(owner: str, repo: str, path: str, ref: str = "") -> str | None:
    """Fetch a file via raw.githubusercontent.com (no size limit)."""
    import urllib.request
    import urllib.error

    refs_to_try = [ref] if ref else ["HEAD", "main", "master"]
    for branch in refs_to_try:
        url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read(2_000_000)  # cap at 2MB
                return data.decode("utf-8", errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
            continue
    return None


def ref_cache_key(ref: str) -> str:
    """Sanitize ref for use in cache filenames (refs may contain slashes)."""
    if not ref:
        return "default"
    return ref.replace("/", "__")


def fetch_file(owner: str, repo: str, path: str, ref: str = "") -> str | None:
    """Fetch a file from GitHub at ref, using cache. Returns decoded content or None."""
    ref_key = ref_cache_key(ref)
    safe_name = f"{owner}__{repo}__{ref_key}__{path.replace('/', '__')}"
    cache_path = CACHE_DIR / safe_name
    if cache_path.exists():
        return cache_path.read_text(encoding="utf-8", errors="replace")

    endpoint = f"/repos/{owner}/{repo}/contents/{path}"
    if ref:
        endpoint += f"?ref={ref}"

    data = gh_api(endpoint)
    content = None

    if data is not None and not isinstance(data, list) and data.get("content"):
        try:
            content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            pass

    # Fall back to raw download for large files (API returns empty content for >1MB)
    if not content:
        content = fetch_file_raw(owner, repo, path, ref)

    if content is None:
        return None

    cache_path.write_text(content, encoding="utf-8")
    time.sleep(0.4)
    return content


def fetch_file_try_names(
    owner: str, repo: str, base_path: str, names: list[str], ref: str = ""
) -> tuple[str | None, str]:
    """Try fetching multiple file names under base_path at ref, return (content, name_found)."""
    for name in names:
        path = f"{base_path}/{name}".strip("/") if base_path else name
        content = fetch_file(owner, repo, path, ref)
        if content is not None:
            return content, path
    return None, ""


# ---------------------------------------------------------------------------
# CVE / Advisory lookup
# ---------------------------------------------------------------------------

def check_advisories(owner: str, repo: str) -> list[dict]:
    """Check GitHub Advisory Database for known vulnerabilities."""
    advisories_found = []

    # Repository-level advisories
    data = gh_api(f"/repos/{owner}/{repo}/security-advisories")
    if isinstance(data, list):
        for adv in data:
            advisories_found.append({
                "cve_id": adv.get("cve_id", ""),
                "summary": adv.get("summary", ""),
                "severity": adv.get("severity", ""),
                "state": adv.get("state", ""),
                "html_url": adv.get("html_url", ""),
            })

    # Global advisory search
    data = gh_api(f"/advisories?affects={owner}/{repo}&type=reviewed&per_page=10")
    if isinstance(data, list):
        for adv in data:
            cve_id = adv.get("cve_id", "")
            if cve_id and not any(a["cve_id"] == cve_id for a in advisories_found):
                advisories_found.append({
                    "cve_id": cve_id,
                    "summary": adv.get("summary", ""),
                    "severity": adv.get("severity", ""),
                    "state": adv.get("state", "published"),
                    "html_url": adv.get("html_url", ""),
                })

    time.sleep(0.4)
    return advisories_found


# ---------------------------------------------------------------------------
# Pattern scanning
# ---------------------------------------------------------------------------

def scan_content(content: str, patterns: list[tuple[str, str]], file_path: str) -> list[dict]:
    """Scan content against regex patterns. Returns list of findings."""
    findings = []
    lines = content.split("\n")
    for regex, label in patterns:
        compiled = re.compile(regex, re.IGNORECASE | re.MULTILINE)
        for i, line in enumerate(lines, 1):
            if compiled.search(line):
                snippet = line.strip()[:200]
                findings.append({
                    "pattern_matched": label,
                    "file_path": file_path,
                    "evidence_snippet": snippet,
                    "line_number": i,
                })
    return findings


def scan_composite_multiline(content: str, file_path: str) -> list[dict]:
    """Detect ${{ inputs/github.event }} in multi-line run: blocks of composite actions."""
    findings = []
    run_block_re = re.compile(r'^(\s*)run:\s*[|>]', re.MULTILINE)
    injection_re = re.compile(r'\$\{\{\s*(?:inputs\.|github\.event\.|github\.head_ref)')

    for m in run_block_re.finditer(content):
        indent = len(m.group(1))
        start_pos = m.end()
        block_lines = []
        for line in content[start_pos:].split("\n")[1:]:
            stripped = line.lstrip()
            line_indent = len(line) - len(stripped)
            if stripped and line_indent <= indent:
                break
            block_lines.append(line)

        block_text = "\n".join(block_lines)
        line_num = content[:m.start()].count("\n") + 1

        for i, bline in enumerate(block_lines):
            if injection_re.search(bline):
                findings.append({
                    "pattern_matched": "run block (multiline) with untrusted input interpolation",
                    "file_path": file_path,
                    "evidence_snippet": bline.strip()[:200],
                    "line_number": line_num + 1 + i,
                    "vulnerability_category": "input_injection",
                    "severity": "high",
                })
    return findings


def detect_action_type(action_yml_content: str) -> tuple[str, str]:
    """Parse action.yml and return (action_type, main_file).
    
    action_type: 'javascript', 'docker', 'composite', or 'unknown'
    main_file: the entry-point file for JS actions, Dockerfile path for docker, etc.
    """
    try:
        data = yaml.safe_load(action_yml_content)
    except yaml.YAMLError:
        return "unknown", ""

    if not isinstance(data, dict):
        return "unknown", ""

    runs = data.get("runs", {})
    if not isinstance(runs, dict):
        return "unknown", ""

    using = str(runs.get("using", "")).lower()

    if using.startswith("node"):
        main_file = runs.get("main", "").lstrip("./")
        return "javascript", main_file
    elif using == "docker":
        image = runs.get("image", "")
        return "docker", image
    elif using == "composite":
        return "composite", ""
    else:
        return "unknown", ""


def check_deprecated_runtime(action_yml_content: str) -> str | None:
    """Return the deprecated runtime string if action uses node12 or node16, else None."""
    try:
        data = yaml.safe_load(action_yml_content)
    except yaml.YAMLError:
        return None

    if not isinstance(data, dict):
        return None

    runs = data.get("runs", {})
    if not isinstance(runs, dict):
        return None

    using = str(runs.get("using", "")).lower()
    if using in ("node12", "node16"):
        return using
    return None


# ---------------------------------------------------------------------------
# Version parsing
# ---------------------------------------------------------------------------

def clean_field(val) -> str:
    """Normalize CSV fields that may be NaN/None."""
    if val is None:
        return ""
    if isinstance(val, float) and val != val:  # NaN
        return ""
    return str(val).strip()


def parse_used_refs(row: dict) -> list[str]:
    """Return unique refs (tags/branches/SHAs) used by workflows for this action."""
    refs: list[str] = []
    seen: set[str] = set()

    for column in ("tag_versions", "sha_versions"):
        raw = row.get(column, "")
        if raw is None or (isinstance(raw, float) and str(raw) == "nan"):
            continue
        for part in str(raw).split(";"):
            ref = part.strip()
            if ref and ref not in seen:
                seen.add(ref)
                refs.append(ref)

    return refs


def parse_action_path(action_path: str) -> tuple[str, str, str]:
    """Split owner/repo[/sub_path] into (owner, repo, sub_path)."""
    parts = action_path.split("/")
    if len(parts) >= 2:
        return parts[0], parts[1], "/".join(parts[2:]) if len(parts) > 2 else ""
    return "", action_path, ""


def action_scan_key(owner: str, repo: str, sub_path: str, ref: str) -> str:
    """Stable key for cycle detection: owner/repo[/sub_path]@ref."""
    path = f"{owner}/{repo}"
    if sub_path:
        path = f"{path}/{sub_path}"
    return f"{path}@{ref}"


def extract_nested_uses(action_yml_content: str) -> list[tuple[str, str]]:
    """Parse composite action.yml steps and return [(action_path, version), ...].

    Skips local references (./...). Version is '' when unspecified.
    """
    try:
        data = yaml.safe_load(action_yml_content)
    except yaml.YAMLError:
        return []

    if not isinstance(data, dict):
        return []

    runs = data.get("runs", {})
    if not isinstance(runs, dict):
        return []
    if str(runs.get("using", "")).lower() != "composite":
        return []

    steps = runs.get("steps", [])
    if not isinstance(steps, list):
        return []

    results: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    for step in steps:
        if not isinstance(step, dict):
            continue
        uses = step.get("uses")
        if not uses or not isinstance(uses, str):
            continue
        uses = uses.strip()
        if uses.startswith("./"):
            continue

        if "@" in uses:
            action_path, version = uses.rsplit("@", 1)
        else:
            action_path = uses
            version = ""

        key = (action_path, version)
        if key not in seen:
            seen.add(key)
            results.append(key)

    return results


def finding_base(row: dict, ref: str, parent_action: str = "", depth: int = 0) -> dict:
    """Common fields for every finding row."""
    return {
        "action": clean_field(row.get("action", "")),
        "owner": clean_field(row.get("owner", "")),
        "repo": clean_field(row.get("repo", "")),
        "version": ref,
        "github_url": clean_field(row.get("github_url", "")),
        "usage_count": row.get("usage_count", 0),
        "workflow_count": row.get("workflow_count", 0),
        "parent_action": parent_action,
        "depth": depth,
        "is_transitive": depth > 0,
    }


def advisory_findings(
    row: dict,
    advisory_cache: dict,
    parent_action: str = "",
    depth: int = 0,
) -> list[dict]:
    """Look up and return known CVE/advisory findings for this action's repo."""
    owner = clean_field(row.get("owner", ""))
    repo = clean_field(row.get("repo", ""))
    if not owner or not repo:
        return []

    repo_key = f"{owner}/{repo}"
    if repo_key not in advisory_cache:
        advisory_cache[repo_key] = check_advisories(owner, repo)

    findings: list[dict] = []
    for adv in advisory_cache[repo_key]:
        if adv.get("state") in ("published", "reviewed", None, ""):
            findings.append({
                **finding_base(row, "", parent_action, depth),
                "vulnerability_category": "known_cve",
                "pattern_matched": adv.get("summary", "Advisory found")[:200],
                "file_path": adv.get("html_url", ""),
                "evidence_snippet": adv.get("summary", "")[:200],
                "severity": adv.get("severity", "high"),
                "cve_id": adv.get("cve_id", ""),
            })
    return findings


def build_child_row(action_path: str, parent_row: dict) -> dict | None:
    """Build a synthetic actions_used-style row for a nested action.

    Returns None if the path looks like a reusable workflow.
    """
    owner, repo, sub_path = parse_action_path(action_path)
    if not owner or not repo:
        return None
    if ".github/workflows/" in sub_path:
        return None

    return {
        "action": action_path,
        "owner": owner,
        "repo": repo,
        "sub_path": sub_path,
        "github_url": f"https://github.com/{owner}/{repo}",
        "usage_count": parent_row.get("usage_count", 0),
        "workflow_count": parent_row.get("workflow_count", 0),
    }


# ---------------------------------------------------------------------------
# Main scanning logic
# ---------------------------------------------------------------------------

def scan_action_at_ref(
    row: dict,
    ref: str,
    *,
    scanned_keys: set[str],
    advisory_cache: dict,
    parent_action: str = "",
    depth: int = 0,
) -> list[dict]:
    """Scan a single action at a specific ref. Returns list of finding dicts.

    For composite actions, recursively scans nested non-official uses: deps.
    """
    owner = row["owner"]
    repo = row["repo"]
    sub_path = clean_field(row.get("sub_path", ""))
    base = sub_path
    findings: list[dict] = []
    indent = "  " * (depth + 1)
    action_label = clean_field(row.get("action", ""))

    if depth > 0:
        via = f" via {parent_action}" if parent_action else ""
        print(f"{indent}[depth={depth}{via}] {action_label}@{ref or 'default'}")

    # Fetch action.yml / action.yaml at this ref
    action_yml_content, action_yml_path = fetch_file_try_names(
        owner, repo, base, ["action.yml", "action.yaml"], ref
    )

    if action_yml_content is None:
        print(f"{indent}[SKIP] Could not fetch action.yml for {action_label}@{ref or 'default'}")
        return findings

    base_fields = finding_base(row, ref, parent_action, depth)

    # Check deprecated runtime
    deprecated = check_deprecated_runtime(action_yml_content)
    if deprecated:
        findings.append({
            **base_fields,
            "vulnerability_category": "deprecated_runtime",
            "pattern_matched": f"runs.using: {deprecated}",
            "file_path": action_yml_path,
            "evidence_snippet": f"uses: {deprecated}",
            "severity": SEVERITY_MAP["deprecated_runtime"],
            "cve_id": "",
        })

    action_type, main_file = detect_action_type(action_yml_content)
    print(f"{indent}@{ref or 'default'}: type={action_type}, main={main_file or 'N/A'}")

    if action_type == "javascript":
        profile = SCAN_PROFILES["javascript"]
        if main_file:
            js_path = f"{base}/{main_file}".strip("/") if base else main_file
            js_content = fetch_file(owner, repo, js_path, ref)
            if js_content:
                scan_text = js_content[:500_000]
                raw_findings = scan_content(scan_text, profile["patterns"], js_path)
                for f in raw_findings:
                    f["vulnerability_category"] = profile["categories"].get(
                        f["pattern_matched"], "input_injection"
                    )
                    f["severity"] = SEVERITY_MAP.get(f["vulnerability_category"], "medium")
                    f.update({**base_fields, "cve_id": ""})
                    findings.append(f)
            else:
                print(f"{indent}[WARN] Could not fetch JS main file: {js_path}@{ref or 'default'}")

    elif action_type == "docker":
        profile = SCAN_PROFILES["docker"]
        if main_file.lower().startswith("dockerfile") or main_file.lower() == "dockerfile":
            docker_path = f"{base}/{main_file}".strip("/") if base else main_file
        else:
            docker_path = f"{base}/Dockerfile".strip("/") if base else "Dockerfile"

        docker_content = fetch_file(owner, repo, docker_path, ref)
        entrypoint_content, entrypoint_path = fetch_file_try_names(
            owner, repo, base, ["entrypoint.sh", "entrypoint", "run.sh", "start.sh"], ref
        )

        for content, fpath in [
            (docker_content, docker_path),
            (entrypoint_content, entrypoint_path),
        ]:
            if content:
                raw_findings = scan_content(content, profile["patterns"], fpath)
                for f in raw_findings:
                    f["vulnerability_category"] = profile["categories"].get(
                        f["pattern_matched"], "input_injection"
                    )
                    f["severity"] = SEVERITY_MAP.get(f["vulnerability_category"], "medium")
                    f.update({**base_fields, "cve_id": ""})
                    findings.append(f)

    elif action_type == "composite":
        profile = SCAN_PROFILES["composite"]
        raw_findings = scan_content(action_yml_content, profile["patterns"], action_yml_path)
        for f in raw_findings:
            f["vulnerability_category"] = profile["categories"].get(
                f["pattern_matched"], "input_injection"
            )
            f["severity"] = SEVERITY_MAP.get(f["vulnerability_category"], "medium")
            f.update({**base_fields, "cve_id": ""})
            findings.append(f)

        ml_findings = scan_composite_multiline(action_yml_content, action_yml_path)
        for f in ml_findings:
            f.update({**base_fields, "cve_id": ""})
            findings.append(f)

        # Recurse into nested uses: (unlimited depth, cycle detection)
        nested = extract_nested_uses(action_yml_content)
        if nested:
            print(f"{indent}  nested uses: {len(nested)}")

        for child_path, child_ref in nested:
            child_owner, child_repo, child_sub = parse_action_path(child_path)
            child_key = action_scan_key(child_owner, child_repo, child_sub, child_ref)

            if child_key in scanned_keys:
                print(f"{indent}  [cycle/seen] skip {child_path}@{child_ref or 'default'}")
                continue
            scanned_keys.add(child_key)

            if child_owner in OFFICIAL_OWNERS:
                print(f"{indent}  [official] record-only {child_path}@{child_ref or 'default'}")
                continue

            if ".github/workflows/" in child_sub:
                print(f"{indent}  [workflow] skip reusable workflow {child_path}")
                continue

            child_row = build_child_row(child_path, row)
            if child_row is None:
                print(f"{indent}  [SKIP] invalid nested action {child_path}")
                continue

            child_findings = scan_action_at_ref(
                child_row,
                child_ref,
                scanned_keys=scanned_keys,
                advisory_cache=advisory_cache,
                parent_action=action_label,
                depth=depth + 1,
            )
            findings.extend(child_findings)

            # CVE / advisory check for transitive child (once per first visit)
            findings.extend(
                advisory_findings(child_row, advisory_cache, action_label, depth + 1)
            )

    return findings


def scan_action(
    row: dict,
    scanned_keys: set[str],
    advisory_cache: dict,
) -> list[dict]:
    """Scan all used refs for a single root action."""
    refs = parse_used_refs(row)
    if not refs:
        refs = [""]  # fallback: default branch when no version info

    owner = clean_field(row.get("owner", ""))
    repo = clean_field(row.get("repo", ""))
    sub_path = clean_field(row.get("sub_path", ""))

    findings: list[dict] = []
    for ref in refs:
        key = action_scan_key(owner, repo, sub_path, ref)
        if key in scanned_keys:
            print(f"  @{ref or 'default'}: already scanned (skip)")
            continue
        scanned_keys.add(key)
        findings.extend(
            scan_action_at_ref(
                row,
                ref,
                scanned_keys=scanned_keys,
                advisory_cache=advisory_cache,
                parent_action="",
                depth=0,
            )
        )
    return findings


def main():
    import pandas as pd

    df = pd.read_csv(ACTIONS_CSV)

    # Filter: exclude official owners
    df = df[~df["owner"].isin(OFFICIAL_OWNERS)]

    # Filter: exclude reusable workflows (sub_path contains .github/workflows/)
    df["sub_path"] = df["sub_path"].fillna("")
    df = df[~df["sub_path"].str.contains(r"\.github/workflows/", na=False)]

    print(f"Scanning {len(df)} standalone non-official actions...\n")

    all_findings = []
    advisory_cache: dict = {}
    scanned_keys: set[str] = set()

    for idx, row in df.iterrows():
        action = row["action"]
        row_dict = row.to_dict()
        refs = parse_used_refs(row_dict)
        refs_label = ", ".join(refs) if refs else "default branch"
        print(f"[{idx+1}/{len(df)}] {action}")
        print(f"  versions to scan ({len(refs) or 1}): {refs_label}")

        # Scan source code at each used ref (and transitive composite deps)
        action_findings = scan_action(row_dict, scanned_keys, advisory_cache)
        all_findings.extend(action_findings)

        # CVE / advisory check for root action (repo-wide, not version-specific)
        all_findings.extend(advisory_findings(row_dict, advisory_cache))

        pattern_findings = [
            f for f in action_findings if f.get("vulnerability_category") != "known_cve"
        ]
        if pattern_findings:
            versions_with_findings = sorted(set(f["version"] for f in pattern_findings))
            transitive_count = sum(1 for f in pattern_findings if f.get("is_transitive"))
            print(
                f"  => {len(pattern_findings)} pattern finding(s) "
                f"across {len(versions_with_findings)} version(s)"
                + (f" ({transitive_count} transitive)" if transitive_count else "")
            )
        print()

    # Write output
    fieldnames = [
        "action", "owner", "repo", "version", "github_url", "vulnerability_category",
        "pattern_matched", "file_path", "evidence_snippet", "severity",
        "cve_id", "usage_count", "workflow_count",
        "parent_action", "depth", "is_transitive",
    ]

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for finding in all_findings:
            writer.writerow(finding)

    print(f"\n{'='*60}")
    print(f"Scan complete.")
    print(f"Total findings: {len(all_findings)}")
    print(f"Actions with findings: {len(set(f['action'] for f in all_findings))}")
    transitive_findings = [f for f in all_findings if f.get("is_transitive")]
    print(f"Transitive findings: {len(transitive_findings)}")
    print(f"Unique actions scanned (keys): {len(scanned_keys)}")
    print(f"Output: {OUTPUT_CSV}")

    # Summary by category
    from collections import Counter
    cats = Counter(f["vulnerability_category"] for f in all_findings)
    print(f"\nFindings by category:")
    for cat, count in cats.most_common():
        print(f"  {cat}: {count}")


if __name__ == "__main__":
    main()
