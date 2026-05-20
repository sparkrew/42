# Diversity Metrics for Sampling GitHub Actions Workflows

This document defines a set of metrics for selecting a diverse subset of GitHub Actions workflow files from a large dataset. Each metric can be computed by parsing the workflow YAML. The goal is to maximize coverage across structural, security, and ecosystem dimensions when building a labeled vulnerability dataset.

## Status Legend

| Status | Meaning |
|---|---|
| ⬜ | Not tested |
| 🟡 | Tested, partially useful |
| ✅ | Tested, confirmed useful |
| ❌ | Tested, not useful / dropped |

---

## 1. Structural Complexity [1]

Metrics that capture the size, shape, and composition of a workflow.

### 1.1 Number of Jobs
- **Field:** Count of keys under `jobs:`
- **Values:** Integer
- **Rationale:** Single-job workflows behave differently from multi-job pipelines with parallel or sequential execution.
- **Status:** ⬜
- **Notes:**

### 1.2 Total Number of Steps
- **Field:** Sum of items across all `jobs.<id>.steps` arrays
- **Values:** Integer
- **Rationale:** More steps means more surface for misconfiguration and more data flow paths.
- **Status:** ⬜
- **Notes:**

### 1.3 Has Matrix Strategy
- **Field:** Presence of `jobs.<id>.strategy.matrix`
- **Values:** Boolean
- **Rationale:** Matrix strategies multiply execution paths and introduce parameterized complexity.
- **Status:** ⬜
- **Notes:**

### 1.4 Has Job Dependencies
- **Field:** Presence of `needs:` in any job definition
- **Values:** Boolean
- **Rationale:** Distinguishes independent parallel jobs from sequential DAG-structured pipelines. Data can flow between dependent jobs via outputs.
- **Status:** ⬜
- **Notes:**

### 1.5 Uses Reusable Workflows
- **Field:** Job-level `uses:` pointing to a `.yml`/`.yaml` file (not an action)
- **Values:** Boolean
- **Rationale:** Reusable workflows add a layer of indirection that complicates security analysis.
- **Status:** ⬜
- **Notes:**

### 1.6 Workflow File Size
- **Field:** Line count or character count of the YAML file
- **Values:** Integer
- **Rationale:** Rough proxy for overall complexity. Very small workflows are likely trivial; very large ones may have more attack surface.
- **Status:** ⬜
- **Notes:**

---

## 2. Trigger Configuration [2]

The trigger type directly determines who can activate a workflow and what data they can control, making it a primary factor in the attack surface.

### 2.1 Trigger Types Present
- **Field:** Keys under `on:` (or the value if `on:` is a string/list)
- **Values:** Set of strings (e.g., `{push, pull_request}`)
- **Rationale:** Different triggers expose different user-controllable data fields and grant different levels of access to secrets and tokens.
- **Status:** ⬜
- **Notes:**

### 2.2 Trigger Diversity Count
- **Field:** Number of distinct trigger event types
- **Values:** Integer
- **Rationale:** Workflows with more trigger types tend to be more actively used and have broader attack surfaces. Correlated with usage intensity (Spearman rho=0.589 per Khatami et al.).
- **Status:** ⬜
- **Notes:**

### 2.3 Trigger Risk Level
- **Field:** Derived from trigger types
- **Values:** Categorical — `low` / `medium` / `high`
- **Classification:**
  - **High:** `pull_request_target`, `issue_comment`, `issues` (types: opened/edited), `discussion_comment`, `workflow_dispatch` (with user inputs)
  - **Medium:** `pull_request`, `workflow_run`
  - **Low:** `push`, `schedule`, `release`, `create`, `delete`
- **Rationale:** High-risk triggers allow user-controlled data to flow into the workflow while retaining elevated permissions or secrets access.
- **Status:** ⬜
- **Notes:**

### 2.4 Has Workflow Dispatch Inputs
- **Field:** Presence of `on.workflow_dispatch.inputs`
- **Values:** Boolean
- **Rationale:** User-defined inputs to manual triggers are a taint source if used unsanitized.
- **Status:** ⬜
- **Notes:**

---

## 3. Action Usage Patterns [3, 4]

How a workflow references third-party and first-party actions determines its supply-chain risk profile.

### 3.1 Number of Third-Party Action References
- **Field:** Count of `uses:` steps where the value does not start with `./` and is not a reusable workflow
- **Values:** Integer
- **Rationale:** Each third-party action is an external dependency that could be compromised, outdated, or misconfigured.
- **Status:** ⬜
- **Notes:**

### 3.2 Number of Unique Action Owners
- **Field:** Count of distinct `owner` values extracted from `uses: owner/repo@ref`
- **Values:** Integer
- **Rationale:** Depending on many different owners increases the trust surface.
- **Status:** ⬜
- **Notes:**

### 3.3 SHA Pinning Ratio
- **Field:** (Number of `uses:` refs pinned to a full 40-char SHA) / (Total `uses:` refs)
- **Values:** Float [0.0, 1.0]
- **Rationale:** SHA pinning is the recommended security practice. A ratio of 0.0 means no pinning; 1.0 means fully pinned. Most workflows have a ratio near 0 (fewer than 3% of repos use SHA pinning per Decan et al.).
- **Status:** ⬜
- **Notes:**

### 3.4 Action-to-Run Ratio
- **Field:** (Number of `uses:` steps) / (Number of `run:` steps)
- **Values:** Float (0 means all shell, infinity means all actions, use ratio or counts)
- **Rationale:** Workflows heavy on `run:` steps have more direct shell execution surface (code injection via expressions). Workflows heavy on `uses:` steps depend more on third-party code.
- **Status:** ⬜
- **Notes:**

### 3.5 Uses Unverified or Obscure Actions
- **Field:** Whether any `uses:` reference points to an action not from a well-known owner (e.g., not `actions/*`, `github/*`, `azure/*`, `aws-actions/*`, `docker/*`)
- **Values:** Boolean
- **Rationale:** Actions from lesser-known owners have a higher risk of being malicious or unmaintained.
- **Status:** ⬜
- **Notes:**

---

## 4. Security-Relevant Features [5]

Features that directly indicate or correlate with known vulnerability patterns.

### 4.1 Expressions in Run Blocks
- **Field:** Whether any `run:` step contains `${{` expressions
- **Values:** Boolean (or count of occurrences)
- **Rationale:** This is the primary pattern for code injection vulnerabilities. Tainted context values interpolated into shell commands enable arbitrary code execution.
- **Status:** ⬜
- **Notes:**

### 4.2 Taint Source Count
- **Field:** Count of known user-controllable GitHub context references in the entire YAML text
- **Values:** Integer
- **Known taint sources (from ARGUS):**
  - `github.event.issue.title`, `github.event.issue.body`
  - `github.event.pull_request.title`, `github.event.pull_request.body`
  - `github.event.comment.body`, `github.event.review.body`
  - `github.event.discussion.title`, `github.event.discussion.body`
  - `github.event.head_commit.message`
  - `github.head_ref`, `github.event.pull_request.head.ref`
  - `github.event.workflow_run.head_branch`
  - `github.event.head_commit.author.email`, `github.event.head_commit.author.name`
  - `github.event.commits.*.message`, `github.event.commits.*.author.email`
  - `github.event.pull_request.head.label`
- **Rationale:** More taint sources in a workflow means more potential entry points for attacker-controlled data.
- **Status:** ⬜
- **Notes:**

### 4.3 Has Permissions Block
- **Field:** Presence of top-level or job-level `permissions:` key
- **Values:** Boolean
- **Rationale:** Workflows without explicit permissions default to read-write on all scopes (for repos created before Feb 2023), making them over-privileged.
- **Status:** ⬜
- **Notes:**

### 4.4 Permission Scope
- **Field:** Value of `permissions:` if present
- **Values:** Categorical — `read-all` / `write-all` / `granular` / `empty (locked down)` / `not set`
- **Rationale:** Granular permissions indicate security-conscious configuration. Write-all or not-set indicates over-privilege.
- **Status:** ⬜
- **Notes:**

### 4.5 Secrets Usage Count
- **Field:** Count of `${{ secrets.` references in the YAML text
- **Values:** Integer
- **Rationale:** Workflows that use secrets have higher impact if compromised. The number of distinct secrets indicates the breadth of sensitive data exposed during execution.
- **Status:** ⬜
- **Notes:**

### 4.6 GITHUB_TOKEN Usage
- **Field:** Whether the YAML contains `${{ github.token }}` or `${{ secrets.GITHUB_TOKEN }}`
- **Values:** Boolean
- **Rationale:** GITHUB_TOKEN grants repository access. If exfiltrated via a code injection vulnerability, it enables supply-chain attacks (pushing code, creating releases, etc.).
- **Status:** ⬜
- **Notes:**

### 4.7 Environment Variables with Expressions
- **Field:** Whether any `env:` block (workflow-level, job-level, or step-level) contains `${{` expressions
- **Values:** Boolean
- **Rationale:** Taint can propagate through environment variables. A tainted value assigned to an env var and later used in a `run:` step is an indirect code injection path.
- **Status:** ⬜
- **Notes:**

### 4.8 Has Conditional Expressions
- **Field:** Presence of `if:` on any job or step
- **Values:** Boolean (or count)
- **Rationale:** Conditional logic can serve as sanitization (reducing vulnerability) or can itself use tainted data. Adds control-flow complexity to analysis.
- **Status:** ⬜
- **Notes:**

---

## 5. Ecosystem and Context [1, 2, 6]

Metrics about the surrounding project and the workflow's purpose.

### 5.1 Repository Primary Language
- **Field:** From repo metadata (not the YAML itself)
- **Values:** String (Python, JavaScript, TypeScript, Go, Java, C++, Rust, C#, Ruby, PHP, etc.)
- **Rationale:** Different language ecosystems have different CI patterns, build tools, and action usage. The GHALogs dataset covers 20 languages.
- **Status:** ⬜
- **Notes:**

### 5.2 Repository Popularity
- **Field:** Star count (or stars + forks) from repo metadata
- **Values:** Integer, bucketed into quartiles or log-scale bands
- **Rationale:** Popular repos tend to have more mature workflows but are also higher-value targets. Less popular repos may have more experimental/insecure configurations.
- **Status:** ⬜
- **Notes:**

### 5.3 Workflow Purpose
- **Field:** Heuristic from the `name:` field or filename
- **Values:** Categorical — `ci-test` / `build` / `deploy-release` / `code-quality` / `security-scan` / `dependency-management` / `documentation` / `other`
- **Heuristic keywords:**
  - `ci-test`: ci, test, check, validate, verify
  - `build`: build, compile, package
  - `deploy-release`: deploy, release, publish, push
  - `code-quality`: lint, format, style, quality, prettier, eslint
  - `security-scan`: codeql, security, scan, sast, snyk, trivy, semgrep
  - `dependency-management`: dependabot, deps, dependency, renovate
  - `documentation`: docs, pages, documentation
- **Rationale:** Different workflow purposes have different vulnerability profiles. A deployment workflow with secrets is higher impact than a lint workflow.
- **Status:** ⬜
- **Notes:**

### 5.4 Runner Operating System
- **Field:** Values of `runs-on:` across all jobs
- **Values:** Set of strings (e.g., `{ubuntu-latest, windows-latest}`)
- **Rationale:** Different OS runners have different shell defaults (bash vs. PowerShell) affecting injection patterns. Self-hosted runners have additional security implications.
- **Status:** ⬜
- **Notes:**

### 5.5 Has Self-Hosted Runner
- **Field:** Whether any `runs-on:` contains `self-hosted`
- **Values:** Boolean
- **Rationale:** Self-hosted runners persist state between runs and may have access to internal networks, making vulnerabilities more impactful.
- **Status:** ⬜
- **Notes:**

### 5.6 Uses Container or Services
- **Field:** Presence of `container:` or `services:` in any job
- **Values:** Boolean
- **Rationale:** Container-based jobs and service containers add another layer where misconfigurations can occur.
- **Status:** ⬜
- **Notes:**

---

## Suggested Sampling Strategy

### Primary Stratification Axes
1. **Structural complexity:** simple (1 job, <=3 steps) / medium (2-3 jobs or 4-10 steps) / complex (4+ jobs, matrix, or 10+ steps)
2. **Trigger risk level:** low / medium / high (from metric 2.3)
3. **Action dependency profile:** no third-party / pinned third-party / unpinned third-party
4. **Security feature surface:** no expressions in run / has expressions but no taint sources / has taint sources in expressions

### Secondary Diversity Axes
5. Repository language (top 6)
6. Repository popularity (quartiles)
7. Workflow purpose (from metric 5.3)

### Sampling Approach
For each combination of primary axes (3 x 3 x 3 x 3 = 81 cells), sample N workflows. Within each cell, maximize diversity on secondary axes. With N=10-15 per cell, the total dataset is 810-1215 workflows.

---

---

## Metrics Summary

| Metric | Already in Metadata | Status |
|---|---|---|
| Number of Jobs |  | ⬜ |
| Total Number of Steps |  | ⬜ |
| Has Matrix Strategy |  | ⬜ |
| Has Job Dependencies |  | ⬜ |
| Uses Reusable Workflows |  | ⬜ |
| Workflow File Size |  | ⬜ |
| Trigger Types Present |  | ⬜ |
| Trigger Diversity Count |  | ⬜ |
| Trigger Risk Level |  | ⬜ |
| Has Workflow Dispatch Inputs |  | ⬜ |
| Number of Third-Party Action References |  | ⬜ |
| Number of Unique Action Owners |  | ⬜ |
| SHA Pinning Ratio |  | ⬜ |
| Action-to-Run Ratio |  | ⬜ |
| Uses Unverified or Obscure Actions |  | ⬜ |
| Expressions in Run Blocks |  | ⬜ |
| Taint Source Count |  | ⬜ |
| Has Permissions Block |  | ⬜ |
| Permission Scope |  | ⬜ |
| Secrets Usage Count |  | ⬜ |
| GITHUB_TOKEN Usage |  | ⬜ |
| Environment Variables with Expressions |  | ⬜ |
| Has Conditional Expressions |  | ⬜ |
| Repository Primary Language |  | ⬜ |
| Repository Popularity |  | ⬜ |
| Workflow Purpose |  | ⬜ |
| Runner Operating System |  | ⬜ |
| Has Self-Hosted Runner |  | ⬜ |
| Uses Container or Services |  | ⬜ |


## References

[1] Rostami Mazrae et al. "An Empirical Study of the Evolution of GitHub Actions Workflows." 2026.

[2] Khatami et al. "Beyond the YAML File: Understanding Real-World GitHub Actions Workflow Adoption." EASE 2026.

[3] Abrokwah & Ghaleb. "How Compliant Are GitHub Actions Workflows?" EASE 2026.

[4] Chaiwut & Nikiforakis. "Time for Actions: A Longitudinal Study of the GitHub Actions Marketplace." IEEE SecDev 2025.

[5] Muralee et al. "ARGUS: A Framework for Staged Static Taint Analysis of GitHub Workflows and Actions." USENIX Security 2023.

[6] Moriconi et al. "GHALogs: Large-Scale Dataset of GitHub Actions Runs." IEEE MSR 2025.

[7] Koishybayev et al. "Characterizing the Security of GitHub CI Workflows." USENIX Security 2022.

[8] Beller et al. "TravisTorrent: Synthesizing Travis CI and GitHub for Full-Stack Research on Continuous Integration." IEEE MSR 2017.
