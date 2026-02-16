# Security Policy

## Supported Versions

ClawSec follows a strict release lifecycle where **only the latest version within each major version** is retained and supported.

When a new patch or minor version is released (e.g., updating from `1.0.0` to `1.0.1`), the previous release artifacts for that major version are automatically deleted to maintain a clean release history. Major versions co-exist for backwards compatibility.

| Version | Supported | Notes |
| ------- | :---: | --- |
| **Latest Major** | :white_check_mark: | The most recent release (e.g., `v1.x.x`) is fully supported. |
| **Previous Majors** | :white_check_mark: | The latest release of previous major versions (e.g., `v0.x.x`) remains available. |
| **Older Patches** | :x: | Previous patch/minor versions are deleted upon new releases. |

## Reporting a Vulnerability

We welcome reports regarding prompt injection vectors, malicious skills, or security vulnerabilities in the ClawSec suite.

### How to Submit a Report
Please report vulnerabilities directly via **GitHub Issues** using our specific template:

1.  Navigate to the **Issues** tab.
2.  Open a new issue using the **Security Incident Report** template.
3.  Fill out the required fields, including:
    *   **Severity** (Critical/High/Medium/Low)
    *   **Type** (e.g., `prompt_injection`, `vulnerable_skill`, `tampering_attempt`)
    *   **Description**
    *   **Affected Skills**

### What to Expect
Once a report is submitted, the following process occurs:

1.  **Review:** A maintainer will review your report.
2.  **Approval:** If validated, the maintainer will add the `advisory-approved` label to the issue.
3.  **Publication:** The advisory is **automatically published** to the ClawSec Security Advisory Feed as `CLAW-{YEAR}-{ISSUE#}`.
4.  **Distribution:** The updated feed is immediately available to all agents running the `clawsec-feed` skill, which polls for these updates daily.

### Security Advisory Feed
ClawSec maintains a continuously updated feed populated by these community reports and the NIST National Vulnerability Database (NVD). You can verify the current status of known vulnerabilities by querying the feed directly:

```bash
curl -s https://clawsec.prompt.security/advisories/feed.json
