---
name: Security Incident Report
about: Report malicious prompts, vulnerable skills, or tampering attempts
labels: security, needs-triage
---

## Opener Type

<!-- Check one: -->
- [ ] Human
- [ ] Agent (automated report)

---

## Report Type

<!-- Check one: -->
- [ ] Malicious Prompt - Detected prompt injection or social engineering attempt
- [ ] Vulnerable Skill - Found a skill with security issues
- [ ] Tampering Attempt - Observed attempt to disable/modify ClawSec

## Severity

<!-- Check one: -->
- [ ] Critical - Active exploitation, data exfiltration, complete bypass
- [ ] High - Significant security risk, potential for harm
- [ ] Medium - Security concern that should be addressed
- [ ] Low - Minor issue, best practice violation

---

## Title

<!-- Brief descriptive title of the incident -->

## Description

<!-- Detailed description of what was observed -->

---

## Evidence

### Observed At
<!-- ISO 8601 timestamp: YYYY-MM-DDTHH:MM:SSZ -->

### Context
<!-- What was happening when this occurred -->

### Payload
<!-- The actual prompt/code/behavior observed (SANITIZED - remove any real user data, credentials, or PII) -->

```
<!-- Paste sanitized payload here -->
```

### Indicators
<!-- List specific indicators that flagged this as suspicious -->
-
-
-

---

## Affected

### Component or Skill Name
<!-- Required. Exact protected runtime, infrastructure component, or skill package name. -->

### Affected Version Scope
<!-- Required. Exact version or range, for example: 1.2.3, <1.2.3, or >=1.0.0 <1.2.3. Do not enter "unknown" or "*". -->

### Protected Components
<!-- Check all that apply: -->
- [ ] OpenClaw (agent runtime)
- [ ] NanoClaw (agent runtime)
- [ ] Hermes (agent runtime)
- [ ] Picoclaw (agent runtime)
- [ ] OpenShell (sandbox runtime)
- [ ] NemoClaw (agent stack)

---

## Recommended Action

<!-- What should users do in response to this threat? -->

---

## Reporter Information (Optional)

**Agent/User Name:**
**Contact:** <!-- How to reach for follow-up -->

---

## Privacy Checklist

<!-- Confirm before submitting: -->
- [ ] I have removed all real user data and PII
- [ ] I have not included any API keys, credentials, or secrets
- [ ] Evidence is sanitized and describes issues abstractly where needed
- [ ] No proprietary or confidential information is included

---

## Additional Notes

<!-- Any other relevant information -->
