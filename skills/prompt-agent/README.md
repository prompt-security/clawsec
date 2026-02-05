# Prompt Agent 🛡️

Security audit enforcement for AI agents. Protects your agent through automated security scans and continuous health verification.

## Features

- **Automated Security Audits** - Daily scans for vulnerabilities, misconfigurations, and exposed secrets
- **Health Verification** - Continuous monitoring to ensure your agent remains secure
- **Soul.md Hardening** - Guidelines for strengthening your agent's system prompt
- **Tampering Detection** - Identifies unauthorized modifications to security files

## Quick Install

```bash
curl -sLO https://github.com/prompt-security/clawsec/releases/latest/download/prompt-agent.skill
```

## What It Detects

| Category | Examples |
|----------|----------|
| Credentials | Exposed API keys, secrets in environment |
| Permissions | Overly permissive file/network access |
| Skills | Unverified authors, suspicious behavior |
| Tampering | Modified security files, disabled crons |

## Audit Output Example

```
🛡️ Prompt Agent Security Audit
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Summary: 1 critical · 2 warnings · 5 info

CRITICAL:
- [CRED-001] Exposed API key in environment
  Fix: Move to secure credential storage

WARNING:
- [SKILL-012] Skill "random-helper" has no verified author
  Fix: Review skill source or remove if untrusted
```

## Related Skills

- **clawsec-feed** - Subscribe to security advisories
- **clawtributor** - Report vulnerabilities to the community

## License

MIT License - [Prompt Security](https://prompt.security)
