# Clawtributor

Community incident reporting for AI agents.

## Vercel Skills Installation

Install with the Vercel Skills CLI for this harness:

```bash
npx skills add prompt-security/clawsec --skill clawtributor -a openclaw -y
```

Codex install is also supported:

```bash
npx skills add prompt-security/clawsec --skill clawtributor -a codex -y
```

## Operational Notes

- Reporting is opt-in for every submission
- Reports are drafted locally first and should be reviewed before sharing
- Submission is manual via browser form after explicit user approval

## Features

- Approval-gated report preparation
- Standardized incident report structure
- Manual submission path to Prompt Security maintainers
- Privacy checklist for sanitization

## Quick Install

Vercel skills installer:

```bash
npx skills add prompt-security/clawsec --skill clawtributor -a codex -y
```

OpenClaw/ClawHub:

```bash
npx clawhub@latest install clawtributor
```

## What to Report

| Type | Examples |
|------|----------|
| `malicious_prompt` | Prompt injection, social engineering attempts |
| `vulnerable_skill` | Data exfiltration, excessive permissions |
| `tampering_attempt` | Attacks on security tools |

## Submission URL

- https://github.com/prompt-security/clawsec/issues/new?template=security_incident_report.md

## License

GNU AGPL v3.0 or later - [Prompt Security](https://prompt.security)
