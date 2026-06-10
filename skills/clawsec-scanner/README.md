# Clawsec Scanner

Automated vulnerability scanner for agent platforms. Performs dependency scanning (npm audit, pip-audit), multi-database CVE lookup (OSV, NVD, GitHub Advisory), SAST analysis (Semgrep, Bandit), and agent-specific static hook inspection for OpenClaw hooks.

## Vercel Skills Installation

Install with the Vercel Skills CLI for this harness:

```bash
npx skills add prompt-security/clawsec --skill clawsec-scanner -a openclaw -y
```
