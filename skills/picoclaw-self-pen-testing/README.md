# picoclaw-self-pen-testing

Picoclaw-only local posture-review findings package for ClawSec.

Status: implemented (v0.0.1), Picoclaw-specific.

## Vercel Skills Installation

Install with the Vercel Skills CLI for this harness:

```bash
npx skills add prompt-security/clawsec --skill picoclaw-self-pen-testing -a openclaw -y
```

## What it does

Given a generated Picoclaw posture profile, it emits severity-ranked findings and a summary count for local operator review.

## Quickstart

```bash
node scripts/self_pen_test.mjs --profile ~/.picoclaw/security/clawsec/current-profile.json
```

## Test

```bash
node test/self_pen_test.test.mjs
```
