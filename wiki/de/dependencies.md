<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (de)
Source: ../dependencies.md
Review status: draft
-->

# Abhängigkeiten

Aufbau und Laufzeit
| Ebene | Primärabhängigkeiten | Warum es existiert |
--- | --- | ---
| Frontend Laufzeit | __TOK_0_, `react-dom`, `react-router-dom`, `lucide-react` | UI Rendering, Routing, Iconographie. |
| Markdown Rendering | __TOK_0_, `remark-gfm` | Render Skill-Docs/readmes und in-app Wiki-Markdown-Seiten. |
| Werkzeugbau | __TOK_0_, __TOK_1_, `typescript` | Fast TS/TSX Bündelung und Produktion baut. |
| Python utilities | stdlib + `ruff`/_TOK_1_ Policy from `pyproject.toml` | Gültige/Paketfähigkeiten und führen statische Überprüfungen durch. |
| Shell Automation | `bash`, `jq`, `curl`, __TOK_3_, `sha256sum`_`shasum` | Fütterung, Signierung, Prüfsummenerzeugung, Freigabeprüfungen. |

Abhängige Details
| Paket | Version Constraint | Scope |
--- | --- | ---
| `react` / `react-dom` | `^19.2.4` | Vorneige Laufzeit |
| `react-router-dom` | __TOK_1_ | Frontend Routing |
| `lucide-react`_ | `^0.575.0` | UI Symbolsatz |
| `vite` | __TOK_1_ | Dev Server + build |
| `typescript` | `~5.8.2` | Typkontrolle |
|
| `@typescript-eslint/*` | __TOK_1_ / `^8.56.0` | TS lint parser/rules |
| `fast-check` | `^4.5.3` | Immobilien/Fuss-Style-Tests |

| Override | Pinned Version | Rationale |
--- | --- | ---
| `ajv` | `6.14.0` | Sicherheit und Kompatibilitätsstabilisierung. |
| `balanced-match` | `4.0.3` | Transitive Sicherheitskontrolle. |
| `brace-expansion` | `5.0.2` | Übergangsabhängigkeitsverfestigung. |
| `minimatch` | `10.2.1` | Deterministische Abhängigkeitsverhalten. |

Externe Dienste
| Service | Gebraucht von | Funktion |
--- | --- | ---
| NVD API (`services.nvd.nist.gov`) | `poll-nvd-cves` Workflow + lokales Feed-Skript | Pull CVEs nach Schlüsselwort/Datumsfenster. |
| GitHub API | Workflows bereitstellen/erleichtern | Releases entdecken, Assets herunterladen, Outputs veröffentlichen. |
| GitHub Pages | Workflow bereitstellen | statische Seite und gespiegelte Artefakte bedienen. |
| ClawHub CLI/Registry | Installieren Sie Skripte + optionale Jobs | Installieren und veröffentlichen Sie Fähigkeiten. |
| Optional lokale SMTP/sendmail | `openclaw-audit-watchdog` Scripts | Auditberichte per E-Mail liefern. |

/ Entwicklungswerkzeuge
| Tool | Invocation | Coverage |
--- | --- | ---
| ESLint | __TOK_0_ | Frontend und Skriptlinting. |
| TypeScript | `npx tsc --noEmit` | Laufzeit TS Vertragsüberprüfungen. |
| Ruff | `ruff check utils/` | Python-Stil und Bug-Muster überprüfen. |
| Bandit | __TOK_0_ | Python Sicherheitskontrollen. |
| Trivy | Workflow + optionaler lokaler Run | FS/config Sicherheitsscans. |
| Gitleaks | __TOK_0_ optionaler lokaler Run | Secret Leck Erkennung vor dem Push. |

Beispiel Snippets
```json
{
  "scripts": {
    "dev": "vite",
    "build": "vite build",
    "preview": "vite preview"
  },
  "dependencies": {
    "react": "^19.2.4",
    "react-router-dom": "^7.13.1"
  }
}
```

```toml
[tool.ruff]
target-version = "py310"
line-length = 120

[tool.bandit]
exclude_dirs = ["__pycache__", ".venv"]
skips = ["B101"]
```

In den Warenkorb
- Lokale Skripte Konto für macOS vs Linux Unterschiede in __TOK_0_ und __TOK_1_ Nutzung.
- Einige Workflows/scripts erfordern OpenSSL-Funktionen, die mit Ed25519 und `pkeyutl -rawin` verwendet werden.
- Windows-Unterstützung ist am stärksten für Node-basierte Tooling; POSIX Shell-Pfade kann WSL / Git Bash benötigen.
- Zu den Futtermittelverbrauchern gehören Kompatibilitätsbypasses für Migrationsphasen, aber der unterzeichnete Modus ist der beabsichtigte stationäre Zustand.

In den Warenkorb
- Skill Release-Tags folgen __TOK_0_ und werden von CI/Deploy Automation parsed.
- Die PR-Validierung erzwingt die Versionsparität zwischen __TOK_0_ und `SKILL.md` Frontmatter für sprunghafte Fähigkeiten.
- Ja. Der Public Skill Index hält die neueste entdeckte Version pro Geschick für UI-Display.
- Signierte Artefakte Manifeste (`checksums.json`) werden pro Veröffentlichung veröffentlicht und beinhalten File Hashes und URLs.

Quellenangaben
- Paket.json
- Paket-lock.json
- pyproject.toml
- eslint.config.js
- tsconfig.json
- Skripte/Präpare-to-push.sh
- Skripte/Popula-lokal-feed.sh
- Skripte/Popula-lokal-skills.sh
- .github/workflows/ci.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/skill-release.yml
