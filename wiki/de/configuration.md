<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (de)
Source: ../configuration.md
Review status: draft
-->

# Konfiguration

Anwendungsbereich
- Konfiguration erstreckt sich über Frontend Build-Einstellungen, Laufzeit-Feed-Pfade, Workflow-Trigger und Kompetenz-Metadaten-Verträge.
- Die meisten Runtime-sensitiven Steuerungen sind Umgebungsvariablen, die mit `CLAWSEC_` oder `OPENCLAW_` vorgegeben sind.
- Die Path-Normalisierung ist sicherheitsempfindlich und lehnt absichtlich ungelöste Heim-Token-Literaturen ab.

Variablen Core Runtime
| Variable | Default | Wird von | verwendet
--- | --- | ---
| `CLAWSEC_FEED_URL` | Hosted Advisory URL | Suite Haken und bewachte Installations-Feed-Ladung. |
| `CLAWSEC_FEED_SIG_URL` | `<feed>.sig` | Gelöschte Signaturquelle. |
| `CLAWSEC_FEED_CHECKSUMS_URL` | `checksums.json` in der Nähe der Feed-URL | Optionale Prüfsumme-manifest-Quelle. |
| `CLAWSEC_FEED_PUBLIC_KEY` | Suite-local PEM-Datei | Signaturverifikation füttern. |
| `CLAWSEC_ALLOW_UNSIGNED_FEED` | `0` | Temporäre Migrationsbypass-Flagge. |
| `CLAWSEC_VERIFY_CHECKSUM_MANIFEST` | `1` | Ermöglicht die Überprüfung von Prüfsummen-Manifest. |
| `CLAWSEC_HOOK_INTERVAL_SECONDS` | `300` | Beratende Haken-Scandrossel. |

/ Wegeauflösungsregeln
| Regel | Verhalten | Durchsetzung Standort |
--- | --- | ---
| `~` Erweiterung | Aufgelöst auf erkanntes Home-Verzeichnis | Geteilte Pfad-Dienstfunktionen in Suite/watchdog-Skripten. |
| `$HOME` / `${HOME}` Erweiterung | Aufgelöst, wenn nicht | Gleiche Dienstprogramme. |
| Windows home tokens | `%USERPROFILE%`, `$env:USERPROFILE` normalisiert | Gleiche Dienstprogramme. |
| Escaped tokens (`\$HOME`) | Ausgestoßen mit explizitem Fehler | Verhindert die zufällige buchstäbliche Verzeichnis-Erstellung. |
| Ungültiger expliziter Pfad | Kann mit Warnung auf Standardpfad zurückfallen . `resolveConfiguredPath` Helfer. |

Frontend und Build Konfiguration
- `vite.config.ts` definiert Port (`3000`), Host (`0.0.0.0`) und Pfad-Alias (`@`_).
- `index.html` bietet Tailwind Runtime config, benutzerdefinierte Schriften, und Grundfarbe Tokens.
- `tsconfig.json` verwendet die Paketermodulauflösung `noEmit` und die JSX Laufzeitkonfiguration.
- `eslint.config.js` TS, React, Haken und Script-spezifische Lint Regeln.

Metadaten der Fähigkeiten Konfiguration
| Feldgruppe | Standort | Funktion |
--- | --- | ---
| Kernkompetenzidentität | `skills/*/skill.json` | Name/Version/Autor/Lizenz/Beschreibung Metadaten. |
| SBOM-Dateiliste | `skill.json -> sbom.files` | Erklärt Release-erforderliche Artefakte. |
| Platform metadata | `openclaw` oder `nanoclaw` Blöcke | CLI Anforderungen, Trigger, Plattformfähigkeitshinweise. |
| Suite Katalog Metadaten | `skills/clawsec-suite/skill.json -> catalog` | Integriertes/Standard/consent Verhalten für Suite-Mitglieder. |

Â Workflow Konfiguration
- Die Schedule-Konfiguration existiert im Workflow `cron` Einträge (`poll-nvd-cves`, `codeql`, `scorecard`.
- Release Workflow erwartet Tag Benming-Muster `<skill>-v<semver>`.
- Der Arbeitsablauf wird durch erfolgreiche CI/Release `workflow_run` Ereignisse und manuelle Versendung ausgelöst.
- Composite Signing Aktion erfordert private Schlüsseleingänge und überprüft Signaturen unmittelbar nach der Unterzeichnung.

Beispiel Snippets
```bash
# run guarded install with explicit local signed feed paths
CLAWSEC_LOCAL_FEED="$HOME/.openclaw/skills/clawsec-suite/advisories/feed.json" \
CLAWSEC_LOCAL_FEED_SIG="$HOME/.openclaw/skills/clawsec-suite/advisories/feed.json.sig" \
CLAWSEC_FEED_PUBLIC_KEY="$HOME/.openclaw/skills/clawsec-suite/advisories/feed-signing-public.pem" \
node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill clawtributor --dry-run
```

```json
{
  "name": "example-skill",
  "version": "1.2.3",
  "sbom": {
    "files": [
      { "path": "SKILL.md", "required": true, "description": "Install docs" }
    ]
  }
}
```

Betriebshinweise
- Halten Sie die Zeichentasten vor dem Repository und injizieren Sie nur über GitHub Secrets.
- Bestimmen Sie absolute Pfade oder unescaped Home Expressions in lokalen Umgebungsvariablen übergeordnet.
- Behandeln Sie den nicht zugewiesenen Feed-Modus als temporäre Migrationsunterstützung, nicht normaler Betrieb.
- Re-run release-link Validierung bei der Bearbeitung `SKILL.md`_ URLs, um gebrochene Artefakte Referenzen zu vermeiden.

Quellenangaben
- vite.config.ts
- index.html
- tsconfig.json
- eslint.config.js
- Fähigkeiten/Clawsec-suite/skill.json
- Fertigkeiten/Klausel-Nanoclaw/skill.json
- Fertigkeiten/Clawsec-suite/hooks/clawsec-advisory-guardian/lib/utils.mjs
- Fertigkeiten/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- Fertigkeiten/Clawsec-suite/scripts/guarded_skill_install.mjs
- Skripte/validate-release-links.sh
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/skill-release.yml
- .github/actions/sign-and-verify/action.yml
