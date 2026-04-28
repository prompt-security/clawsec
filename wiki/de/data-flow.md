<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (de)
Source: ../data-flow.md
Review status: draft
-->

# Datenfluss

Primäre Ströme
- __TOK_0_: NVD/Gemeinde-Eingänge werden in einen normalisierten Beratungsfeed umgewandelt, signiert, dann für Kunden gespiegelt.
- __TOK_0_: Freigabevermögen werden entdeckt und in __TOK_1_ plus per-skill docs/checksums umgewandelt.
- __TOK_0_: Suite- und Nanoclaw-Verbraucher laden beratende Daten, passen gegen Fähigkeiten und senden Alarme oder Bestätigungs-Gate aus.
- Ja. Diese Seite erscheint unter dem `Guides` Abschnitt in `INDEX.md`.

Schritt für Schritt
ANHANG Feed-Produzent Workflow/script holt Quelldaten (_TOK_0__ oder Ausgabe Payload) ab.
2. JSON-Transformationslogik normalisiert Schwere/Typ/beeinflusste Felder und dedupliziert durch Beratungs-ID.
3. Signatur/Checksum-Schritte erzeugen abgelöste Signaturen und Prüfsummen manifestiert.
4. Bereitstellung von Workflow-Spiegeln signiert Artefakte unter __TOK_0_ und `public/releases/latest/download/`.
5. UI-Verbraucher validieren JSON Shape/Content; Laufzeit-Verbraucher überprüfen zusätzlich Signaturen/Checksums vor vertrauensvollen Feed-Daten.
6. Die Matcher vergleichen `affected`-Spezifikatoren mit Geschicksnamen/Versionen und senden Alarme aus oder setzen die Bestätigung durch.

Eingänge und Ausgänge
Inputs/Outputs sind in der folgenden Tabelle zusammengefasst.

| Typ | Name | Standort | Beschreibung |
| --- | --- | ---
| Input | CVE Payloads | `services.nvd.nist.gov/rest/json/cves/2.0` | Source Schwachstellen gefiltert durch ClawSec Keywords. |
| Input | Community Advisory Issue | __TOK_0_ Event Payload | Maintainer-genehmigte Ausgabe verwandelt in Advisory Record. |
| Input | Skill release Assets | GitHub veröffentlicht API + Assets | Wird verwendet, um Webkatalog und Spiegel-Downloads zu erstellen. |
| Input | Local config/env | __TOK_0_, `CLAWSEC_*` vars | Controls Feed-Tracking, Unterdrückung und Verifikationsverhalten. |
| Ausgabe | Beratender Feed | `advisories/feed.json` | Canonical Repository Feed. |
| Ausgabe | Beratende Signatur | `advisories/feed.json.sig` | Entschlossene Signatur für Feed-Authentizität. |
| Ausgabe | Skill Katalogindex | `public/skills/index.json` | Runtime Webkatalog verwendet von `/skills` Seiten. |
| Ausgabe | Release Schecksums/signatures | `release-assets/checksums.json(.sig)` | Integrity manifest for release Konsumenten. |
| Ausgabe | Hook state | __TOK_0_ | Verfolgen Sie Scan-Terminal und angezeigte Spiele. |

oder Datenstrukturen
| Struktur | Schlüsselfelder | Zweck |
--- | --- | ---
| Beratender Feed-Record | __TOK_0_, `severity`, __TOK_2_, `affected[]`, `published`_ | Einheit der von UI und Installern verwendeten Risikodaten. |
| Skill Metadatensatz | __TOK_0_, `name`, __TOK_2_, __TOK_3_, `tag` | Katalogzeile für Web-Browsing und Installationsbefehle. |
| Checksums manifest | __TOK_0_, `algorithm`, `files` | Kartendateinamen, die erwartete Verdauungen aufweisen. |
| Beratender Zustand | __TOK_0_, __TOK_1_, `notified_matches` | Verhindert wiederholte Warnungen und Drosseln Scans. |
| Suppression config | __TOK_0_, `suppressions[]` | Gezielte Liste der Skipisten von __TOK_2_ + `skill`.

(Diagramme)
```mermaid
flowchart LR
  A["NVD + Issue Inputs"] --> B["Transform + Deduplicate"]
  B --> C["advisories/feed.json"]
  C --> D["Sign + checksums"]
  D --> E["public/advisories + releases/latest"]
  E --> F["Web UI fetch"]
  E --> G["Suite/NanoClaw verification"]
  G --> H["Match skills + emit alerts/gates"]
```

Zustand und Lagerung
| Pfad/Scope | Pfad schreiben |
--- | --- | ---
| Canonical Advisories | __TOK_0_ | NVD + Community Workflows und lokales Populärskript. |
| Embedded-Beratungskopien | __TOK_0_ und `skills/clawsec-suite/advisories/` | Sync/Packaging-Prozesse und Release-Workflow. |
| Öffentliche Spiegel | __TOK_0_, `public/releases/` | Workflow bereitstellen. |
| Laufzeit Zustand | `~/.openclaw/clawsec-suite-feed-state.json` | Beratender Haken Zustand Beharrlichkeit. |
| NanoClaw cache | `/workspace/project/data/clawsec-advisory-cache.json` | Host-side Advisory cache manager. |
| Integritätszustand | __TOK_0_ (NanoClaw) | Integritätsmonitor Basis-/Auditspeicher. |

Beispiel Snippets
```bash
# Local feed flow (NVD fetch -> transform -> sync)
./scripts/populate-local-feed.sh --days 120
jq '.updated, (.advisories | length)' advisories/feed.json
```

```bash
# Runtime guarded install uses signed feed paths
CLAWSEC_LOCAL_FEED=~/.openclaw/skills/clawsec-suite/advisories/feed.json \
CLAWSEC_FEED_PUBLIC_KEY=~/.openclaw/skills/clawsec-suite/advisories/feed-signing-public.pem \
node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
```

Nicht verfügbar
- NVD-Ratenlimits (`403/429`) können die Feed-Erfrischung verzögern und Retries/Backoff benötigen.
- Fehlende oder ungültige abgelöste Signaturen verursachen die Ablehnung von Futtermitteln im fehlgeschlagenen Modus.
- HTML Fallback-Antworten für JSON Endpunkte können falsche Positive erzeugen, es sei denn, explizit gefiltert.
- Die Path-token-Fehlerkonfiguration (`\$HOME`) kann die lokale Fallbackpfadauflösung brechen.
- Unübertroffene öffentliche Schlüssel Fingerabdrücke in Workflows lösen harte CI-Versagen aus.

Quellenangaben
- Berater/feed.json
- Berater/feed.json.sig
- Skripte/Popula-lokal-feed.sh
- Skripte/Popula-lokal-skills.sh
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/skill-release.yml
- Fertigkeiten/Clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs
- Fertigkeiten/Clawsec-suite/hooks/clawsec-advisory-guardian/lib/state.ts
- Fähigkeiten/Clawsec-suite/hooks/clawsec-advisory-guardian/lib/matching.ts
- Fertigkeiten/Clawsec-suite/scripts/guarded_skill_install.mjs
- Fertigkeiten/Clawsec-nanoclaw/lib/advisories.ts
- Fähigkeiten/Clawsec-nanoclaw/host-services/advisory-cache.ts
