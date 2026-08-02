<!--
Translation source: ../skill-feature-matrix.md
Last synchronized: 2026-08-02
Method: Codex-assisted translation with repository terminology and structural parity checks
Review status: native-speaker review pending
-->

# Skill-Funktionsmatrix

Diese Seite bewahrt den paketweisen Funktionsvergleich für ClawSec. Die englische Seite ist die kanonische Quelle; diese Übersetzung behält dieselbe Paketreihenfolge und dieselbe Bedeutung der Statusangaben bei.

Die Plattformübersicht fasst die Abdeckung der aktuellen Paketfamilie zusammen. Eine Funktion kann ein separates Skill-Paket erfordern, statt im primären Einstiegspunkt der Plattform enthalten zu sein.

## Plattformübersicht

| Plattform | Advisory- und Feed-Verarbeitung | Integrität und Drift | Audit und Sicherheitslage | Installations-Risikoprüfung | Prüfung potenzieller Installationsartefakte | Community-Meldungen | Runtime-Datenverkehr |
| --- | --- | --- | --- | --- | --- | --- | --- |
| OpenClaw | Signaturprüfung und externe Abfragen | Über das optionale Paket `soul-guardian` | Verfügbar | Advisory- und Reputationsprüfungen | Kein integrierter Prüfer für Kandidatenartefakte; Installation an ClawHub delegiert | Opt-in | Nur Spezifikation |
| NanoClaw | Fail-closed-Signaturprüfung | Integriert | Advisory- und Schwachstellenaudit | Advisory-Vorabprüfung | Implementierte NanoClaw-Integration; Prüfung von Kandidatenpaketsignaturen mit fest verankertem Schlüssel | Opt-in | Nur Spezifikation |
| Hermes | Fail-closed-Signaturprüfung | Integriert | Attestierungs- und Lageprüfung | Nur Advisory-Vorabprüfung | Keine Prüfung von Kandidatenartefakten | Opt-in | Nur Spezifikation |
| Picoclaw | Nutzt vorgelagert verifizierten Feed-Status | Integriert | Integrierte Lageprofilerstellung + separate nur lesende Prüfung | Keine Installationssperre | Ausführbare Releaseartefaktprüfung; vom Aufrufer als vertrauenswürdig festgelegter Schlüssel | Opt-in | Nur Spezifikation |

Jedes veröffentlichte ClawSec-Paket dokumentiert eine manuelle Vorabprüfung des signierten Manifests für sein eigenes Standalone-Archiv. Diese gemeinsame Baseline für Release-Integrität wird unten nicht in jeder Zeile wiederholt. `claw-release` leitet zusätzlich die Erstellung dieser signierten Releases an. Die Kandidatenprüfungsspalte ist Installationsartefakten vorbehalten, die über das eigene Archiv eines Pakets hinausgehen.

## Paketweise Abdeckung

<!-- skill-feature-matrix:start -->
| Skill-Name | Plattform | Advisory- und Feed-Verarbeitung | Integrität und Drift | Audit und Sicherheitslage | Installations-Risikoprüfung | Prüfung potenzieller Installationsartefakte | Community-Meldungen | Runtime-Datenverkehr |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `claw-release` | OpenClaw | Nein | Nein | Nein | Nein | Keine Prüfung von Kandidatenartefakten | Nein | Nein |
| `clawsec-clawhub-checker` | OpenClaw + Integration in `clawsec-suite` | Advisory-Prüfung der Suite | Nein | Nein | ClawHub-Reputation + Advisory-Prüfung der Suite | Keine Prüfung von Kandidatenartefakten | Nein | Nein |
| `clawsec-feed` | OpenClaw | Advisory-Datenpaket; Abruf durch Suite oder Operator; keine Feed-Signaturprüfung | Nein | Nein | Nein | Keine Prüfung von Kandidatenartefakten | Nein | Nein |
| `clawsec-nanoclaw` | NanoClaw | Fail-closed-Signaturprüfung | Dateibaselines + optionale Wiederherstellung | Advisory-/Schwachstellenaudit; keine aktiven Tests | Advisory-Vorabprüfung | Implementierte NanoClaw-Integration; Prüfung von Kandidaten-Paketsignaturen mit fest verankertem Schlüssel | Nein | Nein |
| `clawsec-scanner` | OpenClaw | Externe CVE-Abfrage; keine signierte Feed-Verifizierung | Nein | Abhängigkeits-, SAST- und statisches Hook-Audit; keine aktive Ausnutzung | Nein | Keine Prüfung von Kandidatenartefakten | Nein | Nein |
| `clawsec-suite` | OpenClaw | Verifizierung des signierten Feeds + des Prüfsummenmanifests | Über optionales `soul-guardian`; nicht integriert | Nein | Advisory-Sperre + ausdrückliche Bestätigung | Kein integrierter Prüfer für Kandidatenartefakte; nur ein generisches Hilfsprogramm zur Prüfung abgetrennter Signaturen; Installation an ClawHub delegiert | Nein | Nein |
| `clawtributor` | Alle Kernplattformen | Nein | Nein | Nein | Nein | Nein | Freigabepflichtiger lokaler Entwurf + manuelle Übermittlung | Nein |
| `hermes-attestation-guardian` | Hermes | Fail-closed-Signaturprüfung | Drift bei Attestierung, Konfiguration und Vertrauensankern | Attestierungs- und Lageprüfung | Nur Advisory-Vorabprüfung | Keine Prüfung von Kandidatenartefakten | Nein | Nein |
| `hermes-traffic-guardian` | Hermes | Nein | Nur geplanter Export der Sicherheitslage | Nein | Nein | Nein | Nein | Nur Spezifikation; kein Runtime-Proxy |
| `nanoclaw-traffic-guardian` | NanoClaw | Nein | Nein | Nein | Nein | Nein | Nein | Nur Spezifikation; kein Runtime-Proxy |
| `openclaw-audit-watchdog` | OpenClaw | Nein | Nein | Automatisiertes Audit mit Tiefenmodus; keine aktive Ausnutzung | Nein | Nein | Nein | Nein |
| `openclaw-traffic-guardian` | OpenClaw | Nein | Nein | Nein | Nein | Nein | Nein | Nur Spezifikation; kein Runtime-Proxy |
| `picoclaw-security-guardian` | Picoclaw | Nutzt verifizierten Feed-Status; kryptografische Prüfung erfolgt vorgelagert | Deterministische Profil- und Konfigurationsdrift | Nur lesende Lageprüfungen | Nein | Ausführbare Prüfung von Picoclaw-Releaseartefakten durch Prüfung der Prüfsumme und des signierten Manifests; vom Aufrufer als vertrauenswürdig festgelegter Schlüssel | Nein | Nein |
| `picoclaw-self-pen-testing` | Picoclaw | Nein | Nein | Nur lesende Self-Pen-Lageprüfung; keine aktive Ausnutzung | Nein | Nein | Nein | Nein |
| `picoclaw-traffic-guardian` | Picoclaw | Nein | Nur geplanter Profilexport | Nein | Nein | Nein | Nein | Nur Spezifikation; kein Runtime-Proxy |
| `soul-guardian` | OpenClaw | Nein | Workspace-Dateibaseline, Drifterkennung und optionale Wiederherstellung | Nein | Nein | Nein | Nein | Nein |
<!-- skill-feature-matrix:end -->

## Statusdefinitionen

- **Signaturprüfung** bedeutet, dass das Paket signiertes Vertrauensmaterial selbst prüft. **Überwachung**, **externe Abfrage** und **vorgelagert verifizierter Status** bleiben bewusst getrennt.
- Die **Installations-Risikoprüfung** beschreibt Advisory- oder Reputationsprüfungen vor der Installation. Sie ist kein Nachweis der Provenienz des Kandidatenartefakts.
- Die gemeinsame **Vorabprüfung des eigenen Pakets** deckt nur das jeweilige Releasearchiv ab. Die Kandidatenprüfungsspalte erfasst die Prüfung anderer Installationsartefakte.
- **Audit und Sicherheitslage** umfasst statische, Abhängigkeits-, Advisory-, Attestierungs- und nur lesende Lageprüfungen. Die Matrix kennzeichnet ausdrücklich, wenn keine aktive Ausnutzung erfolgt.
- **Über optionales Add-on** bedeutet, dass das Hauptpaket einen separaten Skill finden oder koordinieren kann, diese Funktion aber nicht selbst ausliefert.
- **Nur Spezifikation** bedeutet, dass Verzeichnis, Metadaten, Frontmatter und Implementierungsvertrag existieren, aber kein Runtime-Proxy ausgeliefert wird.
- **Nur geplanter Export der Sicherheitslage/des Profils** beschreibt einen Integrationsvertrag in einer Traffic-Guardian-Spezifikation und keinen ausgelieferten Driftmonitor.

`clawtributor` ist ein plattformübergreifendes Paket zur Meldung von Sicherheitsvorfällen. Seine `Nein`-Werte bedeuten, dass die anderen Schutzfunktionen der Matrix außerhalb seines Meldeumfangs liegen, nicht dass das Paket inaktiv ist.

## Pflege

Die 16 Paketzeilen wurden aus der früheren README-Matrix übernommen. Die Funktionsachsen wurden dort getrennt, wo die alten Binärwerte Überwachung mit Verifizierung, Audit mit aktiven Tests, Add-ons mit integrierten Funktionen oder Advisory-Sperren mit Artefaktprovenienz vermischten.

Die Matrix muss mit den Verzeichnissen unter `skills/` übereinstimmen. Die Übersetzungsprüfung stellt sicher, dass jede lokalisierte Matrix dieselben 16 Paketkennungen, dieselbe Reihenfolge und eine Struktur mit neun Spalten beibehält.

## Quellreferenzen

- `skills/*/skill.json`
- `skills/*/SKILL.md`
- [ClawSec Suite Core](../modules/clawsec-suite.md)
- [ClawSec Scanner](../modules/clawsec-scanner.md)
- [NanoClaw-Integration](../modules/nanoclaw-integration.md)
- [Hermes Attestation Guardian](../modules/hermes-attestation-guardian.md)
- [Picoclaw Security Guardian](../modules/picoclaw-security-guardian.md)
- [Picoclaw Self Pen Testing](../modules/picoclaw-self-pen-testing.md)
- [Runtime Traffic Guardian Baseline](../modules/runtime-traffic-guardian-baseline.md)
