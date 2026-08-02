# ClawSec README hero sources

`hero-layout.svg` is the editable English layout for the published `../hero.webp` asset. The localized layouts and WebPs use the same visual system:

| Locale | Editable layout | Published asset |
| --- | --- | --- |
| English | `hero-layout.svg` | `../hero.webp` |
| German | `hero-layout-de.svg` | `../hero-de.webp` |
| Spanish | `hero-layout-es.svg` | `../hero-es.webp` |
| French | `hero-layout-fr.svg` | `../hero-fr.webp` |
| Japanese | `hero-layout-ja.svg` | `../hero-ja.webp` |
| Korean | `hero-layout-ko.svg` | `../hero-ko.webp` |

All layouts compose two existing repository-native brand files instead of duplicating or regenerating them:

- `../../../public/img/mascot.png`
- `../../../img/Black+Color.png`

Keep the Prompt Security from SentinelOne lockup intact on its light plaque. The black wordmarks lose contrast when placed directly on the violet background.

## Translation assurance

`hero-copy.json` is the exact copy and accessibility source for every banner. The translations were AI-generated, independently model-reviewed, and given literal English back-translations. They have not been certified by professional native translators.

The local Gemma challenger output was rejected because it translated the UI field label itself and weakened guarded-install terminology. The accepted copy uses the repository contract: an advisory match stops a risky install until the operator gives a second, explicit confirmation.

Regenerate or check the deterministic localized SVG sources:

```bash
node assets/readme/source/generate-localized-hero-svgs.mjs
node assets/readme/source/generate-localized-hero-svgs.mjs --check
```

Run the same gate used by the build, PR checks, and `prepare-to-push.sh`:

```bash
npm run readme:heroes:check
```

That gate validates the manifest before use, checks every generated localized SVG, and verifies English plus all localized README mappings, exact SVG copy, accessibility text, distinct WebPs, `1200 × 460` dimensions, alpha data, and the 300 KB size budget.

Render each SVG in a standards-compliant browser at `1200 × 460`, then export its published WebP at the same dimensions. The layouts use platform font fallbacks and the WebPs use lossy color encoding, so SVG-to-WebP pixel identity is intentionally not treated as deterministic across renderers. After every render, visually inspect desktop and mobile presentation, text fidelity, and actual transparent corner pixels before running the automated gate.

The verifier can also be run directly:

```bash
node assets/readme/source/verify-localized-heroes.mjs
```

No generated artwork is used in these compositions. SVG controls all exact text; the unchanged raster layers are the existing ClawSec mascot and combined Prompt Security from SentinelOne logo.
