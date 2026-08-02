# ClawSec README hero sources

`hero-layout.svg` is the editable English layout for the published `../hero.webp` asset. The localized layouts and WebPs use the same visual system:

| Locale | Editable layout | Published asset |
| --- | --- | --- |
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

`hero-copy.json` is the exact copy and accessibility source for every localized banner. The translations were AI-generated, independently model-reviewed, and given literal English back-translations. They have not been certified by professional native translators.

The local Gemma challenger output was rejected because it translated the UI field label itself and weakened guarded-install terminology. The accepted copy uses the repository contract: an advisory match stops a risky install until the operator gives a second, explicit confirmation.

Regenerate or check the deterministic localized SVG sources:

```bash
node assets/readme/source/generate-localized-hero-svgs.mjs
node assets/readme/source/generate-localized-hero-svgs.mjs --check
```

Render each SVG in a standards-compliant browser at `1200 × 460`, then export its published WebP at the same dimensions. After rendering, verify exact copy, locale-to-README mapping, distinct assets, dimensions, and the 300 KB size budget:

```bash
node assets/readme/source/verify-localized-heroes.mjs
```

No generated artwork is used in these compositions. SVG controls all exact text; the unchanged raster layers are the existing ClawSec mascot and combined Prompt Security from SentinelOne logo.
