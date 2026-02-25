# Module: Frontend Web App

## Responsibilities
- Render the ClawSec website for home, skills catalog/detail, and advisory feed/detail experiences.
- Provide resilient JSON fetch behavior that handles SPA HTML fallback cases.
- Display install commands, checksums, and advisory metadata in a browser-focused UX.

## Key Files
- `index.tsx`: React bootstrap and root mount.
- `App.tsx`: Router map and page entry wiring.
- `pages/Home.tsx`: Landing page, install card, animated platform/file labels.
- `pages/SkillsCatalog.tsx`: Catalog fetch/filter state machine and empty-state handling.
- `pages/SkillDetail.tsx`: Loads `skill.json`, checksums, README/SKILL docs with markdown renderer.
- `pages/FeedSetup.tsx`: Advisory listing UI with pagination.
- `pages/AdvisoryDetail.tsx`: Advisory deep-dive view and source links.
- `components/Layout.tsx` + `components/Header.tsx`: Shared shell and nav behavior.

## Public Interfaces
- Browser routes:
  - `/`
  - `/skills`
  - `/skills/:skillId`
  - `/feed`
  - `/feed/:advisoryId`
- Static fetch targets:
  - `/skills/index.json`
  - `/skills/<skill>/skill.json`
  - `/skills/<skill>/checksums.json`
  - `/advisories/feed.json`
- Display contracts:
  - `SkillMetadata`, `SkillJson`, `SkillChecksums`, `AdvisoryFeed`, `Advisory` from `types.ts`.

## Inputs and Outputs
Inputs/outputs are summarized in the table below.

| Type | Name | Location | Description |
| --- | --- | --- | --- |
| Input | Skills index JSON | `/skills/index.json` | List of published skills and metadata. |
| Input | Skill payload files | `/skills/<id>/skill.json`, markdown docs, `checksums.json` | Detail-page content and integrity table. |
| Input | Advisory feed JSON | `/advisories/feed.json` or remote URL fallback | Advisory list/detail content. |
| Output | Route-specific UI states | Browser view state | Loading, empty, error, and populated experiences. |
| Output | Copy-to-clipboard commands | Clipboard API | Install and checksum snippets copied for users. |

## Configuration
- Build/runtime config comes from:
  - `vite.config.ts` (port, host, path alias)
  - `index.html` Tailwind config + custom fonts/colors
  - `constants.ts` (`ADVISORY_FEED_URL`, `LOCAL_FEED_PATH`)
- Runtime behavior assumptions:
  - JSON responses may be empty or HTML fallback and must be validated.
  - Advisory list pagination uses `ITEMS_PER_PAGE = 9`.

## Example Snippets
```tsx
// Catalog fetch logic guards against HTML fallback responses
const contentType = response.headers.get('content-type') ?? '';
const raw = await response.text();
if (!raw.trim() || contentType.includes('text/html') || isProbablyHtmlDocument(raw)) {
  setSkills([]);
  setFilteredSkills([]);
  return;
}
```

```tsx
// Route map defined in App.tsx
<Route path="/skills/:skillId" element={<SkillDetail />} />
<Route path="/feed/:advisoryId" element={<AdvisoryDetail />} />
```

## Edge Cases
- Missing `skills/index.json` returns empty catalog instead of hard failure.
- Some environments return `index.html` for missing JSON paths with status `200`; code defends against this.
- Skill detail tolerates missing/malformed checksums and missing markdown docs.
- Advisory detail handles absent optional fields (`cvss_score`, `reporter`, `references`).

## Tests
| Test Type | Location | Notes |
| --- | --- | --- |
| Type/lint/build checks | `scripts/prepare-to-push.sh` + CI | Frontend confidence comes from static checks and build success. |
| App-wide CI gates | `.github/workflows/ci.yml` | Multi-OS TypeScript/ESLint/build checks. |
| Manual smoke checks | `npm run dev` | Validate route rendering and fetch paths during development. |

## Source References
- index.tsx
- App.tsx
- pages/Home.tsx
- pages/SkillsCatalog.tsx
- pages/SkillDetail.tsx
- pages/FeedSetup.tsx
- pages/AdvisoryDetail.tsx
- pages/Checksums.tsx
- components/Layout.tsx
- components/Header.tsx
- constants.ts
- types.ts
- vite.config.ts
- index.html
