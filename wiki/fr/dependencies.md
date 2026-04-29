<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (fr)
Source: ../dependencies.md
Review status: draft
-->

Dépendances

## Construire et exécuter
Pourquoi il existe des dépendances primaires
- Oui.
Frontend runtime. - Oui.
Le rendu de Markdown est rendu par `react-markdown`, `remark-gfm`. - Oui.
Construisez l'outillage d'outillage d'outillage d'outillage d'outillage d'outillages `vite`, `@vitejs/plugin-react`, `typescript`. - Oui.
Utilitaires Python : stdlib + `ruff`/`bandit` politique de `pyproject.toml`. - Oui.
- Oui. Automatisation de la coquille: - Oui.

Détails de la dépendance
Version Contraintes Portée
- Oui.
`react` / `react-dom`
`react-router-dom`
Jeu d'icônes de l'interface utilisateur `lucide-react`
`vite`
`typescript`
`eslint`
`@typescript-eslint/*`= `^8.55.0` / `^8.56.0`= TS analyseur de lint/règles=
`fast-check`

Dépassement Version épinglée Justification
- Oui.
`ajv`.`6.14.0`.Sécurité et stabilisation de la compatibilité. - Oui.
`balanced-match`.`4.0.3`. - Oui.
`brace-expansion`.`5.0.2`. - Oui.
`minimatch`.`10.2.1`. - Oui.

Services externes
Service utilisé par fonction
- Oui.
API NVD (`services.nvd.nist.gov`) (`poll-nvd-cves` workflow + script de flux local) Tirez les CVE par la fenêtre mot-clé/date. - Oui.
API GitHub Déployer/release workflows Découvrez les versions, les actifs de téléchargement, les sorties de publication. - Oui.
GitHub Pages Déploiement Déploiement Service statique et artefacts miroirs. - Oui.
Installer des scripts + des emplois de publication optionnels Installer et publier des compétences. - Oui.
En option, SMTP/sendmail local. - Oui.

## Outils de développement
Couverture de l'Invocation
- Oui.
ESLint: `npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0`. - Oui.
TypeScript (en anglais seulement) `npx tsc --noEmit` (en anglais seulement). - Oui.
Le style Python et les contrôles de patrons de bugs. - Oui.
Bandit: `bandit -r utils/ -ll` , Vérifications de sécurité Python. - Oui.
Trivy: flux de travail + exécution locale optionnelle. - Oui.
Gitleaks (en option) `scripts/prepare-to-push.sh` (en option) - Oui.

## Exemples d'extraits
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

## Notes de compatibilité
- Les scripts locaux rendent compte des différences entre macOS et Linux dans l'utilisation de `date` et `stat`.
- Certains workflows/scripts nécessitent des fonctionnalités OpenSSL utilisées avec Ed25519 et `pkeyutl -rawin`.
- La prise en charge de Windows est la plus forte pour l'outillage basé sur les nœuds; les chemins shell POSIX peuvent nécessiter WSL/Git Bash.
- Les consommateurs d'aliments pour animaux incluent les contournements de compatibilité pour les phases de migration, mais le mode signé est l'état stable prévu.

Remarques de version
- Les étiquettes de sortie des compétences suivent `<skill>-v<semver>` et sont analysées par l'automatisation CI/déploiement.
- La validation PR impose la parité de version entre `skill.json` et `SKILL.md` pour les compétences en bosse.
- Oui. L'indice des compétences publiques conserve la dernière version découverte par compétence pour l'affichage de l'interface utilisateur.
- Les manifestes d'artefacts signés (`checksums.json`) sont mis en version par version et comprennent des hashes de fichiers et des URL.

Références sources
- paquet.json
- paquet-lock.json
- pyproject.toml
- eslint.config.js
- tsconfig.json
- scripts/prepare-to-poush.sh
- scripts/popular-local-feed.sh
- scripts/popular-local-skills.sh
- .github/workflows/ci.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/kill-release.yml
