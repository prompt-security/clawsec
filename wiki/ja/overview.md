<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: ../overview.md
Review status: draft
-->

ツイート プロフィール

## 目的
- ClawSecは、公開WebカタログとOpenClawおよびNanoClaw環境用のインストール可能なセキュリティスキルを組み合わせたセキュリティ重視のリポジトリです。
- - - コードベースは、静的ウェブサイトの公開、署名されたアドバイザリー配布、およびper-skill GitHubリリースパッケージの3つのデリバリーパスをサポートしています。
- プライマリユーザーは、CIベースのセキュリティ自動化を実行しているエージェント・オペレータ、スキル・デベロッパー、メンテナーです。

![Prompt Security Logo](../assets/overview_img_01_prompt-security-logo.png)
![ClawSec Mascot](../assets/overview_img_02_clawsec-mascot.png)

ツイート リポレイアウト
| パス | ロール | ノート |
| お問い合わせ |
| `pages/`、`components/`、`App.tsx`、`index.tsx` | Vite + React UI | スキルカタログ、アドバイザリーフィード、詳細ページ お問い合わせ
| `skills/` | セキュリティスキルパッケージ | 各スキルは`skill.json`、`SKILL.md`、オプションスクリプト/テスト/ドキュメントを持っています。 お問い合わせ
| `advisories/` | リポジトリアドバイザリーチャンネル | 署名 `feed.json` + `feed.json.sig`と主要素材. お問い合わせ
| `scripts/` | ローカルオートメーション | フィード/スキル、プレプッシュチェック、リリースヘルパーのポップアップ お問い合わせ
| `.github/workflows/` | CI/CD パイプライン | CI、リリース、NVD ポーリング、コミュニティアドバイザリー摂取、ページ展開 お問い合わせ
| `utils/` | パイソンユーティリティ | スキル検証とチェックサム包装ヘルパー お問い合わせ
| `public/` | 静的資産の公開 | サイトメディア、ミラード・アドバイザリー、生成されたスキルアーティファクト。 お問い合わせ
| `wiki/` | ドキュメンテーションハブ | アーキテクチャー・オペレーション・ランブック・互換性・検証ガイド お問い合わせ

## エントリーポイント
| エントリー | タイプ | 目的 |
| お問い合わせ |
| `index.tsx` | フロントエンドブーツ | `#root`にReactアプリをマウント お問い合わせ
| `App.tsx` | フロントエンドルータ | 自宅・スキル・フィード・wikiページのルートマップの定義 お問い合わせ
| `scripts/prepare-to-push.sh` | Devのワークフロー | プッシュ前にlint/type/build/securityのチェックを実行します。 お問い合わせ
| `scripts/populate-local-feed.sh` | データブートストラップ | NVD から CVE をプルし、現地のアドバイザリーフィードを更新します。 お問い合わせ
| `scripts/populate-local-skills.sh` | データブートストラップ | `public/skills/index.json` と 1 スキルチェックサムのビルド お問い合わせ
| `scripts/generate-wiki-llms.mjs` | ドキュメントのエクスポート | `public/wiki/llms.txt` と 1 ページの wiki のエクスポートを生成します。 お問い合わせ
| `.github/workflows/skill-release.yml` | リリースエントリー | ハンドルPR版-parity/dry-run checks and tag-based Packaging/signing/release お問い合わせ
| `.github/workflows/poll-nvd-cves.yml` | フィード更新スケジュール | ポールズNVDとアップデートのアドバイザリー お問い合わせ

## キーアーティファクト
| アーティファクト | プロデュース | | コンセプト |
| お問い合わせ |
| `advisories/feed.json` | NVD 投票 + コミュニティアドバイザリーワークフロー | Web UI、clawsec-suite ホック、インストーラー お問い合わせ
| `advisories/feed.json.sig` | ワークフローの署名 | スイート・アンド・ノークローのシグネチャ検証 お問い合わせ
| `public/skills/index.json` | ワークフロー・ローカル・ポジュレート・スクリプトの展開 | `pages/SkillsCatalog.tsx` と `pages/SkillDetail.tsx` お問い合わせ
| `public/wiki/llms.txt` + `public/wiki/**/llms.txt` | ウィキジェネレータスクリプト + ビルドホック | LLM-ready wiki エクスポート wiki UI からリンクされています。 お問い合わせ
| `public/checksums.json` + `public/checksums.sig` | ワークフローの展開 | オペレータやランタイムのクライアントのための公開整合性アーティファクト. お問い合わせ
| `release-assets/checksums.json` | スキルリリースワークフロー | 消費者がzipの完全性を検証するリリース お問い合わせ
| `skills/*/skill.json` | スキル作者 | サイトカタログ作成・検証・リリースパイプライン お問い合わせ

ツイート キーワークフロー
- ローカルWeb開発: `npm install` は、`npm run dev` です。
- ローカルセキュリティデータプレビュー: `./scripts/populate-local-skills.sh` と `./scripts/populate-local-feed.sh` をロードする前に `/skills` と `/feed` ページを実行します。
- プレパス品質ゲート:`./scripts/prepare-to-push.sh`(オプションで`--fix`)を実行します。
- スキルのライフサイクル:`skills/<name>/`を編集し、`python utils/validate_skill.py`で検証し、`<skill>-vX.Y.Z`にタグを付けてリリースワークフローをトリガーします。
- アドバイザリーのライフサイクル:NVDのポールおよび問題ラベルに基づくコミュニティの摂取量は、同じ署名されたフィードに結合します。

## サンプルスニペット
```bash
# local UI + locally populated data
npm install
./scripts/populate-local-skills.sh
./scripts/populate-local-feed.sh --days 120
npm run dev
```

```bash
# canonical TypeScript quality checks used by CI
npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0
npx tsc --noEmit
npm run build
```

ツイート 開始場所
- `README.md`は、製品位置決めとインストールパスです。
- `App.tsx` と `pages/` を開き、ユーザーフェーシングの動作を把握します。
- `skills/clawsec-suite/skill.json`を開き、スイート契約と組込みコンポーネントを理解します。
- `.github/workflows/ci.yml`、`.github/workflows/pages-verify.yml`、`.github/workflows/skill-release.yml`、`.github/workflows/deploy-pages.yml`、および`.github/workflows/wiki-sync.yml`の生産行動のレビュー。

ツイート ナビゲートする方法
- `pages/`にUIの動作が集中しています。`components/`にビジュアルラッパーが座っています。
- スキル固有のロジックは、`skills/`のフォルダによって分離されます。各フォルダには独自のスクリプト/テスト/ドキュメントが含まれています。
- フィード処理は、リポジトリフィードファイル、ワークフローの更新、ランタイムの消費者(`clawsec-suite`/`clawsec-nanoclaw`)の3つのレイヤーに表示されます。
- `scripts/`およびワークフローYAMLファイルで動作品質ゲートが稼働します。
- 生成のトレースやベースラインを更新するには、`wiki/GENERATION.md`から始まり、モジュールページにブランチします。

## 共通ピッタフォール
- 設定パス env vars で literal のホームトークン (たとえば `\$HOME`) を使うと、パス検証の失敗をトリガーできます。
- SPA ルートから JSON を取得すると、ステータス 200 で HTML を返すことができます。このページガードは空の状態として扱います。
- 移行の互換性のために、フィードバイパスモード(`CLAWSEC_ALLOW_UNSIGNED_FEED=1`)が存在し、安定した状態では使用しないでください。
- `skill.json`と`SKILL.md`のフロントマッタ間のバージョンのパリティを期待するスキルリリース自動化。
- 一部のスクリプトは、POSIX シェル指向です。 Windows ユーザーは、PowerShell の同等体または WSL を好む必要があります。

## 更新ノート
- 2026-02-26: 削除されたルート`docs/`ディレクトリの代わりに、`wiki/`で運用文書を指すためにリポジトリレイアウトを更新しました。

## ソース参照
- README.mdの
- パッケージ.json
- App.tsxアプリ
- インデックス.tsx
- ページ/ホーム.tsx
- ページ/SkillsCatalog.tsx
- ページ/SkillDetail.tsx
- ページ/フィードSetup.tsx
- スクリプト/prepare-to-push.sh
- スクリプト/populate-local-feed.sh
- スクリプト/populate-local-skills.sh
- スキル/ clawsec-suite/skill.json
- .github/workflows/ci.yml
- .github/workflows/pages-verify.yml
- .github/workflows/skill-release.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/wiki-sync.yml
