<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: ../dependencies.md
Review status: draft
-->

# 依存関係

##ビルドとランタイム
| レイヤー | プライマリ依存 | プライマリ依存症 | なぜそれが存在なのか |
| お問い合わせ |
| フロントエンドのランタイム | `react`、`react-dom`、`react-router-dom`、`lucide-react` | UIのレンダリング、ルーティング、アイコングラフィ。 お問い合わせ
| マークダウンレンダリング | `react-markdown`、`remark-gfm` | レンダリング・スキル・ドキュメント/readmes、アプリ内ウィキマークダウンページ お問い合わせ
| ビルドツーリング | `vite`, `@vitejs/plugin-react`, `typescript` | 速いTS/TSX束縛と生産ビルド. お問い合わせ
| python ユーティリティ | stdlib + `ruff`/`bandit` ポリシー から `pyproject.toml` | 検証・パッケージのスキルと静的なチェックを実行します。 お問い合わせ
お問い合わせ シェルオートメーション | `bash`、`jq`、`curl`、`openssl`、`sha256sum`/`shasum` | フィードポーリング、サイン、チェックサム生成、リリースチェック。 お問い合わせ

## 依存性の詳細
| パッケージ | バージョン制約 | スコープ |
| お問い合わせ |
| `react` / `react-dom` | `^19.2.4` | フロントエンドランタイム |
| `react-router-dom` | `^7.13.1` | フロントエンドルーティング |
| `lucide-react` | `^0.575.0` | UIアイコンセット |
| `vite` | `^7.3.1` | 開発サーバー | ビルド |
| `typescript` | `~5.8.2` | タイプチェック |
| `eslint` | `^9.39.2` | JS/TSライニング |
| `@typescript-eslint/*` | `^8.55.0` / `^8.56.0` | TSXQTOKEN2QXZ | ツ・リントパーサ・ルール |
| `fast-check` | `^4.5.3` | 物件・機能テスト |

| オーバーライド | ピン留め版 | ライエーレ |
| お問い合わせ |
| `ajv` | `6.14.0` | セキュリティと互換性の安定化 お問い合わせ
| `balanced-match` | `4.0.3` | トランジティブ脆弱性制御 お問い合わせ
| `brace-expansion` | `5.0.2` | 移行依存症の硬化 お問い合わせ
| `minimatch` | `10.2.1` | 決定的な依存行動 お問い合わせ

## 外部サービス
| サービス | ご利用 | | ご利用条件 | ご利用条件 |
| お問い合わせ |
| NVD API(`services.nvd.nist.gov`) | `poll-nvd-cves` ワークフロー + ローカルフィードスクリプト | キーワード/日付ウィンドウでCVEをプルする お問い合わせ
| GitHub API | ワークフローの展開・リリース | リリースの発見、アセットのダウンロード、出力の公開 お問い合わせ
| GitHub Pages | ワークフローの展開 | 静的なサイトを運営し、アーティファクトを映す お問い合わせ
| ClawHub CLI/registry | スクリプトのインストール + オプションの公開ジョブ | インストールと公開スキル. お問い合わせ
| オプションのローカルSMTP/sendmail | `openclaw-audit-watchdog`スクリプト | 監査報告書をメールで配信 お問い合わせ

## 開発ツール
| ツール | 呼び出し | 取材 | 取材 |
| お問い合わせ |
| ESLint | `npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0` | フロントエンド・スクリプト・ライニング お問い合わせ
| TypeScript | `npx tsc --noEmit` | コンパイル時間TS契約チェック お問い合わせ
| ラフ | `ruff check utils/` | パイソンスタイルとバグパターンチェック お問い合わせ
| バンディット | `bandit -r utils/ -ll` | python セキュリティー検査 お問い合わせ
| トライビー | ワークフロー + ローカルラン | FS/config 脆弱性スキャン お問い合わせ
| Gitleaks | `scripts/prepare-to-push.sh` オプションのローカルラン | プッシュ前のシークレットリーク検出 お問い合わせ

## サンプルスニペット
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

## 互換性のノート
- `date`と`stat`の使用におけるmacOSとLinuxの違いに対するローカルスクリプトアカウント。
- 一部のワークフロー/スクリプトでは、Ed25519と`pkeyutl -rawin`で使用されるOpenSSL機能が必要です。
- Windows サポートはNodeベースの工具細工のために最も強いです;POSIXの貝パスはWSL/Git Bashを必要とするかもしれません。
- 供給の消費者は移住段階のための両立性バイパスを含んでいます、署名されたモードは意図された安定した状態です。

## 検証ノート
- スキルリリースタグは、`<skill>-v<semver>` をフォローし、CI/deploy 自動化によって解析されます。
- PR検証は、`skill.json`と`SKILL.md`のフロントマッター間でのバージョンパティを強化します。
- - - パブリックスキル指数は、UI表示のためのスキルごとに最新の発見されたバージョンを保持します。
- 署名されたアーティファクトマニフェスト(`checksums.json`)は、リリースごとにバージョンアップされ、ファイルハッシュとURLが含まれています。

## ソース参照
- パッケージ.json
- パッケージ-lock.json
- pyproject.toml
- eslint.config.js ディレクティブ
- tsconfig.json
- スクリプト/prepare-to-push.sh
- スクリプト/populate-local-feed.sh
- スクリプト/populate-local-skills.sh
- .github/workflows/ci.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/skill-release.yml
