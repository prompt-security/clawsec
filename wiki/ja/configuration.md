<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: ../configuration.md
Review status: draft
-->

# 設定

## スコープ
- 設定は、フロントエンドのビルド設定、ランタイムフィードパス、ワークフロートリガー、およびスキルメタデータ契約を組み合わせます。
- ほとんどのランタイムに敏感な制御は`CLAWSEC_`か`OPENCLAW_`とプレフィックスした環境変数です。
- パス正規化は、セキュリティに敏感であり、意図的に未解決の家庭トークンリテラルを拒否します。

## コアランタイム変数
| 変数 | デフォルト | によって使用される |
| お問い合わせ |
| `CLAWSEC_FEED_URL` | ホストアドバイザリーURL | スイートホークとガードドインストーラーの読み込み お問い合わせ
| `CLAWSEC_FEED_SIG_URL` | `<feed>.sig` | 組織図鑑 | 組織図鑑 お問い合わせ
| `CLAWSEC_FEED_CHECKSUMS_URL` | フィードURL付近の`checksums.json` | 任意チェックサムマニフェストソース お問い合わせ
| `CLAWSEC_FEED_PUBLIC_KEY` | スイートローカルPEMファイル | 特筆記検証 お問い合わせ
| `CLAWSEC_ALLOW_UNSIGNED_FEED` | `0` | 一時移行バイパスの旗 お問い合わせ
| `CLAWSEC_VERIFY_CHECKSUM_MANIFEST` | `1` | チェックサム・マニフェスト検証を有効にします。 お問い合わせ
| `CLAWSEC_HOOK_INTERVAL_SECONDS` | `300` | アドバイザリーホックスキャンスロットル お問い合わせ

## パスの決議規則
| ルール | 行動 | 施行拠点 |
| お問い合わせ |
| `~` 拡張 | 自宅のディレクトリに解決 | スイート/ウォッチドッグスクリプトで共有されたパスユーティリティ機能 お問い合わせ
| `$HOME` / `${HOME}` 拡張 | エスケープ時に解決 | 同じユーティリティ. お問い合わせ
お問い合わせ Windowsホームトークン | `%USERPROFILE%`, `$env:USERPROFILE` 正規化 | 同じユーティリティ. お問い合わせ
| エスケープされたトークン(`\$HOME`) | 明示的なエラーで拒否 | 誤ってリテラルディレクトリの作成を防止します。 お問い合わせ
| 無効な明示的なパス | 警告でデフォルトパスにフォールバックできる | `resolveConfiguredPath`ヘルパー お問い合わせ

## フロントエンドとビルド構成
- `vite.config.ts`はポート(`3000`)、ホスト(`0.0.0.0`)、パスエイリアス(`@`)を定義します。
- `index.html`の提供 Tailwind ランタイムの設定、カスタムフォント、ベースカラートークン。
- `tsconfig.json`は、バンドルモジュールの解像度、`noEmit`、およびJSXランタイムの設定を使用します。
- `eslint.config.js`はTS、React、hooks、およびスクリプト固有のlintルールを適用します。

## スキルメタデータ 仕様
| フィールドグループ | 所在地 | 機能 |
| お問い合わせ |
お問い合わせ コアスキルアイデンティティ | `skills/*/skill.json` | 名称・バージョン・著者・ライセンス・記述メタデータ お問い合わせ
| SBOMファイル一覧 | `skill.json -> sbom.files` | 決定版リリース必須項目です。 お問い合わせ
| プラットフォームメタデータ | `openclaw` または `nanoclaw` ブロック | CLI 要件、トリガー、プラットフォームヒント お問い合わせ
| スイートカタログメタデータ | `skills/clawsec-suite/skill.json -> catalog` | スイートメンバーの統合/デフォルト/一貫性のある動作 お問い合わせ

## ワークフロー構成
- スケジュール設定は、`cron`エントリー(`poll-nvd-cves`、`codeql`、`scorecard`)のワークフローに含まれています。
- リリースワークフローでは、タグのネーミングパターン`<skill>-v<semver>`が期待しています。
- 展開ワークフローは、CI/release `workflow_run`イベントとマニュアルディスパッチで起動します。
- 複合署名アクションは、秘密鍵入力を必要とし、署名直後に署名を検証します。

## サンプルスニペット
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

## 操作上の注意
- リポジトリの外にキーを署名し、GitHubの秘密を経由して注入してください。
- ローカル環境変数上書きの絶対パスまたは省略されたホーム式を優先します。
- 一時的なマイグレーション サポートとして署名されていないフィード モードを、正常な操作は扱いません。
- 壊れたアーティファクトの参照を避けるために`SKILL.md` URLを編集するとき再実行の解放リンクの検証。

## ソース参照
- vite.config.ts
- インデックス.html
- tsconfig.json
- eslint.config.js ディレクティブ
- スキル/ clawsec-suite/skill.json
- スキル/clawsec-nanoclaw/skill.json
- スキル/ clawsec-suite/hooks/clawsec-advisory-guardian/lib/utils.mjs
- スキル/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- スキル/clawsec-suite/scripts/guarded_skill_install.mjs
- スクリプト/validate-release-links.sh
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/skill-release.yml
- .github/actions/sign-and-verify/action.yml
