<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: README.md
Review status: draft
-->

# 日本語 Translation Scaffold

This file is currently a draft scaffold. Use README.md as the canonical source.

<h1 align="center">
<img src="./img/prompt-icon.svg"alt="prompt-icon" 幅="40">
ClawSec:AIエージェントのセキュリティスキルスイート
<img src="./img/prompt-icon.svg"alt="prompt-icon" 幅="40">
</h1>

<div align="center">

## 完全なセキュリティスキルスイートでOpenClaw、NanoClaw、およびヘルメスエージェントをセキュアに

<h4>AIセキュリティプラットフォーム</h4>

</div>

<div align="center">

お問い合わせ [Prompt Security Logo](./img/Black+Color.png)の特長
<img src="./public/img/mascot.png"alt="clawsec mascot" 幅="200" />

</div>
<div align="center">

ブーツ **ライブ時: [https://clawsec.prompt.security](https://clawsec.prompt.security) [https://prompt.security/clawsec](https://prompt.security/clawsec)**

[![CI](https://github.com/prompt-security/clawsec/actions/workflows/ci.yml/badge.svg)(https://github.com/prompt-security/clawsec/actions/workflows/ci.yml)
[![Deploy Pages](https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml/badge.svg)(https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml)
[![Poll NVD CVEs](https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml/badge.svg)(https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml)


</div>

お問い合わせ

## 翻訳

- Español: [README.es.md](README.es.md)
- 한국어: [README.ko.md](README.ko.md)

## 🦞 ClawSecとは?

ClawSec は、AI エージェント プラットフォームの**完全なセキュリティ スキル スイートです。 エージェントの認知アーキテクチャを迅速注入、ドリフト、悪意のある指示に対して、統一されたセキュリティ監視、完全性検証、脅威インテリジェンス保護を提供します。

## 対応プラットフォーム

- **OpenClaw**(MoltBot、Clawdbot、およびクローン) - スキルインストーラ、ファイルの完全性保護、およびセキュリティ監査とフルスイート
- **ナノクロー** - コンテナ化されたもの 諮問監視、署名検証、ファイルの整合性のためのMCPツールを使用したAppボットセキュリティ
-**Hermes** - 署名された諮問的フィード検証、アドバイザリーアウェアガード検証、決定的な検証生成、フェイルクローズド検証、ベースラインドリフト検出のためのヘルメスネイティブセキュリティスキル
-**Picoclaw** - 軽量AIゲートウェイセキュリティの姿勢は、アドバイザリーの意識、構成の漂流検出、リリースアーティファクト検証、およびオプションの別々のセルフペンテストパッケージでチェックします

##スキル機能マトリックス

お問い合わせ スキル名 | 対応プラットフォーム| 安全検証| 構成漂流 | エージェントセルフペンテスト| サプライチェーンインストール検証 |
お問い合わせ
| プレスリリース | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部
| クローム・クローブ・チェッカー | OpenClaw + clawsec スイート・インテグレーション | ノー | ノー | ノー | ノー | ノー | ノー |
| クロームフィード | OpenClaw | 有り | なし | なし | なし | 有り |
| クローム・ナンクロー | ナノクロー | 可 | 可 | 有 | 有 | 有 | 有 | 有 | 有 | 有 |
| クローム・スキャナ | オープンクロー | 有り | なし | 有り | 可 | 可 | 可 | 可 | 可 |
| クロームスイート | オープンクローラ | 有り | 有り | なし | 有り | なし | 有り | なし | なし | なし | なし | なし | なし | なし | なし | なし | なし | なし |
| プライバシーポリシー | 免責事項 | 免責事項 | 免責事項 | 免責事項 | 免責事項 | 免責事項 | 免責事項 |
| ヘルメス・アテスタンス・ガーディアン | ヘルメス | はい(アドバイザリー・フィード・検証) | はい | なし | 限定(アドバイザリー・プレッションのみ・アーティファクト・シグネチャ・プロテナンス・インストール・検証なし) |
| Openclaw-audit-watchdog | OpenClaw | ノー | ノー | ノー | ノー | ノー |
| picoclaw-security-guardian | ピッコロー | 有り | なし | 有り | 有り |
| picoclaw-self-pen-testing | ピッコロー | ノー | ノー | ノー | ノー |
| 魂を守る人 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 | 営業部 |

## コア機能

- ** レース スイート インストーラ** - 完全性検証ですべてのセキュリティ スキルのワンコマンド インストール
お問い合わせ ファイル整合性保護** - 重要なエージェントファイル(SOUL.md、IDENTITY.mdなど)のドリフト検出と自動復元
- **セキュリティアドバイザリー** - 自動NVD CVEポーリングとコミュニティの脅威インテリジェンス
- ** 絶縁 セキュリティ監査** - プロンプトインジェクションマーカーと脆弱性を検出するためにスクリプトをセルフチェック
お問い合わせ チェックサム検証** - すべてのスキルアーティファクトのSHA256チェックサム
- **健康チェック** - インストールされたすべてのスキルの自動更新と完全性検証

お問い合わせ

## ✔製品デモ

下記のアニメーションプレビューはGIF(音声なし)です。 任意のプレビューをクリックして、オーディオでフルMP4を開きます。

## デモをインストール (`clawsec-suite`)

[![Install demo animated preview](public/video/install-demo-preview.gif)(パブリック/ビデオ/インストールデモ)

直接リンク: [install-demo.mp4](public/video/install-demo.mp4)

## ドリフト検出デモ(`soul-guardian`)

[![Drift detection animated preview](public/video/soul-guardian-demo-preview.gif)(公共/ビデオ/ソウル-保護者-demo.mp4)

直接リンク: [soul-guardian-demo.mp4](public/video/soul-guardian-demo.mp4)

お問い合わせ

## すぐにスタート

##AIエージェントの###

```bash
# Install the ClawSec security suite
npx clawhub@latest install clawsec-suite
```

インストール後、スイートは次のことができます。
1。 公開されたスキルカタログからインストール可能な保護を発見
2。 署名されたチェックサムを使用してリリースの完全性を確認します
3。 アドバイザリーモニタリングとホックベースの保護フローの設定
4。 オプションのスケジュールチェックを追加

手動/ソース優先オプション:

ツイート 採用情報 https://github.com/prompt-security/clawsec/releases/latest/download/SKILL.md とインストール手順に従います。

人間のための#####

この指示をAIエージェントにコピーします。

ツイート `npx clawhub@latest install clawsec-suite`でClawSecをインストールし、生成された指示からセットアップ手順を完了します。

##シェルとOSノート

ClawSec スクリプトは以下の間に分割されます。
- クロスプラットフォーム Node/Python ツーリング (`npm run build`、hook/setup `.mjs`、`utils/*.py`)
- POSIXシェルワークフロー(`*.sh`、ほとんどの手動インストールスニペット)

Linux/macOS (`bash`/`zsh`) の場合:
- 引用されていないか二重引用された家変数を使用して下さい:`export INSTALL_ROOT="$HOME/.openclaw/skills"`
- 単一の引用符の拡張可能なvars (例えば、`'$HOME/.openclaw/skills'`を避けるため) を**しない**

Windows用(PowerShell):
- プレファーの明示的な道の建物:
- `$env:INSTALL_ROOT = Join-Path $HOME ".openclaw\\skills"`
- `node "$env:INSTALL_ROOT\\clawsec-suite\\scripts\\setup_advisory_hook.mjs"`
- POSIX `.sh`スクリプトはWSLまたはGit Bashが必要です。

トラブルシューティング:`~/.openclaw/workspace/$HOME/...`などのディレクトリが表示された場合、ホーム変数は文字通り渡されました。 絶対パスまたは非引用のホーム式を使用して再実行します。

お問い合わせ

## 🧭プラットフォーム&スイートドキュメント

詳細なプラットフォームとスイート docs は wiki モジュールで動作します。
・ナノクロー:[wiki/modules/nanoclaw-integration.md](wiki/modules/nanoclaw-integration.md)
- ヘルメス:[wiki/modules/hermes-attestation-guardian.md](wiki/modules/hermes-attestation-guardian.md)
- ピコクロー:[wiki/modules/picoclaw-security-guardian.md](wiki/modules/picoclaw-security-guardian.md)
- ピコクローセルフペンテスト: [wiki/modules/picoclaw-self-pen-testing.md](wiki/modules/picoclaw-self-pen-testing.md)の特長
- ClawSec Suite (OpenClaw): [wiki/modules/clawsec-suite.md](wiki/modules/clawsec-suite.md)
- CI/CDのパイプライン: [wiki/modules/automation-release.md](wiki/modules/automation-release.md)の特長

クイックインストールリンク:
- NanoClawは取付けます: [skills/clawsec-nanoclaw/INSTALL.md](skills/clawsec-nanoclaw/INSTALL.md)の特長
- エルメススキルパッケージ:`skills/hermes-attestation-guardian/`
- Picoclawの保護者のパッケージ:`skills/picoclaw-security-guardian/`
- ピコクローセルフペンテストパッケージ:`skills/picoclaw-self-pen-testing/`
- スイートパッケージ:`skills/clawsec-suite/`

お問い合わせ

## 安全保障アドバイザリーフィード

ClawSecは、NISTのNational Vulnerability Database(NVD)から自動ポップアップし、継続的に更新されたセキュリティアドバイザリーフィードを維持します。

## フィード URL

```bash
# Fetch latest advisories
curl -s https://clawsec.prompt.security/advisories/feed.json | jq '.advisories[] | select(.severity == "critical" or .severity == "high")'
```

キヤノンのエンドポイント:`https://clawsec.prompt.security/advisories/feed.json`
互換性ミラー(レガシー):`https://clawsec.prompt.security/releases/latest/download/feed.json`

### 監視されたキーワード

フィードの投票 CVE に関連する:
- **OpenClawプラットフォーム**: `OpenClaw`、`clawdbot`、`Moltbot`
- **ナノクロープラットフォーム**:`NanoClaw`、`WhatsApp-bot`、`baileys`
- **Picoclaw Platform**:`Picoclaw`、`picoclaw`、軽量AIゲートウェイ、MCPゲートウェイ露出
- プロンプト射出パターン
- エージェントのセキュリティ脆弱性

###exploitability コンテキスト

ClawSec は、CVE のアドバイザリーを **exploitability context** で強化し、CVSS スコアを超えて、エージェントが現実的なリスクを評価するのを支援します。 新規に分析されたアドバイザリーには以下が含まれます。

-**Exploit Evidence**: 公共の悪用が野生に存在するかどうか
- **武器の状態**: 悪用が一般的な攻撃フレームワークに統合されている場合
- **攻撃要件**:成功した搾取(ネットワークアクセス、認証、ユーザーインタラクション)に必要な前提条件
-**リスクアセスメント**:技術的重大性を悪用性と組み合わせるコンテキストリスクレベル

この機能は、エージェントが直面する脅威を理論的なリスクに優先し、よりスマートなセキュリティ決定を可能にします。

##アドバイザリー・スキーマ

**NVD CVE ** アドバイザリー:**
```json
{
  "id": "CVE-2026-XXXXX",
  "severity": "critical|high|medium|low",
  "type": "vulnerable_skill",
  "platforms": ["openclaw", "nanoclaw"],
  "title": "Short description",
  "description": "Full CVE description from NVD",
  "published": "2026-02-01T00:00:00Z",
  "cvss_score": 8.8,
  "nvd_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-XXXXX",
  "exploitability_score": "high|medium|low|unknown",
  "exploitability_rationale": "Why this CVE is or is not likely exploitable in agent deployments",
  "references": ["..."],
  "action": "Recommended remediation"
}
```

**コミュニティアドバイザリー:**
```json
{
  "id": "CLAW-2026-0042",
  "severity": "high",
  "type": "prompt_injection|vulnerable_skill|tampering_attempt",
  "platforms": ["nanoclaw"],
  "title": "Short description",
  "description": "Detailed description from issue",
  "published": "2026-02-01T00:00:00Z",
  "affected": ["skill-name@1.0.0"],
  "source": "Community Report",
  "github_issue_url": "https://github.com/.../issues/42",
  "action": "Recommended remediation"
}
```

**プラットフォーム値:**
- `"openclaw"` - OpenClaw/Clawdbot/Molt ボットのみ
- `"nanoclaw"` - ナノクローのみ
- `"hermes"` - ヘルメスのみ
- `"picoclaw"` - ピコクローのみ
- `["openclaw", "nanoclaw", "hermes", "picoclaw"]` - すべてのコアプラットフォーム
- (empty/missing) - すべてのプラットフォーム(後方互換)

お問い合わせ

## は、CI/CD パイプライン

CI/CD パイプラインの詳細は wiki モジュールページに移動しました。
- [wiki/modules/automation-release.md](wiki/modules/automation-release.md)

関連操作 docs:
- [wiki/security-signing-runbook.md](wiki/security-signing-runbook.md)
- [wiki/migration-signed-feed.md](wiki/migration-signed-feed.md)

お問い合わせ

## ️️ オフラインツール

ClawSecには ローカルスキル開発と検証のためのPythonユーティリティ。

##スキルバリデータ

必要なスキーマに対してスキルフォルダーを検証します。

```bash
python utils/validate_skill.py skills/clawsec-feed
```

チェック:
- `skill.json`が存在し、有効なJSON
- 必須フィールド(名前、バージョン、説明、著者、ライセンス)
- SBOMファイルが存在し、読みやすく
- OpenClawメタデータを適切に構造化

##スキルチェックサムジェネレーター

`checksums.json` を SHA256 のハッシュで生成します。

```bash
python utils/package_skill.py skills/clawsec-feed ./dist
```

出力:
- `checksums.json` - SHA256ハッシュの検証

お問い合わせ

## ローカル開発

### 前提条件

- Node.js 20 +
- Python 3.10+(オフラインツール用)
- 午後

### セットアップ

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

################################################################################################################################################################################################################################################################ ローカルデータを出力

```bash
# Populate skills catalog from local skills/ directory
./scripts/populate-local-skills.sh

# Populate advisory feed with real NVD CVE data
./scripts/populate-local-feed.sh --days 120

# Generate wiki llms exports from wiki/ (for local preview)
./scripts/populate-local-wiki.sh

# Direct generator entrypoint (used by predev/prebuild)
npm run gen:wiki-llms
```

注意:
- `npm run dev` と `npm run build` は自動的に wiki `llms.txt` のエクスポート (`predev`/`prebuild` のホック) を再生成します。
- `public/wiki/`は出力(ローカル+CI)を生成し、意図的に無視されます。

## ビルド

```bash
npm run build
```

お問い合わせ

## 📁 プロジェクト構造

```
├── advisories/
│   ├── feed.json                    # Main advisory feed
│   ├── feed.json.sig                # Detached signature for feed.json
│   └── feed-signing-public.pem      # Public key for feed verification
├── components/                      # React components
├── pages/                           # Route/page components
├── wiki/                            # Source-of-truth docs (synced to GitHub Wiki)
├── scripts/
│   ├── generate-wiki-llms.mjs       # wiki/*.md -> public/wiki/**/llms.txt
│   ├── populate-local-feed.sh       # Local CVE feed populator
│   ├── populate-local-skills.sh     # Local skills catalog populator
│   ├── populate-local-wiki.sh       # Local wiki llms export populator
│   ├── prepare-to-push.sh           # Local CI-style quality gate
│   ├── validate-release-links.sh    # Release link checks
│   └── release-skill.sh             # Manual skill release helper
├── skills/
│   ├── claw-release/                # 🚀 Release automation workflow skill
│   ├── clawsec-suite/               # 📦 Suite installer (skill-of-skills)
│   ├── clawsec-feed/                # 📡 Advisory feed skill
│   ├── clawsec-scanner/             # 🔍 Vulnerability scanner (deps + SAST + OpenClaw DAST)
│   ├── clawsec-nanoclaw/            # 📱 NanoClaw platform security suite
│   ├── clawsec-clawhub-checker/     # 🧪 ClawHub reputation checks
│   ├── clawtributor/                # 🤝 Community reporting skill
│   ├── hermes-attestation-guardian/ # 🛡️ Hermes attestation + drift verification
│   ├── openclaw-audit-watchdog/     # 🔭 Automated audit skill
│   ├── picoclaw-security-guardian/  # 🦐 Picoclaw posture/advisory/drift/supply-chain checks
│   ├── picoclaw-self-pen-testing/   # 🧪 Picoclaw self-pen-testing checks (separate package)
│   └── soul-guardian/               # 👻 File integrity skill
├── utils/
│   ├── package_skill.py             # Skill packager utility
│   └── validate_skill.py            # Skill validator utility
├── .github/workflows/
│   ├── ci.yml                       # Cross-platform lint/type/build + tests
│   ├── pages-verify.yml             # PR-only pages build/signing verification
│   ├── poll-nvd-cves.yml            # CVE polling pipeline
│   ├── community-advisory.yml       # Approved issue -> advisory PR
│   ├── skill-release.yml            # Skill release/signing pipeline
│   ├── deploy-pages.yml             # GitHub Pages deployment
│   ├── wiki-sync.yml                # Sync repo wiki/ to GitHub Wiki
│   ├── codeql.yml                   # CodeQL security analysis
│   └── scorecard.yml                # OpenSSF Scorecard checks
└── public/                          # Static assets + generated wiki exports
```

お問い合わせ

## 社会貢献

寄付を歓迎します! ガイドラインの[CONTRIBUTING.md](CONTRIBUTING.md)をご覧ください。

### 提出セキュリティアドバイザリー

迅速な注射ベクトル、悪意のあるスキル、またはセキュリティ脆弱性を発見しましたか? GitHub の問題で報告する:

1。 **セキュリティインシデントレポート**テンプレートを使用して新しい問題を開きます
2。 必須項目を記入(重度、種類、説明、影響を受けたスキル)
3。 メンテナーが`advisory-approved`ラベルを見直し、追加します
4。 アドバイザリーが`CLAW-{YEAR}-{ISSUE#}`としてフィードに自動的に公開されます

詳細は[CONTRIBUTING.md](CONTRIBUTING.md#submitting-security-advisories)をご覧ください。

##新規スキルの追加

1。 `skills/`でスキルフォルダを作成する
2。 必要なメタデータとSBOMで`skill.json`を追加
3。 エージェント読み取り可能な指示で`SKILL.md`を追加
4. `python utils/validate_skill.py skills/your-skill`と検証
5。 レビューのPRを提出する

## ドキュメント 真実のソース

すべてのwikiコンテンツについては、このリポジトリの`wiki/`でファイルを編集します。 GitHub Wiki (`<repo>.wiki.git`) は、`main` が `.github/workflows/wiki-sync.yml` から `wiki/**` が `main` で変更されたときに、`.github/workflows/wiki-sync.yml` から同期されます。

LLM エクスポートは `wiki/` から `public/wiki/` に生成されます。
- `/wiki/llms.txt` は `wiki/INDEX.md` の LLM-ready エクスポート (または `INDEX.md` が見つからない場合は生成されたフォールバックインデックス) です。
- `/wiki/<page>/llms.txt`は、その単一のwikiページのためのLM-readyエクスポートです。

お問い合わせ

## ライセンス

- ソースコード:GNU AGPL v3.0以降 - 詳細は[LICENSE](LICENSE)を参照してください。
- `font/`のフォント: ライセンス別 - [`font/README.md`](font/README.md) をご覧ください。

お問い合わせ

<div align="center">

**ClawSec**・Prompt Security、SentinelOne **

    エージェントのワークフローを強化し、一度に1つのスキル。

</div>
