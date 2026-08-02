<p align="center">
  <img src="./assets/readme/hero.webp" width="100%" alt="ClawSec ロボットと Prompt Security, from SentinelOne のロゴを配した、AI エージェント向け ClawSec セキュリティスキルの紹介画像">
</p>

<p align="center">
  <a href="https://clawsec.prompt.security"><strong>ウェブサイト</strong></a>
  ·
  <a href="https://clawsec.prompt.security/skills"><strong>スキルカタログ</strong></a>
  ·
  <a href="https://clawsec.prompt.security/feed"><strong>セキュリティフィード</strong></a>
  ·
  <a href="./wiki/INDEX.md"><strong>ドキュメント</strong></a>
  ·
  <a href="https://github.com/prompt-security/clawsec/releases"><strong>リリース</strong></a>
</p>

<p align="center">
  <a href="https://github.com/prompt-security/clawsec/actions/workflows/ci.yml"><img src="https://github.com/prompt-security/clawsec/actions/workflows/ci.yml/badge.svg" alt="CI ステータス"></a>
  <a href="https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml"><img src="https://github.com/prompt-security/clawsec/actions/workflows/deploy-pages.yml/badge.svg" alt="Pages デプロイステータス"></a>
  <a href="https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml"><img src="https://github.com/prompt-security/clawsec/actions/workflows/poll-nvd-cves.yml/badge.svg" alt="NVD ポーリングステータス"></a>
</p>

ClawSec は、AI エージェントランタイム向けのセキュリティスキルと署名済みアドバイザリーインテリジェンスをまとめた、AGPL ライセンスのコレクションです。**OpenClaw、NanoClaw、Hermes、Picoclaw** を対象に、スキルアーティファクトの検証、設定ドリフトの検出、エージェント環境の監査、リスクのあるインストールの承認制御を支援します。

---

## OpenClaw スイートをインストールする

OpenClaw のエントリーポイントは `clawsec-suite` です。パッケージの追加と永続フックの有効化は、個別に確認できる別々の手順です。

### 1. スイートを追加する

```bash
npx skills add prompt-security/clawsec --skill clawsec-suite -a openclaw -y
```

このコマンドは、署名済みアドバイザリーのトラストセット、ハートビートワークフロー、ガード付きインストーラー、セットアップスクリプトを含むスイートをインストールします。オプションの保護機能は別パッケージのままで、スイートが公開カタログから検出します。

### 2. アドバイザリーフックを確認して有効化する

```bash
SUITE_DIR="${INSTALL_ROOT:-$HOME/.openclaw/skills}/clawsec-suite"
node "$SUITE_DIR/scripts/setup_advisory_hook.mjs"
```

セットアップスクリプトは、OpenClaw の永続設定を変更する前にプリフライト内容を表示します。正常に完了したら OpenClaw ゲートウェイを再起動し、`/new` を一度実行して最初のアドバイザリースキャンを開始してください。

現在利用できるオプション保護を確認するには、次を実行します。

```bash
node "$SUITE_DIR/scripts/discover_skill_catalog.mjs"
```

> **ほかの人の環境にインストールする場合：** その人のエージェントに、上記のコマンドで `clawsec-suite` をインストールしてフックのプリフライトを提示し、フックまたはオプションの cron ジョブを有効化する前に承認を待つよう依頼してください。

<details>
<summary><strong>シェルとパスに関する注意</strong></summary>

`bash` と `zsh` では、ホーム変数を展開できる状態にしてください。

```bash
export INSTALL_ROOT="$HOME/.openclaw/skills"
```

`$HOME` を含むパスをシングルクォートで囲まないでください。PowerShell では、パスを明示的に組み立てます。

```powershell
$env:INSTALL_ROOT = Join-Path $HOME ".openclaw\skills"
node "$env:INSTALL_ROOT\clawsec-suite\scripts\setup_advisory_hook.mjs"
```

Windows で POSIX `.sh` ワークフローを実行するには、WSL または Git Bash が必要です。

</details>

---

## 動作を見る

### エージェントファイルのドリフトを検出して対処する

`soul-guardian` のデモでは、保護対象のエージェントファイルを変更し、不一致を検出して、対応手順を確認できます。

[![ClawSec soul-guardian ドリフト検出デモ](public/video/soul-guardian-demo-preview.gif)](public/video/soul-guardian-demo.mp4)

**[音声付き MP4 を見る →](public/video/soul-guardian-demo.mp4)**

<details>
<summary><strong>スイートのインストール手順を見る</strong></summary>

<p align="center">
  <a href="./public/video/install-demo.mp4"><img src="./public/video/install-demo-preview.gif" width="320" alt="ClawSec スイートのインストール手順"></a>
</p>

<p align="center"><a href="./public/video/install-demo.mp4"><strong>音声付き MP4 を開く →</strong></a></p>

</details>

---

## ClawSec がエージェントを保護する仕組み

| 保護レイヤー | 役割 |
| --- | --- |
| **署名済みインテリジェンス** | 公開済みのリスクをインストール済みスキルと照合する前に、アドバイザリーフィードとチェックサムマニフェストを検証します。 |
| **ガード付きインストール** | アドバイザリーに一致すると停止し、リスクのあるインストールを続行する前に、明示的な確認をもう一度求めます。 |
| **完全性とドリフト** | プラットフォーム別スキルに、重要ファイル、設定、アテステーション、リリースアーティファクトのベースラインを提供します。 |
| **監査とレポート** | 各プラットフォームの仕様で対応する範囲に限り、監査、セキュリティ態勢、セルフテスト、コミュニティ報告に特化したパッケージを提供します。 |

ClawSec はアクションを推奨し、承認ゲートを設けます。破壊的な削除とインストールのオーバーライドには、引き続き承認が必要です。

### プラットフォーム別のエントリーポイント

- **OpenClaw** — 署名済みアドバイザリーの監視とガード付きインストールには、まず [`clawsec-suite`](skills/clawsec-suite/) を使用し、その後、別パッケージとして提供されるドリフト保護と監査機能をカタログから確認します。
- **NanoClaw** — NanoClaw 固有のアドバイザリー、完全性、検証、セキュリティツールのワークフローには [`clawsec-nanoclaw`](skills/clawsec-nanoclaw/) を使用します。
- **Hermes** — 署名済みアドバイザリーチェック、ガード付き検証、決定論的アテステーション、ベースラインドリフト検出には [`hermes-attestation-guardian`](skills/hermes-attestation-guardian/) を使用します。
- **Picoclaw** — セキュリティ態勢、アドバイザリー、ドリフト、リリースアーティファクトのチェックには [`picoclaw-security-guardian`](skills/picoclaw-security-guardian/) を使用します。[セルフペンテスト](skills/picoclaw-self-pen-testing/) は、別途有効化するオプションパッケージです。

> `*-traffic-guardian` ディレクトリは、プラットフォーム実装者向けの仕様ベースラインです。現時点で実行時プロキシとして提供されているものではありません。

すべてのパッケージは、**[公開スキルカタログ](https://clawsec.prompt.security/skills)** またはリポジトリの **[`skills/` ディレクトリ](skills/)** で確認できます。

---

## 署名済みアドバイザリーチャネルを照会する

統合フィードには、関連する NVD CVE、承認済みコミュニティレポート、まだ CVE 識別子がない暫定 GitHub アドバイザリーが含まれる場合があります。

```bash
curl -fsSL https://clawsec.prompt.security/advisories/feed.json \
  | jq '.advisories[] | select(.severity == "critical" or .severity == "high")'
```

トラスト情報はフィードと同じ場所にあります。

- [アドバイザリーフィード](advisories/feed.json)
- [分離フィード署名](advisories/feed.json.sig)
- [固定済み Ed25519 公開鍵](advisories/feed-signing-public.pem)
- [署名と検証のランブック](wiki/security-signing-runbook.md)

従来の `/releases/latest/download/feed.json` エンドポイントは、互換性ミラーとして引き続き利用できます。新しい利用者は、正規の `/advisories/feed.json` エンドポイントを使用してください。

---

## ビルド、テスト、コントリビューション

ウェブカタログをローカルで実行します。

```bash
npm install
npm run dev
```

プッシュ前に、リポジトリのローカル品質ゲートを実行します。

```bash
./scripts/prepare-to-push.sh
```

スキルパッケージを直接検証します。

```bash
python utils/validate_skill.py skills/clawsec-feed
```

まず、次の資料を参照してください。

- [アーキテクチャ](wiki/architecture.md)
- [プラットフォーム検証](wiki/platform-verification.md)
- [テスト](wiki/testing.md)
- [リリース自動化](wiki/modules/automation-release.md)
- [コントリビューションガイド](CONTRIBUTING.md)
- [セキュリティポリシー](SECURITY.md)

プロジェクトドキュメントの信頼できる情報源は [`wiki/`](wiki/) です。GitHub Wiki ページと LLM 向けエクスポートは、これらのファイルから生成されます。

---

## 翻訳

[English](README.md)
· [Deutsch](README.de.md)
· [Español](README.es.md)
· [Français](README.fr.md)
· **日本語**
· [한국어](README.ko.md)

各言語の wiki インデックス：[DE](wiki/de/INDEX.md) · [ES](wiki/es/INDEX.md) · [FR](wiki/fr/INDEX.md) · [JA](wiki/ja/INDEX.md) · [KO](wiki/ko/INDEX.md) · [EN](wiki/INDEX.md)

---

## ライセンス

ClawSec のソースコードは **GNU AGPL-3.0-or-later** の下でライセンスされています。詳細は [LICENSE](LICENSE) を参照してください。[`font/`](font/) 配下のファイルには別のライセンス条件が適用され、README のアートワークでは使用していません。

<p align="center">
  <strong>ClawSec</strong> · Prompt Security, from SentinelOne<br>
  エージェントが信頼する前に検証を。
</p>
