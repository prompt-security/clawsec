<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: ../security-signing-runbook.md
Review status: draft
-->

# ClawSec 署名操作 Runbook

> 参照実装: `clawsec-suite`（OpenClawスイート）

ツイート 1) 目的

この runbook は、ClawSec リポジトリに暗号署名を導入および実行するための運用手順を定義します。

それはカバーします:
- キー生成
- GitHubの秘密管理
- ワークフローの統合の署名
- キーの回転およびrevocation
- インシデント対応

ツイート 2) 現在の作動状態(重要)

`main`では、アドバイザリーおよびリリースチャネルは、デフォルトで署名および検証されています。

- フィードライター:
- `.github/workflows/poll-nvd-cves.yml`は`advisories/feed.json`を更新し、`advisories/feed.json.sig`に署名します
- `.github/workflows/community-advisory.yml`は承認された問題のレポートのために同じことをします
- 署名されたフィードアーティファクトを`skills/clawsec-feed/advisories/`に同期する
- フィード公開パス:
- `.github/workflows/deploy-pages.yml`公開 `public/advisories/feed.json` + `.sig`の特長
- `public/checksums.json` + `public/checksums.sig`を生成し、署名します
- `public/signing-public.pem`および`public/advisories/feed-signing-public.pem`としてcanonicalキーを出版して下さい
- `public/releases/latest/download/`(`feed.json`、`feed.json.sig`、`checksums.json`、`checksums.sig`、`signing-public.pem`を含む)に基づく互換性のアーティファクトをミラーリング
- 供給の消費者:
- `skills/clawsec-suite/hooks/clawsec-advisory-guardian/handler.ts`
- `skills/clawsec-suite/scripts/guarded_skill_install.mjs`
- `skills/clawsec-nanoclaw/lib/advisories.ts`
- デフォルトのフィードURLは`https://clawsec.prompt.security/advisories/feed.json`です

符号なしモードは、明示的な互換性バイパス(`CLAWSEC_ALLOW_UNSIGNED_FEED=1`)のままであり、安定した状態の動作モデルではありません。

ツイート 3) ターゲット署名されたアーティファクト

##アドバイザリーフィードチャネル
- `advisories/feed.json` (ペイロード)
- `advisories/feed.json.sig`(Ed25519署名を取り外す)
- `advisories/feed-signing-public.pem`(ピンキー公開)

################################################################################################################################################################################################################################################################ リリースアーティファクトチャンネル
- `<release>/signing-public.pem`
- `<release>/signing-public.pem`
- `<release>/signing-public.pem`

ツイート 4) 主な役割およびcustody

- **セキュリティ所有者**:重要なライフサイクルの変更とインシデントアクションを承認します。
- **プラットフォーム所有者**:ワークフローとGitHubの秘密を保持します。
-**Reviewer**:PR /リリースで指紋を検証します。

ポリシー:
- 秘密鍵は決して約束しません
- 公開鍵はコミットされ、コードレビューされます
- 信頼できるオペレータのワークステーションかHSM支えられた環境で主生成は起こります

ツイート 5)キー生成(Ed25519)

ツイート 安全なワークステーションから実行します。 共有CIランナーで実行しないでください。

```bash
# Feed signing keypair
openssl genpkey -algorithm Ed25519 -out feed-signing-private.pem
openssl pkey -in feed-signing-private.pem -pubout -out feed-signing-public.pem

# Release checksums signing keypair (optional separate key)
openssl genpkey -algorithm Ed25519 -out release-signing-private.pem
openssl pkey -in release-signing-private.pem -pubout -out release-signing-public.pem
```

指紋の生成(チケット/変更記録の保存):

```bash
openssl pkey -pubin -in feed-signing-public.pem -outform DER | shasum -a 256
openssl pkey -pubin -in release-signing-public.pem -outform DER | shasum -a 256
```

出版前の任意テスト署名:

```bash
echo '{"probe":"ok"}' > /tmp/probe.json
openssl pkeyutl -sign -rawin -inkey feed-signing-private.pem -in /tmp/probe.json -out /tmp/probe.sig.bin
openssl base64 -A -in /tmp/probe.sig.bin -out /tmp/probe.sig
openssl base64 -d -A -in /tmp/probe.sig -out /tmp/probe.sig.bin
openssl pkeyutl -verify -rawin -pubin -inkey feed-signing-public.pem -in /tmp/probe.json -sigfile /tmp/probe.sig.bin
```

ツイート 6) GitHubの秘密のセットアップ

郵便番号 必須の秘密

- `CLAWSEC_SIGNING_PRIVATE_KEY` — PEMエンコードEd25519プライベートキー(フィードとリリース署名の両方に使用されます)
- プライベートキーが暗号化されている場合、`CLAWSEC_SIGNING_PRIVATE_KEY_PASSPHRASE` — (オプション) パスフレーズ

### 手順

1。 [Repo 設定] → [秘密と変数] → [アクション] → [新しいリポジトリ] に移動します。
2. ヘッダー/フッターを含む完全なPEMを貼って下さい。
3。 プリファー GitHub **環境の秘密** (必要な査読者と) 可能な場合のワークフロースキャッピング。
4。 レコード変更チケット:
- 秘密名
- クリエイター
- 制作時間
- 主指紋

################################################################################################################################################################################################################################################################ 推奨環境保護

- 署名の秘密を使用できるワークフローの手動承認が必要です。
- 保護されたワークフローを編集できる制限
- `main`のブランチ保護を有効にし、ワークフロー変更のレビューが必要です。

ツイート 7) ワークフロー統合ポイント

このリポジトリは、ポスト・ミュテーション、事前公開制御として署名を強制します。

## フィードパイプライン

現在の供給の変異ポイント:
- `.github/workflows/community-advisory.yml`
- `advisories/feed.json`

現在の動作:
- ワークフローステップは`advisories/feed.json`を`advisories/feed.json.sig`に署名します
- アクションの署名は、ワークフローの実行中に生成された署名を検証します
- 署名されたアーティファクトはPRのオートメーションによって託されます

郵便番号 ページパイプライン

現在のパブリッシャー:
- `public/advisories/`

現在の動作:
- `public/advisories/`にペイロード/署名をコピー
- `public/checksums.json`と`public/checksums.sig`を生成します
- `public/signing-public.pem`と`public/advisories/feed-signing-public.pem`への署名キーを公開
- アドバイザリー+シグネチャ/チェックサム/キーコンパニオンを`public/releases/latest/download/`互換パスにミラーリング

################################################################################################################################################################################################################################################################ スキルリリースパイプライン(推奨硬化)

現在の解放の発電機:
- `checksums.json`

現在の動作:
- `checksums.json` を作成し、`checksums.sig` に署名し、公開する前に署名を検証します。
- リリースアセットに`signing-public.pem`が含まれています
- 生成された公開鍵の指紋を正規キー素材に対して検証

ツイート 8) 回転ポリシーとランブック

## 回転アカデミー
- ルーチン:90日ごとに(または厳格なorgポリシー)。
- 即時:疑わしい暴露、不正なワークフロー変更、または明示されていない署名不一致。

## ルーチン回転ステップ

1。 新しいキーペアを生成します。
2。 パブリックキーファイルと指紋のドキュメントを更新するPRを開きます。
3。 GitHub シークレットとして新しい秘密鍵を追加します。
4。 新しいキーを使用するワークフローの変更をマージします。
5。 最新のフィード/リリースマニフェストを再署名します。
6。 CI および外部クライアントの検証を検証します。
7。 古い秘密鍵を削除します。
8。 過去の公開鍵の参照は、履歴検証に必要な限りのみ保持します。

## 取消ステップ

1。 妥協されたキーを使用してワークフローを無効にします。
2. 承認されたGitHubの秘密を削除します。
3。 取消しメモと公開鍵をコミットします。
4。 交換キーで最新のアーティファクトを再署名します。
5。 タイムスタンプとインパクトのあるウィンドウでインシデントアドバイザリーを発行します。

ツイート 9) インシデント応答 Playbook(署名固有の)

## トリガー
- 新規公開フィード/リリースのシグネチャ検証が失敗
- 未知のコミット/ワークフローは署名パスに触れる編集します
- 漏れたキー素材、誤ったロギング、または疑わしいシークレットアクセス

###重度ガイド
-**SEV-1**:鍵の浸入確認または悪意のある署名されたペイロードが公開
- **SEV-2**:未知の原因で検証障害
- **SEV-3**: 手続き非遵守、活動的な妥協無し

郵便番号 応答フェーズ

1。 **条件* * 必須
- ワークフローの署名/公開を一時停止
- 認証が未認証の場合、さらなるフィードマージをブロック
2. **調査**
- ワークフローの実行ログのレビュー
- `.github/workflows/`、`advisories/`、および主要なファイルに影響を与える検討のコミット
- ファースト・ベイド・タイムスタンプおよび影響を受けたアーティファクトを決定する
3。 **取引**
- 回転/回転調整キー(s)
- 既知のコミットから信頼できるアーティファクトを復元する
4。 **回復**
- 再署名のアーティファクト
- redeployページ/リリース
- 独立したクライアントチェックで確認
5。 **郵便番号* * 必須
- タイムラインと修正要約を公開
- 制御をきつく締めて下さい(眺めのゲート、保護された環境、秘密の規模)

#10 監査証拠チェックリスト

各リリースサイクルまたはフィード署名実行の場合、以下を保持します。
- ワークフロー実行 URL とコミット SHA
- 使用中のサイダーのキー指紋
- 検証結果ログ
- オペレータ/査読者の承認
- 例外かバイパスの合理

#11) 厳格なポリシー変更前の最小受け入れ基準

ポリシーをさらに締める前に(例えば、互換性バイパスパスのパスを削除):
- 署名されたアーティファクトは少なくとも2週のために一貫して作り出されます
- パイプラインミラーのシグネチャーコンをデプロイする
- 1つのロールバックのドリルおよび1つの主回転ドリルは首尾よく完了しました
- インシデント対応のオンコールオーナーが特定および文書化

## ソース参照
- アドバイザリー/フィード.json
- アドバイザリー/フィード.json.sig
- アドバイザリー/フィード署名-public.pem
- clawsec-signing-public.pem
- .github/actions/sign-and-verify/action.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/skill-release.yml
- スクリプト/ci/verify_signing_key_consistency.sh
- wiki/migration-signed-feed.md
