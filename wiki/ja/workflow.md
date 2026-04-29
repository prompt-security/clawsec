<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: ../workflow.md
Review status: draft
-->

# ワークフロー

## エンドツーエンドのライフサイクル
- 開発は、ローカルコーディング+ローカルデータ人口と現実的なUIプレビューから始まります。
- PR CI は、品質/セキュリティとスキルテストスイートを検証します。
- PR Pages-verifyは、公開せずに生産ビルド/署名の動作を検証します。
- タグ主導のリリースワークフローパッケージとスキルアーティファクトの署名。
- ページは、ワークフローミラーのリリース/アドバイザーのアーティファクトをデプロイし、静的なサイトを公開します。
- Wiki-sync ワークフローでは、`wiki/` のドキュメントを GitHub Wiki に公開しています。
- スケジュールされたワークフローは、アドバイザリーフィードとサプライチェーンの可視性を継続的に強化します。

## 第一次ワークフローマップ
| ワークフロー | トリガー | 主な工程 |
| お問い合わせ |
| CI | PR/push to `main` | リント、タイプチェック、ビルド、Pythonチェック、セキュリティスキャン、スキルテスト。 お問い合わせ
お問い合わせ ページの検証 | `main`へのPR | ページのアーティファクトを構築し、サインアウトプットを検証 (公開なし). お問い合わせ
| 有料NVD CVE | 日頃のcron + マニュアルディスパッチ | フェッチCVE、トランス/デプス、アップデートフィード、サインアーティファクト、PR変更。 お問い合わせ
| プロセスコミュニティアドバイザリー | 課題ラベル `advisory-approved` | 課題フォーム | 課題フォーム | 諮問・署名フィードの作成・広報オープン・コメント問題 お問い合わせ
| スキルリリース | スキルタグ+メタデータPR変更 | PR: バージョン・パーティー + ドライランチェック、タグ: パッケージ・サイン・公開リリースアセット お問い合わせ
| 展開ページ | CI/Release/手動ディスパッチの成功 | リリース、ミラーアセットの発見、パブリックアドバイザリー/チェックサムの署名、展開サイト お問い合わせ
| シンクウィキ | `main` に `wiki/**` に触れる `wiki/` を `<repo>.wiki.git` に同期し、 `INDEX.md` から `Home.md` を生成します。 お問い合わせ

## ローカルオペレーターワークフロー
| ステップ | コマンド | アウトカム |
| お問い合わせ |
| デプス設置 | `npm install` | 既読のローカル環境 お問い合わせ
| ローカルカタログ | `./scripts/populate-local-skills.sh` | `public/skills/index.json` とファイルチェックサムの人口 お問い合わせ
| ローカルフィード | `./scripts/populate-local-feed.sh --days 120` | ローカルアドバイザリーフィードのコピーを更新しました。 お問い合わせ
| wiki llms のエクスポートを生成する | `npm run gen:wiki-llms` | `public/wiki/llms.txt` とページごとのエクスポートを更新します。 お問い合わせ
| ローカルゲートを走らせて下さい | `./scripts/prepare-to-push.sh` | CIのようなパス/fail信号。 お問い合わせ
| 開発UIスタート | `npm run dev` | ローカルViteエンドポイントでのブラウザプレビュー お問い合わせ

ツイート リリースワークフローの詳細
- PR/tag パスでは、バージョン バンプと docs のパシティが強化されます。
- スキルパッケージには、SBOM-declaredファイルと完全性マニフェストが含まれています。
- `checksums.json`は署名され、ワークフローの実行ですぐに検証されます。
- 設定されたとき、GitHubリリースの成功後、オプションのpublish-to-ClawHubジョブが実行されます。
- 同じ主要なライン内の古いリリースは、自動化によって監督/削除することができます。

## 諮問ワークフローの詳細
- NVDワークフローは、以前のフィード`updated`タイムスタンプから増分ウィンドウを決定します。
- フェーズマップCVEメトリックを重症/タイプに変換し、影響を受けたターゲットを正規化します。
- コミュニティアドバイザリーワークフローは、問題メタデータから決定的なID(`CLAW-YYYY-NNNN`)を作成します。
- アドバイザリーワークフローは、スキルフィードコピーと署名者を更新します。

## サンプルスニペット
```bash
# manual release prep for a skill
./scripts/release-skill.sh clawsec-feed 0.0.5
# then push tag if running in release branch mode
```

```yaml
# pages deploy depends on successful upstream workflow run
on:
  workflow_run:
    workflows: ["CI", "Skill Release"]
    types: [completed]
```

##運用リスク
- ワークフロー権限と秘密のスコープの不正設定は、署名/公開をブロックできます。
- NVD/API の一時的な失敗はアドバイザリーの新鮮さを遅らせるかもしれません。
- Invalidタグのネーミングやバージョンのミスマッチのハレットリリース自動化。
- オペレータ機械が予想されるバイナリ(`jq`、`openssl`、`clawhub`)を欠いているかどうか、ローカルスクリプトとCIは掘り下げることができます。

## ソース参照
- スクリプト/リリース-skill.sh
- スクリプト/prepare-to-push.sh
- スクリプト/populate-local-feed.sh
- スクリプト/populate-local-skills.sh
- スクリプト/generate-wiki-llms.mjs
- .github/workflows/ci.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml
- .github/workflows/deploy-pages.yml
- .github/workflows/pages-verify.yml
- .github/workflows/wiki-sync.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/actions/sign-and-verify/action.yml
