<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: ../glossary.md
Review status: draft
-->

ツイート 用語集

## 利用規約
| 用語 | 定義 |
| お問い合わせ |
| アドバイザリーフィード | スキル/プラットフォームのセキュリティアドバイザリーを含むJSON文書(`feed.json`) お問い合わせ
| `skill@1.2.3`、ワイルドカード、マッチングロジックで使用される範囲などのスキルセレクター お問い合わせ
| ガードド インストール | アドバイザーが一致したときに明示的な確認を必要とする2段階のインストーラーの動作。 お問い合わせ
| SBOMファイル | 包装・検証に用いられる`skill.json`における技術実証済みのアーティファクトリスト お問い合わせ
| 別売のシグネチャー | ベース64 署名ファイル(`.sig`)は、署名されたペイロードから別途保存されます。 お問い合わせ
| チェックサムマニフェスト | ペイロードの完全性を検証するために使用されるファイルハッシュマップ(`checksums.json`) お問い合わせ

## スキル包装条件
| 用語 | 定義 |
| お問い合わせ |
| スキルタグ | リリース自動化で使われる`<skill>-v<semver>`としてフォーマットされたGitタグ。 お問い合わせ
| リリースアセット | GitHub リリースに添付されているファイル(zip、`skill.json`、チェックサム、シグネチャ) お問い合わせ
| カタログのインデックス | `public/skills/index.json`, ウェブカタログで消費される生成リスト お問い合わせ
| 組込み部品 | 別々に含まれている1つのスキルからの機能束(例えばスイートで埋め込まれる供給のために)。 お問い合わせ

## 諮問とセキュリティ規約
| 用語 | 定義 |
| お問い合わせ |
| フェイルクローズド検証 | 署名またはチェックサム検証が失敗した場合のペイロードを差し込みます。 お問い合わせ
| 符号なしの互換性モード | `CLAWSEC_ALLOW_UNSIGNED_FEED=1`で有効な一時的なバイパスパスパス お問い合わせ
| Suppression Rule | 既知の知的/受容性の調査を抑制する`checkId`および`skill`のエントリーマッチングの設定 お問い合わせ
| キー指紋 | キーの一貫性の点検に使用する DER によって符号化される公共のキーの SHA-256 の消化器。 お問い合わせ

##ランタイムとプラットフォーム利用規約
| 用語 | 定義 |
| お問い合わせ |
| OpenClaw Hook | アドバイザリーをチェックするランタイムイベントハンドラ(`clawsec-advisory-guardian`) お問い合わせ
| NanoClaw IPC | 諮問のリフレッシュ、シグネチャ検証、整合性チェックのためのホスト/コンテーナータスク交換 お問い合わせ
| 完全性ベースライン | 保護されたファイルのための承認されたハッシュ/スナップショットを保存しました。 お問い合わせ
| ハッシュチェーン監査ログ | 各エントリーが事前のハッシュに依存する監査ログのみを表示 お問い合わせ

## CI/CD 利用規約
| 用語 | 定義 |
| お問い合わせ |
| NVD CVEs ワークフロー | NVD CVEs をアドバイザリーに送出・変換するワークフローをスケジュール お問い合わせ
| コミュニティ・アドバイザリーワークフロー | 認定コミュニティ・アドバイザリーを発行する課題・ラベル・トリガーワークフロー お問い合わせ
| スキル・リリースワークフロー | スキル・リリース・ワークフロー | タグ・トリガー・パッケージ・署名・出版 パイプライン お問い合わせ
| ページワークフローの展開 | サイトアセットをビルドするワークフローと、リリース/アドバイザーアーティファクトをミラーリングするワークフロー お問い合わせ

## ソース参照
- タイプ。ts
- スキル/ clawsec-suite/skill.json
- スキル/clawsec-nanoclaw/skill.json
- スキル/clawsec-suite/scripts/guarded_skill_install.mjs
- スキル/ clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs
- スキル/ clawsec-suite/hooks/clawsec-advisory-guardian/lib/suppression.mjs
- スキル/クローセ・ナンクロー/ガーディアン/積分僧侶。ts
- スクリプト/populate-local-feed.sh
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml
- .github/workflows/deploy-pages.yml
