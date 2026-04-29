<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: ../testing.md
Review status: draft
-->

# テスト

## テスト戦略
- - - リポジトリは、単一のルート`npm test`コマンドではなくレイヤ認証を使用します。
- 中心の信任はlint/type/buildのゲートと巧みなローカルから来ます ノードテストスイート。
- Python とシェルツーリングは、専用の lint/security チェックで検証されます。
- ワークフローパイプラインは、ローカルプリパスオートメーションで使用される同じコマンドクラスを実行します。

## 検証レイヤー
| レイヤー | コマンド | スコープ |
| お問い合わせ |
| フロントエンド/静的チェック | ESLint + `tsc --noEmit` + `npm run build` | TS/TSX の正しさと生存性の構築 お問い合わせ
| スキルユニットテスト | `node skills/<skill>/test/*.test.mjs` | 署名・マッチング・抑制・インストーラー契約 お問い合わせ
| Pythonの品質 | `ruff check utils/`、`bandit -r utils/ -ll` | ユーティリティの正確性とセキュリティのパターン お問い合わせ
| シェル/スクリプトの品質 | ShellCheck + 手動スクリプトスモーク実行 | スクリプト衛生とコマンドの堅牢性。 お問い合わせ
| CIセキュリティスキャン | トライビー、npm監査、CodeQL、スコアカード | 依存性、構成、およびサプライチェーンのセキュリティ姿勢。 お問い合わせ
| ローカルプレパスセキュリティスキャン | `scripts/prepare-to-push.sh`経由のオプション`gitleaks detect` | プッシュ前のシークレットリーク検出 お問い合わせ

##スキルテストマトリックス
| スキル | テストファイル | プライマリフォーカス |
| お問い合わせ |
| `clawsec-suite` | `feed_verification`、`guarded_install`、`path_resolution`、ファズテスト | 署名チェック、アドバイザリーギャング、パスセーフティ、マッチング堅牢性 お問い合わせ
| `openclaw-audit-watchdog` | 抑制設定・レンダリングテスト | 解析・抑制動作の設定、レポートのフォーマット お問い合わせ
| `clawsec-clawhub-checker` | `reputation_check.test.mjs` | 入力検証と評判のゲーミング動作. お問い合わせ

## CIワークフローカバレッジ
| ワークフロー | トリガー | 主旨 お問い合わせ
| お問い合わせ |
| `ci.yml` | PR/push to `main` | リント/タイプ/ビルド、Pythonチェック、セキュリティスキャン、スキルテスト お問い合わせ
| `codeql.yml` | PR/push/schedule | JS/TS 静的セキュリティ解析 お問い合わせ
| `scorecard.yml` | スケジュール・出演 | サプライチェーン姿勢報告・SARIFアップロード お問い合わせ
| `skill-release.yml` | タグ + 広報 | 版画・リリースアーティファクト検証 お問い合わせ

## ローカルテストコマンド
```bash
# baseline frontend + config checks
npx eslint . --ext .ts,.tsx,.js,.jsx,.mjs --max-warnings 0
npx tsc --noEmit
npm run build
```

```bash
# representative skill tests
node skills/clawsec-suite/test/feed_verification.test.mjs
node skills/clawsec-suite/test/guarded_install.test.mjs
node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
```

## 時計の失敗パターン
- 署名/テストフィクスチャーは、予想されたファイルが意図的に再生されると、キー/ペイロードの不一致から失敗することができます。
- エスケープされたホームトークンに意図的に失敗するパスレゾリューションテスト。この動作は期待され、セキュリティ関連性があります。
- `openclaw`または`clawhub`バイナリに依存するローカルスクリプトは、それらのCLIが存在しない環境で失敗する可能性があります。
- デプロイ/リリース ロジックは、秘密やワークフローのパーミッションが異なる場合、CIで失敗したときにローカルに渡すことができます。

## 推奨テスト注文
1. 完全なローカル ゲートのための `./scripts/prepare-to-push.sh` を実行して下さい。
2。 直接影響を受けたスキルローカルテストを実行します。
3。 フィード/署名変更のため、スイート検証テストを最初に実行します(`feed_verification`、`guarded_install`)。
4。 ワークフローやリリースの変更については、`scripts/validate-release-links.sh`とキーの一貫性スクリプトを実行します。

## 更新ノート
- 2026-02-26: 移行された`wiki/platform-verification.md`チェックリストにソースの参照を更新しました。

## ソース参照
- AGENTS.mdの
- スクリプト/prepare-to-push.sh
- スクリプト/validate-release-links.sh
- .github/workflows/ci.yml
- .github/workflows/codeql.yml
- .github/workflows/scorecard.yml
- .github/workflows/skill-release.yml
- スキル/clawsec-suite/test/feed_verification.test.mjs
- スキル/ clawsec-suite/test/guarded_install.test.mjs
- スキル/clawsec-suite/test/path_resolution.test.mjs
- スキル/openclaw-audit-watchdog/test/suppression_config.test.mjs
- スキル/clawsec-clawhub-checker/test/reputation_check.test.mjs
- wiki/platform-verification.md の
