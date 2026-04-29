<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: ../remediation-plan.md
Review status: draft
-->

# クロスプラットフォームの修復計画

ツイート フェーズ1:リスク閉鎖の即時化(完了)

##マイルストーン
- 高リスクランタイム/インストールパスで明示的なホームパス拡張+疑わしいトークン拒否を実行します。
- パスの拡張とエスケープトケン拒否のための回帰テストを追加します。
- `.gitattributes` LFポリシーを追加します。
- Node lint/type/build CI のカバレッジを Linux/macOS/Windows に拡張します。
- シェル固有のガイダンスとリテラル`$HOME`のトラブルシューティングでインストールドキュメントを更新します。

## アウトカム
- `$HOME`パス伝搬のバグをソースで解決
- コアアドバイザリー/インストールパスコンフィグが無効なパストークンで高速に失敗しました。

お問い合わせ

ツイート フェーズ2:批判的ワークフローのためのWindowsのパリティ(次)

### クイック勝利
- パワーを追加 最も使用されるマニュアルのインストール/チェックコマンドのシェルの同等物:
- `skills/clawsec-suite/SKILL.md`
- `skills/openclaw-audit-watchdog/SKILL.md`
- `README.md`
- 欠けているツールを検出し、OS固有のインストールのヒントを印刷するために、軽量`scripts/preflight.mjs`を追加します。

##マイルストーン
- ネイティブパワー スイートのセットアップとアドバイザリーのホックのためのシェルの指示。
- シェルスクリプトが無効なWSL/Git Bashフォールバックが文書化されました。

お問い合わせ

ツイート フェーズ3:POSIXを削減 貝の表面(Deeper Refactor)

##Refactor ターゲット
- `scripts/populate-local-feed.sh`
- `scripts/populate-local-skills.sh`
- `scripts/release-skill.sh`

### アプローチ
- `jq/sed/awk/find/chmod`パイプラインの依存性を除去するためにNode/Pythonで再実装重要なパス。
- 後方互換性のためのシェルラッパーを保存します。新しいクロスプラットフォームの実装へのルート。

##マイグレーションノート
- 古いスクリプトのエントリは、少なくとも1つのマイナーリリースのラッパーとして設定します。
- 正確なマイグレーションコマンドで非推奨警告を省略します。

お問い合わせ

ツイート フェーズ4:CIの堅くなり、主張する検証

##マイルストーン
- ノード行列(Linux/macOS/Windows)を必須チェックとして保持します。
- パスの処理を取付けるための対象となるWindowsの煙テストを加えて下さい。
- 関連するOpenSSLコマンドの互換性メモのmacOSチェックを追加します。

郵便番号 テスト戦略
- ローカル:
- ノードテストスイートを実行し、パスの拡張/抑制/インストール動作をカバーします。
- 変更されたスクリプトの構文チェックを実行します。
- CI:
- マトリックスノードは+ガードドインストーラ/抑制/パステストをチェックします。
- Linuxのみのセキュリティスキャンは残っていますが、明示的にLinux-scopedとしてマークされています。

お問い合わせ

##ロールアウト/リリース検討

- - - このパッチセットで導入されたインターフェイスの変更を破らない; 動作は無効/未公開のパストークンのみ厳格です。
- リリースノートで通信:
- パストークンの検証が強化されました
- 無効な引用符 env 値を修正する方法
- パワー シェル例ライブ

## ソース参照
- .gitattributesの
- .github/workflows/ci.yml
- スクリプト/populate-local-feed.sh
- スクリプト/populate-local-skills.sh
- スクリプト/リリース-skill.sh
- スキル/クローセスイート/ホック/クローセ-アドバイザー/ハンドラー.ts
- スキル/clawsec-suite/scripts/guarded_skill_install.mjs
- スキル/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- wiki/platform-verification.md の
