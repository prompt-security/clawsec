<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: ../platform-verification.md
Review status: draft
-->

# プラットフォーム検証チェックリスト

このチェックリストを使用して、変更後のポータビリティとパス処理の動作を検証します。

## Linux 検証

1。 コアノードのテストを実行します。
   ```bash
   node skills/clawsec-suite/test/path_resolution.test.mjs
   node skills/clawsec-suite/test/guarded_install.test.mjs
   node skills/clawsec-suite/test/advisory_suppression.test.mjs
   node skills/openclaw-audit-watchdog/test/suppression_config.test.mjs
   ```
期待:すべてのテストパス。

2。 `$HOME`パスの受け入れを検証しません。
   ```bash
   CLAWSEC_LOCAL_FEED='\$HOME/advisories/feed.json' \
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
期待:`Unexpanded home token`エラーでゼロを終了します。

3. `$HOME`の拡張機能を検証:
   ```bash
   HOME=/tmp/clawsec-home node skills/clawsec-suite/test/path_resolution.test.mjs
   ```
期待:`$HOME`拡張テストパス

# macOS 検証

1。 Linux と同じ Node テスト スイートを実行します。
2。 OpenSSLツーリングパスの仮定が文書化されていることを確認します。
- LibreSSL/OpenSSL のバリエーションを使用する場合は、docs からテストされたコマンドフォームを使用することを確認してください。
3。 設定パスでチルドの拡張を確認します。
   ```bash
   OPENCLAW_AUDIT_CONFIG=~/.openclaw/security-audit.json \
   node skills/openclaw-audit-watchdog/scripts/load_suppression_config.mjs --enable-suppressions
   ```
期待される: パスは正しく解決します (または拡張された場所での明確なファイルではなく、エラー)。

## Windowsの検証(PowerShell)

1。 ノードテストを実行します。
   ```powershell
   node skills/clawsec-suite/test/path_resolution.test.mjs
   node skills/clawsec-suite/test/guarded_install.test.mjs
   node skills/clawsec-suite/test/advisory_suppression.test.mjs
   ```
期待:すべてのパス。

2。 電力を検証 Shell env パス拡張動作:
   ```powershell
   $env:CLAWSEC_LOCAL_FEED = '$env:USERPROFILE\advisories\feed.json'
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
期待: パストークンが展開/正規化されるか、ターゲットファイルが不足している場合、クリアエラーで失敗します。

3。 エスケープされたリテラルトークン拒否を確認します。
   ```powershell
   $env:CLAWSEC_LOCAL_FEED = '\$HOME\advisories\feed.json'
   node skills/clawsec-suite/scripts/guarded_skill_install.mjs --skill test-skill --dry-run
   ```
期待: `Unexpanded home token` のエラー、Liteal `$HOME` のディレクトリ作成なし。

ツイート ライン・エンド・サンティ

1。 LFポリシーの提示を確認する:
   ```bash
   test -f .gitattributes && grep -n "eol=lf" .gitattributes
   ```
期待:スクリプト/コンフィグファイルパターンはLFを強制します。

2。 CRLF-prone のチェックアウト後、スクリプトは引き続き解析します。
   ```bash
   bash -n scripts/populate-local-feed.sh
   bash -n scripts/populate-local-skills.sh
   ```
期待される:`^M`のshbang/parseの間違い無し。

## Explicit Bug Check: 文字無し `$HOME` ディレクトリ作成

1。 リテラル/エスケープされたトークンを持つパスを設定します。
2。 セットアップ/インストールコマンドを実行します。
3。 コマンドがトークンエラーで初期に失敗することを確認します。
4. `$HOME` のセグメントディレクトリは、作業ディレクトリで作成されていないことを確認します。

期待される結果:**Liteal `$HOME` を含むディレクトリはサポートされたセットアップスクリプトによって作成されます。 メニュー

## ソース参照
- .gitattributesの
- スクリプト/populate-local-feed.sh
- スクリプト/populate-local-skills.sh
- スキル/clawsec-suite/test/path_resolution.test.mjs
- スキル/ clawsec-suite/test/guarded_install.test.mjs
- スキル/ clawsec-suite/test/advisory_suppression.test.mjs
- スキル/clawsec-suite/scripts/guarded_skill_install.mjs
- スキル/openclaw-audit-watchdog/scripts/load_suppression_config.mjs
- スキル/openclaw-audit-watchdog/test/suppression_config.test.mjs
