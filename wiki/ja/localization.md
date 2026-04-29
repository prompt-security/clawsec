<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: ../localization.md
Review status: draft
-->

# ローカリゼーションワークフロー

## 目的
ClawSec README および wiki ページのリピート可能な docs ローカリゼーション パイプラインを定義します。

## スコープ
- ソース言語:英語(`README.md`、`wiki/*.md`)
- 現在の翻訳言語:スペイン語(`README.es.md`、`wiki/es/*.md`)
- 韓国の試験言語:韓国(`README.ko.md`、`wiki/ko/*.md`)
- 将来の言語:`wiki/<lang>/...`と`README.<lang>.md`

## 真実のルールのソース
1。 英語のファイルは正式です。
2. 翻訳は、コマンド、ファイルパス、コードブロック、および識別子を正確に保存する必要があります。
3。 商品名と技術名は翻訳されていないまま(`ClawSec`、`OpenClaw`、`NanoClaw`、`Hermes`、`Picoclaw`、スキルパッケージ名)。
4。 翻訳のカバレッジが部分的である場合、翻訳されたファイルは明示的にスコープを記述する必要があります。

## フォルダー コンベンション
- README 翻訳:
- `README.es.md`
- 未来:`README.fr.md`、`README.de.md`、`README.ja.md`、等。
- ウィキ翻訳:
- `wiki/es/INDEX.md`
- `wiki/es/<page>.md`
- 未来:`wiki/fr/<page>.md`、`wiki/de/<page>.md`、等。
- ローカリゼーションアセット:
- `wiki/i18n/terminology-en-es.md`
- `wiki/i18n/translation-tracker.md`

## ワークフローの更新
1。 **ソースコードの初期化* * 必須
- 翻訳前の明確さと構造のための英語ソースのドキュメントを更新します。
2。 **Record delta **
- `wiki/i18n/translation-tracker.md`で英語ページを変更しました。
3. **Translate changed pages**
- マークダウン構造と見出しレベルを維持します。
- コマンドブロックを無接触に保ちます。
4. **QA pass**
- リンクが解決することを確認します。
- コードブロックとインラインコマンドの検証は変更されません。
- `terminology-en-es.md`を使用した用語集の一貫性を確認します。
5. **Regenerate exports**
- `npm run gen:wiki-llms`を実行します。
6. **Review and PR**
- 翻訳されたページの要約と残りのギャップを含みます。

## 翻訳 QA チェックリスト
- [ ] 階層を保持する。
- [ ] コマンドスニペットは変更され、実行できません。
- [ ] ファイルパスとURLは変更されません。
- [ ] スキルとプラットフォーム名が変更されていない。
- [ ]セキュリティ用語の一貫性。
- [ ] `wiki/INDEX.md`は翻訳リンクエントリを持っています。
- [ ] `wiki/<lang>/INDEX.md`は、翻訳されていないときに重要な英語ページに戻ります。

## おすすめ言語ロールアウト
1。 スペイン語(`es`) - フェーズ1ベースラインで行われます。
2. フランス(`fr`)、ドイツ(`de`)、幅広い技術聴衆のための。
3. 高度のプラットホームの文書のための日本語(`ja`)。

## ソース参照
- README.mdの
- README.es.mdの
- wiki/INDEX.md(ウィキ・インデックス)
- wiki/es/INDEX.md(ウィキ・エス・インデックス)
- wiki/es/overview.md
