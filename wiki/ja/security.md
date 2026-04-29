<!-- AUTO-GENERATED TRANSLATION SCAFFOLD (ja)
Source: ../security.md
Review status: draft
-->

ツイート セキュリティ

##セキュリティモデルの概要
- ClawSec は、コンテンツの配布 (署名されたアーティファクト) とランタイムの動作 (管理者のゲート、完全性監視) の両方を保護します。
- Trust アンカーは、リポジトリにコミットし、ワークフロー生成された出力に対して検証された公開鍵をピン留めします。
- Runtime 消費者は、明示的なマイグレーションバイパスフラグを使用して、検証優先動作にデフォルトでデフォルトで設定します。

## 暗号化制御
| 制御 | 機構 | 位置 |
| お問い合わせ |
お問い合わせ フィード認証 | Ed25519 は署名を取り外す (`feed.json.sig`) | アドバイザリーワークフロー + 消費者検証ライブラリ お問い合わせ
| アーティファクトの完全性 | SHA-256チェックサムマニフェスト(`checksums.json`) | スキルリリースとページ展開ワークフロー お問い合わせ
お問い合わせ 鍵の一貫性 | ドキュメント全体の指紋比較 + 正式PEM | `scripts/ci/verify_signing_key_consistency.sh`. お問い合わせ
| シグネチャー検証アクション | CIでのコンポジットサイン+検証アクション | `.github/actions/sign-and-verify/action.yml` お問い合わせ

#ランタイムの執行制御
| 制御 | コンポーネント | 効果 |
| お問い合わせ |
| アドバイザリーホークギャティング | `clawsec-advisory-guardian` | マッチングアドバイザリーに基づく注意・注意深い指導 お問い合わせ
| ダブルカンファレンスインストーラー | `guarded_skill_install.mjs` | `42`を終了 マッチングアドバイザリーの明示的な確認まで お問い合わせ
| 評判の延長 | `clawsec-clawhub-checker` | インストール前の追加リスクスコアリング お問い合わせ
| ナノクローシグネチャーゲート | `skill-signature-handler.ts` + MCPツール | ブロック改ざん・荷役パッケージをポリシーでインストールします。 お問い合わせ
| 整合性ベースラインモニター | `soul-guardian` + NanoClaw 整合性モニター | ドリフト検知・検疫・復元・監査可能な履歴 お問い合わせ

## サプライチェーンとCIコントロール
- CI実行 トリビー、npm 監査、CodeQL、およびスコアカードワークフロー。
- `gitleaks`がインストールされているときにローカルプレパスチェックが`gitleaks detect`を実行できます。
- リリースワークフローは、パッケージの前にSBOMファイルの存在を検証します。
- ワークフローをデプロイすると、生成された署名キーフィンガープリントをキャノンキー素材に対して検証します。
- リリースドキュメントには、ダウンストリームの消費者向けの手動検証コマンドが含まれます。

## インシデントとローテーションの Playbooks
- `wiki/security-signing-runbook.md`は、キー生成、クラスト、回転、およびインシデントフェーズを定義します。
- `wiki/migration-signed-feed.md`は段階的な執行およびロールバックのレベルを定義します。
- ロールバックパスは、署名された公開を優先順位付けし、可能かつ任意のバイパスをタイムボックス化します。

## サンプルスニペット
```bash
# verify canonical public key fingerprint
openssl pkey -pubin -in clawsec-signing-public.pem -outform DER | shasum -a 256
```

```bash
# run repo key-consistency guardrail used in CI
./scripts/ci/verify_signing_key_consistency.sh
```

#既知のセキュリティトレードオフ
- 符号なしの互換性モードは保証を減らすことができ、移行が完了したら無効にする必要があります。
- バックワードの互換性のために署名されていないレガシーチェックサムアセットを許容するパスをいくつかデプロイします。
- 評判は外的な工具細工の出力に依存し、ヒューリスティック偽陽性/負を含むかもしれません。
- ローカルスクリプトは、環境の信頼を継承します。 侵害されたローカルシェルは、オペレータのワークフローをサブバートできます。

## 困難な機会
- 移行の安定化後に署名されていない互換性フラグを削除します。
- すべてのミラーリングされた解放ファイルのための決定的なチェックサム/signatureの確認を拡大して下さい。
- ワークフローレベルのシグネチャー障害シナリオに明示的なテストを追加します。
- アドバイザリー・フェッチ/検証の失敗に対するランタイムテレメトリーを増加させ、インシデント・トライを簡素化します。

## 更新ノート
- 2026-02-26: `docs/`ファイルをroot `wiki/`の操作ページ専用の署名とマイグレーションの参照をリセットしました。

## ソース参照
- セキュリティ.md
- wiki/security-signing-runbook.md
- wiki/migration-signed-feed.md
- スクリプト/ci/verify_signing_key_consistency.sh
- .github/actions/sign-and-verify/action.yml
- .github/workflows/poll-nvd-cves.yml
- .github/workflows/community-advisory.yml
- .github/workflows/skill-release.yml
- .github/workflows/deploy-pages.yml
- スキル/ clawsec-suite/hooks/clawsec-advisory-guardian/lib/feed.mjs
- スキル/clawsec-suite/scripts/guarded_skill_install.mjs
- スキル/clawsec-clawhub-checker/scripts/enhanced_guarded_install.mjs
- スキル/ロシア語/スクリプト/soul_guardian.py
- スキル/ clawsec-nanoclaw/host-services/skill-signature-handler.ts
- スキル/クローセ・ナンクロー/ガーディアン/積分僧侶。ts
