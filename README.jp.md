# SecuLens

[English](README.md) | [日本語](README.jp.md)

SecuLensはTypeScriptで実装したセキュリティ評価CLI・ライブラリです。SPDXとCycloneDXのSBOMを読み込み、コンポーネントのバージョンをOSVの脆弱性情報と独自に照合します。ライセンスポリシーの評価、JavaScript／TypeScriptのAST解析、顧客提出用Wordレポートの生成にも対応します。

**0.3.1は初期リリースです。** 検出結果は確認のための根拠であり、安全性や法令遵守を保証するものではありません。[独立したPython実装](https://github.com/masahiroid/seculens-python)も公開しています。[独立したPHP実装](https://github.com/masahiroid/seculens-php)も公開しています。

## インストール

Node.js 22以降とnpmが必要です。

```sh
npm install -g seculens
seculens --help
```

配布アーカイブは[GitHub Releases](https://github.com/masahiroid/seculens/releases)からも取得できます。

## 対話ウィザード

引数なしで起動すると設定ウィザードが始まります。既定の言語は英語です。言語選択でEnterを押すと英語、`ja`を入力すると日本語になり、選択した言語をWordレポートにも使います。

```sh
seculens
# 日本語で直接開始
seculens wizard --lang ja
```

既存SBOMの検査またはSBOM生成を選び、パスとオプションを入力します。検査ではローカルOSVデータベースまたはOSVからの取得、任意のライセンスポリシーとソースフォルダー、顧客名・対象名・作成者、レポート形式、出力先、検出時の終了方針を設定します。ウィザードでは顧客提出用レポートが既定です。

最後に設定を確認して開始します。入力終了（EOF）や最後の確認で`n`を選ぶと中止し、Ctrl+Cでも中断できます。OSVへ送信する情報は実行前に表示します。相対パスは現在の作業フォルダーを基準に指定してください。従来の`scan`／`sbom`コマンドも使えます。

## 既存SBOMの検査

保存済みOSV JSONデータベースによるオフライン検査：

```sh
seculens scan sbom.json --db database.json --policy policy.json \
  --customer 'サンプル顧客' --lang ja --output reports
```

脆弱性情報の候補を取得し、ローカルで照合：

```sh
seculens scan sbom.json --fetch-osv --policy policy.json --output reports
```

`--fetch-osv`はパッケージ名とエコシステムを`api.osv.dev`に送信します。バージョンの照合はSecuLens内で行います。ソースコードやSBOM全体は送信しません。このモードにはネットワーク接続が必要で、通信失敗時は検査を停止します。`--db`モードではネットワーク接続を使いません。

検査ごとに`report.json`、`report.docx`、元の`sbom.json`、`database.json`を保存します。レポートにはSBOMとデータベースのSHA-256ハッシュを記録し、根拠を保存・再利用できます。同じスナップショットで照合結果を再現できますが、レポートの日時とDOCXのメタデータは異なる場合があります。

## SBOMの生成

依存関係をインストール済みのnpmプロジェクト：

```sh
seculens sbom ./my-project --format cyclonedx --output sbom.json
seculens sbom ./my-project --format spdx --output sbom.spdx.json
```

既存の`npm sbom`を呼び出し、インストールスクリプトは実行しません。`npm sbom`に対応したnpmが必要です。Python、PHP、コンテナーなどは既存のツールでSBOMを生成して読み込んでください。

## JS／TSソース解析

```sh
seculens scan sbom.json --db database.json --source ./src --output reports
```

直接の`eval`、`new Function`、`innerHTML`／`outerHTML`への代入、循環的複雑度が10を超える関数、ネスト深度が4を超える関数を確認候補として検出します。`&&`、`||`、`??`も複雑度に加算し、入れ子の関数は個別に測定します。構文エラーは解析範囲の不足として記録します。生成物フォルダーとシンボリックリンクはスキップします。

構文に基づく確認候補です。この版には関数間データフロー解析、型に基づく呼び出し解決、悪用可能性の判定、Python／PHPのAST解析はありません。同名のローカル変数などによる誤検出や、未検出の危険な構文があり得ます。

## ライセンスポリシー

```json
{
  "allow": ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC"],
  "deny": ["AGPL-3.0-only", "AGPL-3.0-or-later"]
}
```

SPDX式を構造的に解析します。`AND`は全分岐の許可、`OR`はいずれかの選択肢の許可が必要です。`WITH`例外は式全体を明示的に許可してください。不明・独自・未記載のライセンスは要確認です。宣言されたライセンスとソースの一致、配布義務、顧客の実際の利用方法は検証しません。ポリシー未指定の場合は全ライセンスを要確認とします。

## 対応入力と照合範囲

- SPDX 2.2／2.3 JSONのパッケージ情報。
- CycloneDX 1.4〜1.7 JSONのコンポーネント・依存関係情報。
- npm：SemVer。
- PyPI：PEP 440。パッケージ名を正規化します。
- Packagist：安定版の数値SemVer互換バージョン、先頭の`v`、末尾が`.0`の4桁バージョン、SemVerプレリリース。Composerのブランチ別名、4桁目が0以外の形式、その他のComposer固有形式は未評価です。
- OSVの`SEMVER`／`ECOSYSTEM`範囲、明示的な影響バージョン、修正版・最終影響版・上限の境界、撤回済み情報。同一の脆弱性を指す別名はコンポーネントごとに統合します。GIT範囲のみの情報は未評価です。

対応Package URL（`pkg:npm`、`pkg:pypi`、`pkg:composer`）とバージョンが必要です。他のエコシステムは未評価として記録します。SecuLensが使う入力項目を検証しますが、規格全体への適合検証ではありません。SPDX 3、XML、暗号学的な証明の検証、顧客固有のリスク優先順位付け、ソースからのライセンス探索、インフラ設定監査は未対応です。

「一致なし」は指定データベースに一致する情報がないという意味で、安全を保証しません。必要な情報を含むスナップショットを用意してください。データベースの完全性や、脆弱なコードへの到達可能性は証明しません。

## 終了コード

- `0`：解析範囲の不足なく検査完了。確認対象が残っている場合があります。
- `1`：`--fail-on-findings`指定時に、影響する脆弱性、拒否ライセンス、セキュリティ確認候補を検出。
- `2`：入力不正、実行エラー、解析範囲の不足。`--fail-on-findings`指定時は検出による終了コード1が優先されます。

詳細はJSONレポートを確認してください。Wordは既定で英語です。`--lang ja`で主要な見出しと要約を日本語化します。脆弱性情報の本文や技術的注記には元の言語が残ります。

## ライブラリAPI

```ts
import { scanSbom, validateDatabase, writeWordReport } from "seculens";

const records = validateDatabase(databaseJson);
const report = scanSbom(sbomText, records, {
  customer: "サンプル顧客",
  policy: { allow: ["MIT", "Apache-2.0"] },
});
await writeWordReport(report, "report.docx", "ja");
```

## 顧客提出用レポート

`--report-style customer`で、表紙、要約、重大度の色分け、優先順の検出一覧、番号付き詳細、コンポーネントの評価範囲表、根拠ハッシュ、ページ番号を含むWordレポートを生成します。標準形式は`--report-style standard`で指定できます。コマンド直接実行では標準形式が既定です。

```sh
seculens scan bom.json --db database.json --policy policy.json \
  --customer "顧客企業" --target "顧客Webサービス" \
  --issuer "セキュリティ評価チーム" --lang ja \
  --report-style customer --output reports/customer
```

`--target`は対象システム名で、未指定時はSBOMのファイル名です。`--issuer`は表紙の作成者・文書の著者です。両方とも省略できます。レポートIDにはSBOMハッシュ、DBハッシュ、評価日時を使います。検出番号で一覧と詳細を対応させ、コード・ライセンスの確認状態と脆弱性の重大度を分けて表示します。

重大度の色はCritical／Highが赤、Mediumが黄、Lowが青、Noneが緑、Unratedが灰色です。色に加えてラベルも表示します。脆弱性の件数はコンポーネントごとに別名を統合し、カテゴリ別件数には確認候補も含めます。CVSSの0点／Noneは重大度の区分であり、脆弱性がないことの証明ではありません。

重大度は検証済みCVSS 3.0／3.1基本ベクトルまたは認識可能な`database_specific.severity`に基づきます。パッケージ固有のOSV `affected.severity`は、その影響エントリーの全体ベクトルより優先します。別名統合時には根拠を保存し、対応する重大度のうち最も高いものを表示します。情報源で評価が異なる場合もラベル・ベクトル・スコアをJSONに残します。CVSS 2／4や不正なベクトルは計算せず、他に使える情報がなければUnratedです。本文、AST確認候補、ライセンスから重大度を推測しません。

JSONスキーマ1.1には任意の`severity`（重大度、任意の基本スコア、情報源ID・フィールドパス・元の値）とCLIの`sourceAnalysis`実行情報を追加しています。表示用の並び替えで評価JSONは変更しません。Wordには重大度の根拠を簡潔に表示し、元のメタデータと参照先はJSONに保存します。このモードは表示形式と重大度の根拠を追加するもので、脆弱性の照合条件は変えません。

参照：[CVSS 3.1仕様](https://www.first.org/cvss/v3.1/specification-document)、[OSVスキーマ](https://ossf.github.io/osv-schema/)。

```js
await writeWordReport(report, "customer.docx", "ja", {
  style: "customer",
  issuer: "評価チーム",
});
```

## 開発

```sh
npm ci
npm test
npm pack
```

[設計とロードマップ](docs/architecture.md)、[セキュリティポリシー](SECURITY.md)も参照してください。

## ライセンス

Apache-2.0です。TrivyおよびSECULENSという名称の光学レンズ企業とは独立したプロジェクトです。脆弱性情報には各情報源のライセンスが適用され、ソフトウェアのライセンスが取得したデータベースにも適用されるとは限りません。

日本語WordレポートにはNoto Sans JP（SIL OFL 1.1）を埋め込みます。表示環境による文字の違いを抑えるため、レポート容量は約4 MB増えます。
