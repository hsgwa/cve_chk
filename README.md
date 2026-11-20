# vuln-triage

オフライン環境（AWS EC2 / EMR / Lambda、Linux、Windows）から回収したインベントリと、会社公表の脆弱性リスト（Excel）を突き合わせて、**通達1件ごとに各環境の「影響あり / 影響なし / 未使用 / 対象外 / 判定不能」**と社内ランク・対応期限を出すツールです。

```
[オフライン Linux]   collect_linux.sh（syft を呼ぶ） → out/<ホスト名>/cdx_syft.json, os_info.json
[オフライン Windows] collect_win.ps1（スクリプトのみ）→ out/<ホスト名>/inventory.json
          │  フォルダごと回収
          ▼
[管理 PC（ネット接続あり）] vuln-triage run → report.xlsx / CSV
```

設計の経緯と詳細は [docs/PLAN.md](docs/PLAN.md) にあります。

## 1. セットアップ（管理 PC）

Python 3.10 以降が必要です。

```
pip install -e .
```

CVE の照合には [Trivy](https://github.com/aquasecurity/trivy/releases) を使います。Windows 用の zip を展開し、`trivy.exe` のあるフォルダを PATH に追加するか、`config.yaml` の `trivy.path` に場所を書いてください。初回実行時に Trivy が脆弱性データベースを自動でダウンロードします。

動作確認（Trivy 無しでも、保存済みの結果を使って実行できます）:

```
vuln-triage run --inventory-dir examples/inventory --env-master examples/env_master.csv ^
  --advisory examples/advisory_list.xlsx --trivy-results-dir examples/trivy_fixtures ^
  --cache-dir examples/cache --offline --base-date 2026-11-20 --out-dir out
```

## 2. 回収（オフライン環境）

### Linux（EC2、EMR の各ノード）

持ち込むもの: `collectors/collect_linux.sh` と、[syft](https://github.com/anchore/syft/releases) の `syft_<版>_linux_amd64.tar.gz`（Graviton なら `linux_arm64`）。同じフォルダに置いて実行します。

```
sudo bash collect_linux.sh
```

- `out/<ホスト名>/` に `cdx_syft.json`（SBOM）、`os_info.json`、`collect.log` ができます。
- root で実行しないと、読めないフォルダの中身が漏れます。
- NFS などネットワーク上の領域と、コンテナの保存領域は走査しません。
- 走査範囲や除外は環境変数で変えられます（スクリプト冒頭のコメントを参照）。
- EMR はクラスタが動いているうちに、マスター 1 台とコア 1 台で実行してください。

### Windows

持ち込むもの: `collectors/collect_win.ps1` だけです（exe は不要）。管理者として開いた PowerShell で実行します。

```
powershell -ExecutionPolicy Bypass -File collect_win.ps1
powershell -ExecutionPolicy Bypass -File collect_win.ps1 -ScanRoots 'D:\apps','E:\hulft'
powershell -ExecutionPolicy Bypass -File collect_win.ps1 -AllDrives
```

- `out\<ホスト名>\` に `inventory.json` と `collect.log` ができます。
- 既定の走査対象は `Program Files`、`Program Files (x86)`、`ProgramData` です。**アプリを別の場所に置いている場合は `-ScanRoots` で指定するか `-AllDrives` を付けてください。**
- 取得するもの: OS のビルド番号、適用済み KB、インストール済みソフト、exe / dll のバージョン情報、jar / war / ear の中身（入れ子も）、Python・npm・NuGet のパッケージ、実行中のプロセスの場所。

### HULFT / DataMagic などの商用ソフト

パッケージ管理の外に置かれる製品は、両スクリプト冒頭の「個別製品の版取得」の表で扱います。初期状態では **名前で探して「存在する（版不明）」と記録するだけ**なので、判定は「影響あり（比較不能）」になります。版まで取るには、実機で版が分かるコマンドかファイルを確認し、表に 1 行足してください（記入例がコメントで入っています）。Windows でインストーラを使って入れた製品は、レジストリから版が取れます。

### Lambda

実行環境の中ではスクリプトを動かせません。デプロイ用 zip を展開したフォルダに対して Linux 上で `SCAN_ROOT=<展開先> bash collect_linux.sh` を実行するか、Amazon Inspector の SBOM エクスポート（CycloneDX）を環境フォルダに置いてください。

### 回収後

`out/<ホスト名>/` をフォルダごと管理 PC にコピーし、次のように並べます。フォルダ名が「環境名」になります。

```
inventory/
  web-ec2/      cdx_syft.json  os_info.json
  batch-emr/    cdx_syft.json  os_info.json
  win-app01/    inventory.json
```

CycloneDX JSON（syft、Amazon Inspector など）、`winget export`、`Get-HotFix | ConvertTo-Json`、`VersionInfo` の JSON を単体で置いても読み込みます。

## 3. 入力ファイル

### 環境マスタ `env_master.csv`

```
env_name,exposure,system_name
web-ec2,internet,受発注Web
batch-emr,internal,分析基盤
```

`exposure` は `internet`（外部公開）か `internal`（社内限定）。未登録の環境は `internal` として扱い、サマリで警告します。

### 会社公表リスト（`.xlsx` / `.xlsm` / `.csv`）

会社の Excel をそのまま渡せます。見出しの対応は `config.yaml` の `advisory_input.columns` に書きます（シート名、見出し行の位置、結合セルの扱いも設定できます）。

| 項目 | 内容 |
|---|---|
| `advisory_id` | 通達番号 |
| `cve_id` | CVE 番号。1 セルに複数あれば CVE ごとに判定 |
| `product_name` | 製品名。下記参照 |
| `affected_version` | 影響バージョンの条件。下記参照 |
| `published_date` | 公表日。対応期限の起点 |
| `company_rank` / `deadline_days` | 社内ランクと期限日数。書かれていれば最優先 |
| `note` | 備考 |

1 行の書き方は次の 3 通りです。

| 種類 | 書き方 | 判定方法 |
|---|---|---|
| CVE 指定 | `cve_id` を書く。`product_name` と `affected_version` も書くと精度が上がる | Trivy。Windows OS の CVE は OS のビルド番号 |
| 製品名＋版 | `product_name` と `affected_version`（例 `>=2.0.0,<2.17.1`、`<=3.0.12`、`9.0.*`） | 回収データの名前と版を直接比較 |
| Windows パッチ | `product_name` に KB 番号、`affected_version` に `missing`。`KB5034441\|KB5035845` と書くと、どれか適用済みなら可 | 適用済み KB の一覧 |

- **版の条件は Excel で「文字列」として入力してください。** 数値セルに `9.0` と入れると `9` として保存されます。
- 製品名は大文字小文字と区切り文字（空白、`_`、`.`、`-`）の違いを無視して完全一致で照合します。`Apache Tomcat*` のようなワイルドカード、`re:^HULFT\d` のような正規表現も使えます。呼び名が違う場合は `config.yaml` の `aliases` に登録します。
- **CVE だけで製品名が無い行は、「未使用」と「影響なし」を区別できません**（「影響なし（CVE未検出）」と表示）。できるだけ製品名も書いてください。

## 4. 実行

```
vuln-triage check-inputs --inventory-dir inventory --env-master env_master.csv --advisory 通達.xlsx
vuln-triage run          --inventory-dir inventory --env-master env_master.csv --advisory 通達.xlsx --out-dir out
```

`check-inputs` は判定をせず、回収データの読み込み結果と、通達の製品名が回収データのどれに当たったかを表示します。**新しい通達を取り込んだら、まずこれで「該当なし」が表記ゆれでないかを確認してください。**

主なオプション（`vuln-triage run --help` で全件）:

| オプション | 内容 |
|---|---|
| `--only-advisory` | 会社公表リストにある脆弱性だけを出力する |
| `--base-date YYYY-MM-DD` | 実行日として扱う日付 |
| `--skip-trivy` | Trivy を使わない（CVE だけの通達は「判定不能」） |
| `--save-trivy-json DIR` | Trivy の生の結果を証跡として保存 |
| `--trivy-results-dir DIR` | 保存済みの Trivy 結果で再判定 |
| `--no-msrc` / `--offline` | Windows OS のビルド番号判定を行わない / キャッシュだけで行う |
| `--resolve-hashes` | 名前の分からない jar を SHA-1 で Maven Central に照会 |

## 5. 出力

`out/report.xlsx` のシート:

| シート | 内容 |
|---|---|
| サマリ | 件数の集計、注意事項、この結果の限界 |
| 通達別一覧 | 1 行 = 通達 1 件。総合判定と、影響あり / 影響なし / 未使用 / 対象外 / 判定不能の環境名 |
| 通達×環境 | 行 = 通達、列 = 環境の一覧表 |
| 明細 | 1 行 = 通達 × 環境 × パッケージ。影響なし・未使用も含む全件（証跡） |
| 新規検出（参考） | 通達には無いが Trivy が検出した脆弱性 |
| 収集状況 | 環境ごとの回収日時、回収ファイル、読めなかったフォルダ、走査範囲外で動いているプログラム |

同じ内容の CSV（BOM 付き UTF-8）も `report_summary.csv`、`report_detail.csv`、`report_new_findings.csv` として出ます。

### 影響有無の意味

| 値 | 意味 |
|---|---|
| 影響あり | Trivy が検出、または製品の版が条件に該当、または KB 未適用 |
| 影響あり（比較不能） | 製品はあるが版を比較できない（安全側の判定） |
| 影響なし | 製品はあるが、版が条件の外／修正済み／KB 適用済み |
| 影響なし（CVE未検出） | CVE だけの通達で Trivy が検出しなかった（未使用との区別は不可） |
| 未使用 | その製品が回収データに存在しない |
| 対象外 | Windows 向けの通達に対する Linux 環境など |
| 判定不能 | 判定に必要なデータを回収できていない |

### 社内ランクと対応期限

通達にランク・日数が書かれていればそれを使い、無ければ CVSS v3 と公開区分から決めます（`config.yaml` の `rank_matrix`）。

| CVSS v3 | internet | internal |
|---|---|---|
| 9.0 以上 | Rank-S（3 日） | Rank-A（14 日） |
| 7.0 以上 | Rank-A（14 日） | Rank-B（30 日） |
| 4.0 以上 | Rank-B（30 日） | Rank-C（90 日） |
| 4.0 未満・不明 | Rank-C（90 日） | Rank-C（90 日） |

対応期限は **公表日（無ければ実行日）＋日数** です。過ぎている場合は備考に「期限超過」と出ます。

## 6. この結果の限界

「未使用」「影響なし」は**回収できた範囲での結果**です。詳細は [docs/PLAN.md](docs/PLAN.md) の「限界」を参照してください。

- **対象外**: コンテナの中身、Lambda の実行環境そのもの、AWS マネージドサービス側、Windows の Go / Rust 製 exe の内部依存。
- **取りこぼしうるもの**: 権限不足で読めなかったフォルダ、走査対象に入れなかったフォルダ、ネットワークドライブ上のソフト、表に登録していない商用ソフト。「収集状況」シートで確認してください。
- **判定の限界**: Trivy のデータベースに無い脆弱性は検出されません。「影響あり」は版の一致であり、実際に攻撃可能かは判定しません。製品名の表記が違うと「未使用」になります。
- **Windows 用スクリプトは Windows 実機では未検証です**（Linux 上の PowerShell 7 で、ファイル解析の部分だけ確認済み）。初回は 1 台で実行し、`inventory.json` の中身が実態と合っているか確認してください。
- **Windows OS のビルド番号判定と `--resolve-hashes` は、実際の外部サービスに接続した確認ができていません。** 初回実行時に「取得できませんでした」と出る、または明らかにおかしい結果になる場合は連絡してください。

## 7. 開発

```
pip install -e ".[dev]"
pytest
python examples/make_advisory_list.py     # サンプルの会社公表リストを作り直す
```
