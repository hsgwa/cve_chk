# vuln-triage

オフライン環境（AWS EC2 / EMR / Lambda、Linux、Windows）から回収したインベントリと、会社公表の脆弱性リスト（Excel）を突き合わせて、**通達1件ごとに各環境の「影響あり / 影響なし / 未使用 / 対象外 / 判定不能」**と社内ランク・対応期限を出すツールです。

```
[オフライン Linux]   collect_linux.sh（syft を呼ぶ） → out/<ホスト名>/cdx_syft.json, os_info.json
[オフライン Windows] collect_win.ps1（スクリプトのみ）→ out/<ホスト名>/inventory.json
          │  フォルダごと回収
          ▼
[管理 PC（ネット接続あり）]
   vuln-triage db-update  … 脆弱性データ（OSV.dev / Amazon Linux の公式情報）を手元に取得
   vuln-triage run        … 手元のデータだけで照合 → report.xlsx / CSV
```

管理 PC でも **exe は不要**です（Python と標準ライブラリ、pip で入る依存だけで動きます）。

仕組み（データの取得、照合、判定の流れ）は [docs/DESIGN.md](docs/DESIGN.md) にあります。設計の経緯は [docs/PLAN.md](docs/PLAN.md) にあります。

## 1. セットアップ（管理 PC）

Python 3.10 以降が必要です。

```
pip install -e .
```

動作確認（同梱のサンプルと、サンプル用の小さな脆弱性データで動きます。ネット接続も不要）:

```
vuln-triage run --inventory-dir examples/inventory --env-master examples/env_master.csv ^
  --advisory examples/advisory_list.xlsx --db-dir examples/vulndb ^
  --cache-dir examples/cache --offline --base-date 2026-11-20 --out-dir out
```

### 脆弱性データの取得と毎日の更新（db-update）

CVE の照合は、ダウンロードして手元に置いた脆弱性データだけで行います。**初回**は、回収データを置いてから次を実行します。

```
python -m vuln_triage db-update --inventory-dir inventory
```

回収データに出てくるパッケージの種類を見て、必要なデータだけを取得し、`vulndb/` に照合用の索引（SQLite）を作ります。

**2 回目以降は毎日実行します**（下の「毎日の自動実行」で登録できます）。

```
python -m vuln_triage db-update                              # 取得済みのデータをすべて更新
python -m vuln_triage db-update --inventory-dir inventory    # 新しく出てきたエコシステムも追加
```

- 毎日の更新は**差分**です。OSV.dev が公開している変更一覧（`modified_id.csv`）を見て、前回から変わった記録だけを取り直します。Maven の場合で 1 日あたり数百 KB 程度です。
- Amazon Linux は、公式リポジトリの updateinfo が前回と同じなら、ダウンロード自体を省きます。
- `config.yaml` の `vulndb.full_refresh_days`（既定 7 日）ごとに全件を取り直して、ずれを防ぎます。差分が `max_delta_records`（既定 3000 件）を超えた日も全件を取り直します。`--full` を付けると、いつでも全件を取り直せます。
- 更新に失敗したデータは、前回の内容のまま残ります（終了コード 1）。次回の更新で取り直されます。
- 最後の更新から 1 日（`vulndb.max_age_days`）を超えたデータで `run` すると、サマリに「更新が古くなっています」と出ます。
- `python -m vuln_triage` は `vuln-triage` と同じです。pip が作る `vuln-triage.exe` を使わずに済みます。

| データ | 取得元 | 初回（全件）の大きさの目安 |
|---|---|---|
| Java（Maven）/ Python / npm / NuGet / Go / Rust / Ruby など | OSV.dev（Google が公開している脆弱性データ） | Maven 10 MB、PyPI 37 MB、npm 212 MB など |
| Amazon Linux 2 / 2023 の OS パッケージ | Amazon Linux の公式リポジトリの updateinfo（Amazon Linux 2 は extras の全トピックも） | 各 2〜3 MB（extras は合計 数 MB） |
| Ubuntu / Debian / RHEL / Rocky / AlmaLinux の OS パッケージ | OSV.dev | Ubuntu 784 MB、Debian 80 MB、Red Hat 28 MB |
| CVSS の点数（Amazon Linux 用） | OSV.dev の Debian データ（OS パッケージがある場合に自動で取得） | 80 MB |

- 取得したデータに、本ツールが分類していない系統（例: データ提供元が新しく追加したもの）があると、`db-update` が警告を出します。その系統にしか修正情報が無い脆弱性は見落とすので、[docs/DEFECTS.md](docs/DEFECTS.md) の手順で確認してください。
- 管理 PC から次のホストへ HTTPS（Amazon Linux 2 は HTTP）で出られる必要があります: `osv-vulnerabilities.storage.googleapis.com`、`amazonlinux.default.amazonaws.com`、`cdn.amazonlinux.com`、`al2023-repos-*.s3.dualstack.*.amazonaws.com`。社内プロキシは環境変数 `HTTPS_PROXY` / `HTTP_PROXY` で指定します。
- 送るのはダウンロードの要求だけで、パッケージ名やホスト名などの回収データは外部に送りません。
- 管理 PC から取得できない場合は、別の PC のブラウザで `https://osv-vulnerabilities.storage.googleapis.com/<エコシステム名>/all.zip`（例 `Maven/all.zip`）を保存し、`db-update --import Maven=Maven.zip` で取り込めます（この場合は差分更新はできず、次回の更新は全件になります）。
- 取得済みのデータと最終更新日時は `python -m vuln_triage db-update --list` で確認できます。

### 毎日の自動実行（Windows のタスクスケジューラ）

管理 PC で一度だけ次を実行すると、毎朝 6:30 に `db-update` を実行するタスクが登録されます（Windows 標準の機能だけを使います）。

```
powershell -ExecutionPolicy Bypass -File scripts\register_daily_task.ps1 -InventoryDir D:\vuln\inventory
```

| 引数 | 内容 |
|---|---|
| `-Time 06:30` | 実行する時刻 |
| `-InventoryDir` | 回収データのフォルダ（新しく出てきたエコシステムを自動で追加する） |
| `-DbDir` / `-Config` | 脆弱性データの置き場所 / 設定ファイル（省略時は既定） |
| `-Python` | python.exe の場所（省略時は PATH から探す） |
| `-RunWhetherLoggedOn` | ログオフ中も実行する（パスワードを尋ねられる）。省略時はログオン中のみ |
| `-NoPassword` | ログオフ中も実行する。パスワードを保存しない（S4U）。管理者として開いた PowerShell で登録する。インターネットには出られるが、ネットワーク共有には接続できない |
| `-Unregister` | 登録を削除する |

- 実行内容は `scripts\daily_db_update.ps1` です。結果は `logs\db-update_<日付>.log` に残り、30 日より古いログは消えます。
- PC が止まっていて時刻を過ぎた場合は、起動後に実行します。失敗した場合は 30 分後に 2 回まで再試行します。
- 失敗したかどうかは、ログの最後の行（「終了: 成功」/「終了: 失敗」）か、タスクスケジューラの「履歴」で確認できます。
- すぐに試すには `Start-ScheduledTask -TaskName "vuln-triage db-update"` を実行します。
- スクリプトを使わずに登録する場合は、タスクスケジューラで次のように設定します。
  - トリガー: 毎日 6:30
  - 操作: プログラム `powershell.exe`、引数 `-NoProfile -ExecutionPolicy Bypass -File "<ツールのフォルダ>\scripts\daily_db_update.ps1" -InventoryDir "<回収データのフォルダ>"`、開始 `<ツールのフォルダ>`
  - 設定: 「スケジュールされた時刻にタスクを開始できなかった場合、すぐにタスクを実行する」をオン

タスクの登録は、CI（GitHub Actions の Windows Server 2025）で `-NoPassword` の登録・実行・削除を毎回確かめています。`-RunWhetherLoggedOn`（パスワードを保存する）と、省略時（ログオン中のみ）は自動では確かめていません。初回は登録後に「すぐに試す」で 1 回実行し、ログに「終了: 成功」と出ることを確認してください。

Trivy（`trivy.exe`）を使いたい場合は `--scanner trivy` で従来どおり使えます（7 章参照）。

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
- **既定で優先度を最低にして実行します**（`nice -n 19`、`ionice -c3`）。業務処理が優先され、その分だけ回収に時間がかかります。通常の優先度にするには `LOW_PRIORITY=0` を付けます。
- syft が 3 時間で終わらなければ打ち切り、syft の失敗として記録します（`SYFT_TIMEOUT_SEC` で変更）。
- サーバーへの影響と、本番の前に確かめることは [docs/OPERATIONS.md](docs/OPERATIONS.md) にあります。

#### スクリプトを使わず、syft だけで回収する場合

syft を直接実行して CycloneDX を作り、そのファイルだけを環境フォルダに置いても照合できます。OS（`ubuntu 22.04` など）は SBOM の中から判別し、回収日時は SBOM の作成日時を使います。

```
tar -xzf syft_<版>_linux_amd64.tar.gz syft
sudo SYFT_CHECK_FOR_APP_UPDATE=false ./syft scan dir:/ \
  --exclude './proc/**' --exclude './sys/**' --exclude './dev/**' \
  --exclude './run/**' --exclude './tmp/**' \
  --exclude './var/lib/docker/**' --exclude './var/lib/containerd/**' \
  -o cyclonedx-json=cdx_syft.json
```

- 古い syft には `scan` が無いので、その場合は `./syft dir:/ ...` と書きます。
- NFS などネットワーク上の領域は自動では除外されません。`findmnt -t nfs,nfs4,cifs,fuse.s3fs,lustre -o TARGET` で場所を確かめ、`--exclude './<場所>/**'` を足してください。
- 管理 PC では `inventory/<環境名>/cdx_syft.json` に置きます（ファイル名は `*.json` なら何でもかまいません）。

`collect_linux.sh` を使う場合と比べて、次のものが取れません。

| 取れないもの | 影響 |
|---|---|
| 個別製品の版（HULFT / DataMagic など、スクリプト内の表で取るもの） | 通達の製品名で見つからなければ「未使用」になる |
| EMR のリリースラベル | EMR の版を指定した通達を判定できない |
| syft の失敗と収集の中断の記録 | 失敗した場合はファイルが無いだけになる。環境マスタに登録しておけば「判定不能（回収漏れ）」として出る |

### Windows

持ち込むもの: `collectors/collect_win.ps1` だけです（exe は不要）。管理者として開いた PowerShell で実行します。

```
powershell -ExecutionPolicy Bypass -File collect_win.ps1
powershell -ExecutionPolicy Bypass -File collect_win.ps1 -ScanRoots 'D:\apps','E:\hulft'
powershell -ExecutionPolicy Bypass -File collect_win.ps1 -AllDrives
```

- `out\<ホスト名>\` に `inventory.json` と `collect.log` ができます。
- 既定で CPU の優先度を「通常以下」にして実行します（`-NormalPriority` で通常）。
- 既定の走査対象は `Program Files`、`Program Files (x86)`、`ProgramData` です。**アプリを別の場所に置いている場合は `-ScanRoots` で指定するか `-AllDrives` を付けてください。**
- 取得するもの: OS のビルド番号、適用済み KB、インストール済みソフト、exe / dll のバージョン情報、jar / war / ear の中身（入れ子も）、Python・npm・NuGet のパッケージ、実行中のプロセスの場所。

### HULFT / DataMagic などの商用ソフト

パッケージ管理の外に置かれる製品は、両スクリプト冒頭の「個別製品の版取得」の表で扱います。初期状態では **名前で探して「存在する（版不明）」と記録するだけ**なので、判定は「影響あり（比較不能）」になります。版まで取るには、実機で版が分かるコマンドかファイルを確認し、表に 1 行足してください（記入例がコメントで入っています）。Windows でインストーラを使って入れた製品は、レジストリから版が取れます。

### Lambda

実行環境の中ではスクリプトを動かせません。デプロイ用 zip を展開したフォルダに対して Linux 上で `SCAN_ROOT=<展開先> bash collect_linux.sh` か `syft scan dir:<展開先> -o cyclonedx-json=cdx_syft.json` を実行するか、Amazon Inspector の SBOM エクスポート（CycloneDX）を環境フォルダに置いてください。

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

**環境マスタは対象ホストの台帳として使えます。** 登録済みなのに回収フォルダが無い環境は、すべての通達で「判定不能」（判定区分「回収なし」、備考「回収漏れ」）として出し、サマリでも警告します。回収し忘れたホストに気づけるよう、対象のホストはすべて登録してください。

### 会社公表リスト（`.xlsx` / `.xlsm` / `.csv`）

会社の Excel をそのまま渡せます。見出しの対応は `config.yaml` の `advisory_input.columns` に書きます（シート名、見出し行の位置、結合セルの扱いも設定できます）。

読み落としを防ぐため、次の場合は警告を出します（実行時の画面とサマリシート。`check-inputs --advisory` でも確認できます）。

- 読むのは 1 シートだけです（既定は先頭のシート）。**データのある他のシートがあれば警告します。** 通達が複数のシートにある場合は、`advisory_input.sheet` でシートを指定して、シートごとに実行してください。
- 結合セルは、既定で値を結合範囲の各行に引き継ぎます（`fill_merged: true`）。`false` にした場合、縦に結合したセルがあれば警告します。
- CVE 番号の欄に、CVE 番号として読めない記載（`CVE-2024-123` のような桁不足、`CVE2024-0001` のようなハイフン抜け、`2024-0001` のような `CVE-` の書き忘れ）があれば、行番号つきで警告します。

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
| CVE 指定 | `cve_id` を書く。`product_name` と `affected_version` も書くと精度が上がる | 手元の脆弱性データ。Windows OS の CVE は OS のビルド番号 |
| 製品名＋版 | `product_name` と `affected_version`（例 `>=2.0.0,<2.17.1`、`<=3.0.12`、`9.0.*`） | 回収データの名前と版を直接比較 |
| Windows パッチ | `product_name` に KB 番号、`affected_version` に `missing`。`KB5034441\|KB5035845` と書くと、どれか適用済みなら可 | 適用済み KB の一覧 |

- **版の条件は Excel で「文字列」として入力してください。** 数値セルに `9.0` と入れると `9` として保存されます。
- 製品名は大文字小文字と区切り文字（空白、`_`、`.`、`-`）の違いを無視して完全一致で照合します。`Apache Tomcat*` のようなワイルドカード、`re:^HULFT\d` のような正規表現も使えます。呼び名が違う場合は `config.yaml` の `aliases` に登録します。
- **CVE だけで製品名が無い行は、「未使用」と「影響なし」を区別できません**（「影響なし（CVE未検出）」と表示）。できるだけ製品名も書いてください。

## 4. 実行

```
python -m vuln_triage check-inputs --inventory-dir inventory --env-master env_master.csv --advisory 通達.xlsx
python -m vuln_triage run          --inventory-dir inventory --env-master env_master.csv --advisory 通達.xlsx --out-dir out
```

脆弱性データは毎日自動で更新されている前提です（上の「毎日の自動実行」）。回収データを入れ替えて新しい種類のパッケージが増えた場合は、`run` の前に `python -m vuln_triage db-update --inventory-dir inventory` を実行してください。

`check-inputs` は判定をせず、回収データの読み込み結果と、通達の製品名が回収データのどれに当たったかを表示します。**新しい通達を取り込んだら、まずこれで「該当なし」が表記ゆれでないかを確認してください。**

主なオプション（`vuln-triage run --help` で全件）:

| オプション | 内容 |
|---|---|
| `--only-advisory` | 会社公表リストにある脆弱性だけを出力する |
| `--base-date YYYY-MM-DD` | 実行日として扱う日付 |
| `--db-dir DIR` | 脆弱性データの置き場所（既定 `vulndb`） |
| `--scanner osv / trivy / none` | CVE の照合方法（既定 `osv` = 手元の脆弱性データ） |
| `--no-msrc` / `--offline` | Windows OS のビルド番号判定を行わない / キャッシュだけで行う |
| `--resolve-hashes` | 名前の分からない jar を SHA-1 で Maven Central に照会 |

## 5. 出力

`out/report.xlsx` のシート:

| シート | 内容 |
|---|---|
| サマリ | 件数の集計、注意事項、この結果の限界 |
| 通達別一覧 | 1 行 = 通達 1 件。総合判定と、影響あり / 影響なし / 未使用 / 対象外 / 判定不能の環境名 |
| 要更新パッケージ | 1 行 = 環境 × パッケージ。影響ありの脆弱性（通達と新規検出の両方）をまとめ、**すべてが直る版（修正版のうち最も新しい版）**、件数、最も厳しいランクと最も早い期限を出す。対応の作業はこのシートから始める |
| 通達×環境 | 行 = 通達、列 = 環境の一覧表 |
| 明細 | 1 行 = 通達 × 環境 × パッケージ。影響なし・未使用も含む全件（証跡） |
| 新規検出（参考） | 通達には無いが脆弱性データとの照合で見つかった脆弱性 |
| 収集状況 | 環境ごとの回収日時、回収ファイル、CVE 照合の可否、読めなかったフォルダ、走査範囲外で動いているプログラム |

同じ内容の CSV（BOM 付き UTF-8）も `report_summary.csv`、`report_detail.csv`、`report_updates.csv`、`report_new_findings.csv` として出ます。

### 影響有無の意味

| 値 | 意味 |
|---|---|
| 影響あり | 脆弱性データとの照合で検出、または製品の版が条件に該当、または KB 未適用 |
| 影響あり（比較不能） | 製品はあるが版を比較できない（安全側の判定） |
| 影響なし | 製品はあるが、版が条件の外／修正済み／KB 適用済み |
| 影響なし（CVE未検出） | CVE だけの通達で、照合しても検出されなかった（未使用との区別は不可） |
| 未使用 | その製品が回収データに存在しない |
| 対象外 | Windows 向けの通達に対する Linux 環境など |
| 判定不能 | 判定に必要なデータを回収できていない |

### 社内ランクと対応期限

通達にランク・日数が書かれていればそれを使い、無ければ CVSS v3 と公開区分から決めます（`config.yaml` の `rank_matrix`）。CVSS は脆弱性データに入っている CVSS v3 のベクトルから計算します（v4 は使いません）。

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
- **判定の限界**: 脆弱性データ（OSV.dev、Amazon Linux の公式情報）に無い脆弱性は検出されません。「影響あり」は版の一致であり、実際に攻撃可能かは判定しません。製品名の表記が違うと「未使用」になります。
- **対象外の系統**: RHEL の追加製品（OpenShift、JBoss など）、RHEL の延長サポート（EUS）、Ubuntu の FIPS / Realtime 版の修正情報は使いません（[docs/DEFECTS.md](docs/DEFECTS.md) の 4 章）。
- **不具合の記録と類似不良の確認**: [docs/DEFECTS.md](docs/DEFECTS.md)。実データの監査は `python tools/audit_vulndb.py --db-dir vulndb --inventory-dir inventory`。
- **照合の精度**: Trivy・Grype・OSV-Scanner と同じ SBOM で結果を比べました（[docs/COMPARISON.md](docs/COMPARISON.md)）。Amazon Linux 2 / 2023 の OS パッケージは Grype と完全に一致し、Java・Python・npm・Go・Rust のライブラリは他ツールの共通部分をすべて含み、Ubuntu の OS パッケージも Grype とほぼ一致しました。他の3ツールがそろって検出していて本ツールだけが見落としたものは 0 件です。Ruby は Trivy 独自のデータ源の分だけ少なくなります。実行ファイル自体（ruby・python・node のバイナリなど）の照合は行いません。
- **Amazon Linux**: Amazon Linux 2 は core と extras の全トピック（kernel-5.4 / 5.10 / 5.15、nginx1、php8.x など 73 件）、Amazon Linux 2023 は core の情報を取得します。x86_64 の情報で、arm64 にも同じ版番号のため流用します。EMR 独自のパッケージは含みません。公式情報に CVSS が無いため、Debian のデータの同じ CVE から点数を引いています（見つからなければ「CVSS 不明」で Rank-C、備考に Amazon の深刻度を表示）。
- **実機での確認**（[docs/COMPARISON.md](docs/COMPARISON.md) の「実機での確認」）: Windows 11（管理者でない実行、ARM64）での回収、Ubuntu 24.04 と Amazon Linux 2 / 2023 での回収（スクリプトと syft だけの両方）、`db-update` の全件取得と差分更新、MSRC に接続した Windows OS の判定を通して確かめました。Windows Server 2025（管理者）での回収と照合は CI で毎回確かめています（`.github/workflows/ci.yml`）。初回は 1 台で実行し、`inventory.json` の中身が実態と合っているか確認してください。
- **`--resolve-hashes`（Maven Central への照会）は、実際に接続した確認ができていません。**

## 7. Trivy を使う場合（任意）

`trivy.exe` を使える環境では、従来どおり Trivy で照合することもできます。

```
vuln-triage run ... --scanner trivy [--save-trivy-json DIR] [--trivy-results-dir DIR]
```

`trivy.exe` は PATH に置くか、`config.yaml` の `trivy.path` に場所を書きます。注意: **syft が出す SBOM の Amazon Linux（OS 名 `amzn`）は Trivy では「未対応の OS」と扱われ、OS パッケージが照合されません**（確認済み）。Amazon Linux を含む場合は既定の `--scanner osv` を使ってください。

## 8. 開発

```
pip install -e ".[dev]"
pytest
python examples/make_advisory_list.py     # サンプルの会社公表リストを作り直す
```

`examples/vulndb/` は、本物の OSV.dev / Amazon Linux のデータから、サンプルのパッケージに関係する記録だけを抜き出したものです（`db-update --import` で作成）。

GitHub Actions の CI（`.github/workflows/ci.yml`）が、push のたびに単体テストと、Windows Server・Amazon Linux 2023・Ubuntu 24.04 での回収から照合までの試験を行います。変更履歴は [CHANGELOG.md](CHANGELOG.md)、不具合の記録は [docs/DEFECTS.md](docs/DEFECTS.md) にあります。

## 9. ライセンス

このツールのコード・スクリプト・文書は [MIT No Attribution（MIT-0）](LICENSE) です。著作権表示を残す義務も無く、改変・再配布・商用利用を含めて自由に使えます（無保証）。

依存ライブラリ（pip で別に入るもの。このリポジトリには含めていません）はすべて、同じく自由に使えるライセンスです。

| ライブラリ | ライセンス | 用途 |
|---|---|---|
| PyYAML | MIT | 設定ファイルの読み込み |
| packaging | Apache-2.0 または BSD-2-Clause | 版の比較 |
| click | BSD-3-Clause | コマンドライン |
| openpyxl（と et-xmlfile） | MIT | Excel の読み書き |
| pytest（開発時のみ） | MIT | テスト |

外部のツールとデータ（このツールのライセンスの対象外です）:

- **syft**（Apache-2.0）、**Trivy**（Apache-2.0、任意）は利用者が別に入手して使います。このリポジトリには含めていません。
- `db-update` で取得する脆弱性データ（OSV.dev、Amazon Linux の公式情報）と、Windows OS の判定で取得する Microsoft の公開データは、それぞれの提供元の条件に従います。OSV.dev のデータは、提供元（GitHub Advisory Database、Ubuntu、Debian など）ごとにライセンスが異なります。
- `examples/vulndb/`（OSV.dev と Amazon Linux のデータの一部）、`examples/cache/msrc/`（Microsoft の公開データの一部）、`examples/trivy_fixtures/`（Trivy の出力）は、試験用にそれらのデータから抜き出したもので、元のデータの条件に従います。
