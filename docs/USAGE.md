# 使い方

管理 PC の準備、対象マシンでの回収、入力ファイルの書き方、実行、レポートの読み方をまとめます。ツールの概要と用語は [README](../README.md)、本番導入の計画は [ROLLOUT.md](ROLLOUT.md)、運用の手順と困ったときの対処は [OPERATIONS.md](OPERATIONS.md) を参照してください。

| 章 | 内容 |
|---|---|
| [1. セットアップ（管理 PC）](#1-セットアップ管理-pc) | インストール、脆弱性データの取得と更新、調査をまとめて実行するスクリプト |
| [2. 回収（オフライン環境）](#2-回収オフライン環境) | 対象マシンに残さない方法（フォルダ 1 つで完結）、Linux / Windows / 商用ソフトでの回収、zip・jar・war などのファイル（Lambda など）の調べ方、回収物の置き方 |
| [3. 入力ファイル](#3-入力ファイル) | 環境マスタと会社公表リストの書き方 |
| [4. 実行](#4-実行) | `preview` と `check`、主なオプション |
| [5. 出力](#5-出力) | レポートのシート、影響有無の意味、社内ランクと対応期限 |
| [6. この結果の限界](#6-この結果の限界) | 取りこぼしうるもの、判定の限界、照合の精度 |
| [7. Trivy を使う場合（任意）](#7-trivy-を使う場合任意) | |
| [8. 開発](#8-開発) | テストと CI |
| [9. アンインストール（管理 PC）](#9-アンインストール管理-pc) | 管理 PC に残るものと消し方 |

## 1. セットアップ（管理 PC）

Python 3.10 以降が必要です。版を固定して使う場合は、[リリース](https://github.com/hsgwa/cve_chk/releases)の版を取得してください（例: `git clone --branch v0.8.0 https://github.com/hsgwa/cve_chk.git`）。取得したフォルダで次を実行します。

```
pip install -e .
```

`zk` コマンドが使えるようになります（パッケージ名は `zeijaku-kakunin`）。

| コマンド | すること |
|---|---|
| `zk update` | 脆弱性データを最新にする |
| `zk check` | 照合してレポートを出す |
| `zk preview` | 入力（回収物と会社公表リスト）の読み込み結果だけを見る（判定はしない） |
| `zk scan-file` | zip・jar・war などのファイルの中を調べて、回収物として置く |
| `zk export-sbom` | Windows の回収物から SBOM を書き出す（Trivy を使う場合） |

- `zk` が見つからない場合は、pip が表示した場所（例 `%APPDATA%\Python\Python3xx\Scripts`）を PATH に足すか、`python -m zeijaku_kakunin` で実行します。
- 別のツールの `zk`（同名のメモ用のツールなど）が入っている場合は、同じ働きの長い名前 `zeijaku-kakunin` を使います。
- 0.7.0 までの名前（`vuln-triage`、`db-update`、`run`、`check-inputs`、`scan-archive`、`build-sbom`）もしばらく使えます（使うと新しい名前を案内します）。

動作確認（同梱のサンプルと、サンプル用の小さな脆弱性データで動きます。ネット接続も不要）:

```
zk check --inventory-dir examples/inventory --env-master examples/env_master.csv ^
  --advisory examples/advisory_list.xlsx --db-dir examples/vulndb ^
  --cache-dir examples/cache --offline --base-date 2026-11-20 --out-dir out
```

### 脆弱性データの取得と更新（update）

CVE の照合は、ダウンロードして手元に置いた脆弱性データだけで行います。**初回**は、回収データを置いてから次を実行します。

```
zk update --inventory-dir inventory
```

回収データに出てくるパッケージの種類を見て、必要なデータだけを取得し、`vulndb/` に照合用の索引（SQLite）を作ります。

**2 回目以降は、照合の前に実行します**（下の `check_all.ps1` は自動で実行します）。

```
zk update                              # 取得済みのデータをすべて更新
zk update --inventory-dir inventory    # 新しく出てきたエコシステムも追加
```

- 2 回目以降の更新は**差分**です。OSV.dev が公開している変更一覧（`modified_id.csv`）を見て、前回から変わった記録だけを取り直します。Maven の場合で 1 日分あたり数百 KB 程度です。
- Amazon Linux は、公式リポジトリの updateinfo が前回と同じなら、ダウンロード自体を省きます。
- `config.yaml` の `vulndb.full_refresh_days`（既定 7 日）ごとに全件を取り直して、ずれを防ぎます。差分が `max_delta_records`（既定 3000 件）を超えた日も全件を取り直します。`--full` を付けると、いつでも全件を取り直せます。
- 更新に失敗したデータは、前回の内容のまま残ります（終了コード 1）。次回の更新で取り直されます。
- 最後の更新から 1 日（`vulndb.max_age_days`）を超えたデータで `check` すると、サマリに「更新が古くなっています」と出ます。
- `zk` は `zk` と同じです。pip が作る `zk.exe` を使わずに済みます。

| データ | 取得元 | 初回（全件）の大きさの目安 |
|---|---|---|
| Java（Maven）/ Python / npm / NuGet / Go / Rust / Ruby など | OSV.dev（Google が公開している脆弱性データ） | Maven 10 MB、PyPI 37 MB、npm 212 MB など |
| Amazon Linux 2 / 2023 の OS パッケージ | Amazon Linux の公式リポジトリの updateinfo（Amazon Linux 2 は extras の全トピックも） | 各 2〜3 MB（extras は合計 数 MB） |
| Ubuntu / Debian / RHEL / Rocky / AlmaLinux の OS パッケージ | OSV.dev | Ubuntu 784 MB、Debian 80 MB、Red Hat 28 MB |
| CVSS の点数（Amazon Linux 用） | OSV.dev の Debian データ（OS パッケージがある場合に自動で取得） | 80 MB |

- 取得したデータに、本ツールが分類していない系統（例: データ提供元が新しく追加したもの）があると、`update` が警告を出します。その系統にしか修正情報が無い脆弱性は見落とすので、[DEFECTS.md](DEFECTS.md) の手順で確認してください。
- 管理 PC から次のホストへ HTTPS（Amazon Linux 2 は HTTP）で出られる必要があります: `osv-vulnerabilities.storage.googleapis.com`、`amazonlinux.default.amazonaws.com`、`cdn.amazonlinux.com`、`al2023-repos-*.s3.dualstack.*.amazonaws.com`。社内プロキシは環境変数 `HTTPS_PROXY` / `HTTP_PROXY` で指定します。
- 送るのはダウンロードの要求だけで、パッケージ名やホスト名などの回収データは外部に送りません。
- 管理 PC から取得できない場合は、別の PC のブラウザで `https://osv-vulnerabilities.storage.googleapis.com/<エコシステム名>/all.zip`（例 `Maven/all.zip`）を保存し、`update --import Maven=Maven.zip` で取り込めます（この場合は差分更新はできず、次回の更新は全件になります）。
- 取得済みのデータと最終更新日時は `zk update --list` で確認できます。

### 調査をまとめて実行する（check_all.ps1）

調査のたびに、管理 PC で次の 1 つを実行します。脆弱性データの更新、照合、レポートの作成を順に行います。

```
powershell -ExecutionPolicy Bypass -File scripts\check_all.ps1 -BaseDir D:\vuln
```

作業フォルダ（`-BaseDir`）の決まった場所にあるデータを使います。

```
D:\vuln\
  inventory\<環境名>\   回収物（人が置く）
  advisory\             会社公表リスト（人が置く。.xlsx / .xlsm / .csv のうち最も新しいものを使う）
  env_master.csv        環境マスタ（人が用意する）
  reports\<日付>\       レポート（自動。reports\latest.txt に最新のフォルダ名）
  logs\                 実行ログ（自動。run_<日付>.log。90 日で消える）
```

- 前回のレポートが `reports\` にあれば、比べて「前回との差分」も出します。
- 同じ日に 2 回実行すると、2 回目は `reports\<日付>_<時刻>\` に出します。
- その日のうちにデータを更新済みなら、`-SkipDbUpdate` で更新を省けます。
- 終了コード: 0 = 成功、1 = データの更新の一部に失敗したが照合はできた（前回のデータを使った）、2 = 照合できなかった（回収物や会社公表リストが無いなど）。
- 結果はログ（`logs\run_<日付>.log`）の最後の行で確かめられます（「終了: 成功」/「終了: 失敗」）。

| 引数 | 内容 |
|---|---|
| `-BaseDir` | 作業フォルダ（必須） |
| `-DbDir` / `-Config` | 脆弱性データの置き場所 / 設定ファイル（省略時は既定） |
| `-Python` | python.exe の場所（省略時は PATH の python） |
| `-SkipDbUpdate` | 脆弱性データの更新をしない |

`update` と `check` を個別に実行することもできます（上の update と、4 章）。

Trivy（`trivy.exe`）を使いたい場合は `--scanner trivy` で従来どおり使えます（7 章参照）。

## 2. 回収（オフライン環境）

### 対象マシンに残さない（フォルダ 1 つで完結）

回収スクリプトが書き込むのは、**スクリプトを置いたフォルダの中だけ**です。回収物を取り出したら、そのフォルダを消せば対象マシンは元の状態に戻ります（アンインストールの手順はこれだけです）。

| | 手順 |
|---|---|
| Linux | 1. `/opt/vuln-collect` などのフォルダに `collect_linux.sh` と syft の tar.gz・チェックサムを置く<br>2. `sudo bash /opt/vuln-collect/collect_linux.sh`<br>3. `/opt/vuln-collect/out/<ホスト名>/` を持ち出す<br>4. `sudo rm -rf /opt/vuln-collect` |
| Windows | 1. `C:\vuln-collect` などのフォルダに `collect_win.ps1` を置く<br>2. `powershell -ExecutionPolicy Bypass -File C:\vuln-collect\collect_win.ps1`<br>3. `C:\vuln-collect\out\<ホスト名>\` を持ち出す<br>4. `C:\vuln-collect` を削除する |

- Linux では、syft の展開・一時ファイル・キャッシュもすべてフォルダの中（`.work/`）に置き、終わると消します。
- 何もインストールせず、レジストリ・サービス・タスク・設定ファイルを変えません。ファイルは読むだけで、Windows では他のプログラムの書き込み・削除を妨げない開き方をします。
- 出力先の空きが 500 MB 未満なら、何も書かずに止めます（終了コード 4。Linux は `MIN_FREE_MB`、Windows は `-MinFreeMB` で変更）。
- **CI で毎回確かめています。** Amazon Linux 2023・Ubuntu 24.04 のコンテナではファイルシステム全体、Windows Server ではユーザーのプロファイル・一時フォルダ・ProgramData・インストール済みソフト・サービス・タスクの一覧を、実行前とフォルダ削除後で比べ、差が無いことを確かめます（`tests/e2e/footprint_*.*`）。Windows では、デスクトップのプロセスがいつでも書き換えるもの（エクスプローラーの縮小版のキャッシュ、ストアアプリの設定、ユーザーのレジストリの記録、PowerShell の起動時のファイル）と、待つだけのスクリプトを同じように実行したときに変わったもの（対照）は比べません。
- 残るもの: OS が記録するもの（Linux の sudo のログやシェルの履歴、Windows のイベントログ、PowerShell が起動のたびに書くファイル）。これはこのツールに限らず、コマンドを実行すれば記録されます。
- 例外: 個別製品の版取得で `cmd`（コマンドを実行して版を読む）を使う場合、そのコマンドが書き込むものは対象外です（例: `java -version` は `/tmp/hsperfdata_<ユーザー名>` を作ることがある）。`cmd` を足すときは、検証機でそのコマンドが何を書くかを確かめてください。

### Linux（EC2、EMR の各ノード）

持ち込むもの: `collectors/collect_linux.sh` と、[syft](https://github.com/anchore/syft/releases) の `syft_<版>_linux_amd64.tar.gz`（Graviton なら `linux_arm64`）、同じリリースの `syft_<版>_checksums.txt`。同じフォルダに置いて実行します。

- **チェックサムのファイルがあると、syft の tar.gz が配布元のものと同じかを SHA-256 で確かめます。** 一致しなければ syft を実行しません（改ざん・破損の恐れ）。ファイルが無いときは確かめずに実行し、レポートに注意が出ます。確かめられないときも実行しないようにするには `REQUIRE_SYFT_CHECKSUM=1` を付けます。

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
- syft のメモリの目安を 1 GiB にしています（`SYFT_MEMORY_LIMIT`。Go の `GOMEMLIMIT`）。超えそうになるとメモリの回収を早めます。止めるものではないので、それ以上使うこともあります。
- 終了コード: 0 = 成功、1 = 出力先・作業フォルダを作れない、3 = syft が失敗（`os_info.json` は出る）、4 = 空き容量が足りない。
- サーバーへの影響と、本番の前に確かめることは [OPERATIONS.md](OPERATIONS.md) にあります。

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
- **この方法では、syft が一時ファイルやキャッシュをフォルダの外（`/tmp` やホームフォルダ）に作ることがあります。** 対象マシンに残さないことを確かめているのは `collect_linux.sh` を使う場合です。
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
- 終了コード: 0 = 成功、4 = 空き容量が足りない（`-MinFreeMB` で変更）。
- 既定の走査対象は `Program Files`、`Program Files (x86)`、`ProgramData` です。**アプリを別の場所に置いている場合は `-ScanRoots` で指定するか `-AllDrives` を付けてください。**
- 取得するもの: OS のビルド番号、適用済み KB、インストール済みソフト、exe / dll のバージョン情報、jar / war / ear の中身（入れ子も）、Python・npm・NuGet のパッケージ、実行中のプロセスの場所。

### HULFT / DataMagic などの商用ソフト

パッケージ管理の外に置かれる製品は、両スクリプト冒頭の「個別製品の版取得」の表で扱います。初期状態では **名前で探して「存在する（版不明）」と記録するだけ**なので、判定は「影響あり（比較不能）」になります。版まで取るには、実機で版が分かるコマンドかファイルを確認し、表に 1 行足してください（記入例がコメントで入っています）。Windows でインストーラを使って入れた製品は、レジストリから版が取れます。

### zip・jar・war などのファイルを調べる（Lambda など）

サーバーで回収せずに、成果物のファイルを管理 PC で直接調べられます。Lambda のデプロイ用 zip やレイヤー、アプリケーションの war や fat jar（Spring Boot など）、Python の wheel が対象です。syft も Linux も不要で、ファイルを展開せずに読みます。

```
zk scan-file function.zip layer-1.zip --inventory-dir inventory --env lambda-my-function
zk scan-file app.war batch.jar --inventory-dir inventory
zk scan-file D:\extracted\my-function --inventory-dir inventory --env lambda-my-function
```

- 調べたものは `inventory\<環境名>\archive_inventory.json` に置かれ、`check`（または `check_all.ps1`）でほかの環境と同じように照合されます。環境マスタにも環境名を登録してください（公開区分でランクが決まり、回収漏れも検出できます）。
- `--env` を付けると、指定したものをすべて 1 つの環境にまとめます（関数とそのレイヤーなど）。付けなければ、ファイル・フォルダごとに、その名前の環境を作ります。
- 見つけるもの:
  - Java: `META-INF/maven/.../pom.properties`。zip・war・ear の中の jar、jar の中の jar（`BOOT-INF/lib/`、`WEB-INF/lib/` など）もたどる（4 段まで）。pom.properties の無い jar は MANIFEST かファイル名から推定し、SHA-1 を記録する（`check --resolve-hashes` で Maven Central に照会できる）
  - Python: `*.dist-info/METADATA`、`*.egg-info/PKG-INFO`（Lambda の zip の直下、レイヤーの `python/lib/python3.x/site-packages/` など）
  - npm: `node_modules/<名前>/package.json`
  - .NET: `*.deps.json`
- OS は無い扱いです（Windows の KB・OS の通達は「対象外」）。Lambda の実行環境そのもの（ランタイムと OS）は AWS が管理しているので対象外です。ランタイムのサポート終了日は AWS の文書で確かめてください。
- 読めなかったもの（壊れた zip、512 MB を超える入れ子）は「収集状況」の「読めなかったフォルダ」に出ます。
- Go などで作った実行ファイル（Lambda の `bootstrap` など）の中のライブラリは調べません。

Lambda のファイルの取り出し方:

| 種類 | 取り出し方 |
|---|---|
| zip で配置した関数 | Lambda のコンソールの関数の画面で「ダウンロード」→「関数コード .zip」。AWS CLI なら `aws lambda get-function --function-name <関数名> --query Code.Location --output text` で表示される URL から取得する |
| レイヤー | `aws lambda get-layer-version --layer-name <レイヤー名> --version-number <版> --query Content.Location --output text` で表示される URL から取得する |
| コンテナイメージの関数 | このコマンドでは調べられない。イメージを `docker save` で tar にし、Linux 上で `syft scan docker-archive:<tar> -o cyclonedx-json=cdx_syft.json` を実行して、環境フォルダに置く |

Amazon Inspector の SBOM エクスポート（CycloneDX）を環境フォルダに置いても読み込みます。

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

読み落としを防ぐため、次の場合は警告を出します（実行時の画面とサマリシート。`preview --advisory` でも確認できます）。

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
zk preview --inventory-dir inventory --env-master env_master.csv --advisory 通達.xlsx
zk check          --inventory-dir inventory --env-master env_master.csv --advisory 通達.xlsx --out-dir out
```

ふだんは 1 章の `check_all.ps1` でまとめて実行します。個別に実行する場合は、`check` の前に `zk update --inventory-dir inventory` で脆弱性データを更新してください（回収データに新しい種類のパッケージがあれば、そのデータも取得します）。

`preview` は判定をせず、回収データの読み込み結果と、通達の製品名が回収データのどれに当たったかを表示します。**新しい通達を取り込んだら、まずこれで「該当なし」が表記ゆれでないかを確認してください。**

主なオプション（`zk check --help` で全件）:

| オプション | 内容 |
|---|---|
| `--only-advisory` | 会社公表リストにある脆弱性だけを出力する |
| `--base-date YYYY-MM-DD` | 実行日として扱う日付 |
| `--db-dir DIR` | 脆弱性データの置き場所（既定 `vulndb`） |
| `--scanner osv / trivy / none` | CVE の照合方法（既定 `osv` = 手元の脆弱性データ） |
| `--no-msrc` / `--offline` | Windows OS のビルド番号判定を行わない / キャッシュだけで行う |
| `--resolve-hashes` | 名前の分からない jar を SHA-1 で Maven Central に照会（送るのは SHA-1 だけ） |
| `--previous DIR` | 前回の出力フォルダと比べ、「新たに影響あり」「解消」「継続」「今回の回収なし」を出す。`--out-dir` とは別のフォルダにする（例: 毎月 `out\2026-11`、`out\2026-12` に出して前月を指定） |

## 5. 出力

`out/report.xlsx` のシート:

| シート | 内容 |
|---|---|
| サマリ | 件数の集計、注意事項、この結果の限界 |
| 通達別一覧 | 1 行 = 通達 1 件。総合判定と、影響あり / 影響なし / 未使用 / 対象外 / 判定不能の環境名 |
| 前回との差分 | `--previous` を指定したときだけ。1 行 = 環境 × 脆弱性 × パッケージの変化。前回の回収に無かった環境の行は「解消」ではなく「今回の回収なし」 |
| 要更新パッケージ | 1 行 = 環境 × パッケージ。影響ありの脆弱性（通達と新規検出の両方）をまとめ、**すべてが直る版（修正版のうち最も新しい版）**、件数、最も厳しいランクと最も早い期限を出す。対応の作業はこのシートから始める |
| 通達×環境 | 行 = 通達、列 = 環境の一覧表 |
| 明細 | 1 行 = 通達 × 環境 × パッケージ。影響なし・未使用も含む全件（証跡） |
| 新規検出（参考） | 通達には無いが脆弱性データとの照合で見つかった脆弱性 |
| 収集状況 | 環境ごとの回収日時、回収ファイル、CVE 照合の可否、読めなかったフォルダ、走査範囲外で動いているプログラム |

同じ内容の CSV（BOM 付き UTF-8）も `report_summary.csv`、`report_detail.csv`、`report_updates.csv`、`report_new_findings.csv`、`report_changes.csv`（`--previous` のとき）として出ます。

Excel の 1 シートには、ランク・期限の順で先頭 10 万行までを書きます（`config.yaml` の `xlsx_max_rows`。Excel の上限は約 104 万行）。超えた場合はサマリに注意が出ます。CSV には常に全件が出ます。

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

「未使用」「影響なし」は**回収できた範囲での結果**です。取りこぼしを減らす確認の手順は [OPERATIONS.md](OPERATIONS.md) の 1 章にあります。

- **対象外**: コンテナの中身、Lambda の実行環境そのもの、AWS マネージドサービス側、Windows の Go / Rust 製 exe の内部依存。
- **取りこぼしうるもの**: 権限不足で読めなかったフォルダ、走査対象に入れなかったフォルダ、ネットワークドライブ上のソフト、表に登録していない商用ソフト。「収集状況」シートで確認してください。
- **判定の限界**: 脆弱性データ（OSV.dev、Amazon Linux の公式情報）に無い脆弱性は検出されません。「影響あり」は版の一致であり、実際に攻撃可能かは判定しません。製品名の表記が違うと「未使用」になります。
- **対象外の系統**: RHEL の追加製品（OpenShift、JBoss など）、RHEL の延長サポート（EUS）、Ubuntu の FIPS / Realtime 版の修正情報は使いません（[DEFECTS.md](DEFECTS.md) の 4 章）。
- **不具合の記録と類似不良の確認**: [DEFECTS.md](DEFECTS.md)。実データの監査は `python tools/audit_vulndb.py --db-dir vulndb --inventory-dir inventory`。
- **照合の精度**（[COMPARISON.md](COMPARISON.md)）:
  - 検証用の SBOM で Trivy・Grype・OSV-Scanner と比べ、他の 3 ツールがそろって検出していて本ツールだけが見落としたものは 0 件でした。Ruby は Trivy 独自のデータ源の分だけ少なくなります。
  - 実機（Ubuntu 24.04、Amazon Linux 2 / 2023）の SBOM で、現在の Grype と比べました。Ubuntu は 27,532 件が一致し、本ツールだけの検出は Go の版の表記の違いだけでした。Grype だけの検出は、実行ファイル自体の照合（カーネル、node、python）、修正版がまだ無い CVE、Grype 側の当てはめすぎ（Amazon Linux 2 の extras）で、理由を 1 件ずつ確かめています。
  - 実行ファイル自体（ruby・python・node のバイナリ、カーネルのイメージなど）の照合は行いません。
- **Amazon Linux**: Amazon Linux 2 は core と extras の全トピック（kernel-5.4 / 5.10 / 5.15、nginx1、php8.x など 73 件）、Amazon Linux 2023 は core の情報を取得します。x86_64 の情報で、arm64 にも同じ版番号のため流用します。EMR 独自のパッケージは含みません。公式情報に CVSS が無いため、Debian のデータの同じ CVE から点数を引いています（見つからなければ「CVSS 不明」で Rank-C、備考に Amazon の深刻度を表示）。
- **実機での確認**（[COMPARISON.md](COMPARISON.md) の「実機での確認」）: Windows 11（管理者でない実行、ARM64）での回収、Ubuntu 24.04 と Amazon Linux 2 / 2023 での回収（スクリプトと syft だけの両方）、`update` の全件取得と差分更新、MSRC に接続した Windows OS の判定を通して確かめました。Windows Server 2025（管理者）での回収と照合は CI で毎回確かめています（`.github/workflows/ci.yml`）。初回は 1 台で実行し、`inventory.json` の中身が実態と合っているか確認してください。
- **`--resolve-hashes`**: Maven Central に実際に接続し、名前の分からない jar（log4j-core 2.14.1 の SHA-1）を特定して影響ありと判定できることを確かめました。

## 7. Trivy を使う場合（任意）

`trivy.exe` を使える環境では、従来どおり Trivy で照合することもできます。

```
zk check ... --scanner trivy [--save-trivy-json DIR] [--trivy-results-dir DIR]
```

`trivy.exe` は PATH に置くか、`config.yaml` の `trivy.path` に場所を書きます。注意: **syft が出す SBOM の Amazon Linux（OS 名 `amzn`）は Trivy では「未対応の OS」と扱われ、OS パッケージが照合されません**（確認済み）。Amazon Linux を含む場合は既定の `--scanner osv` を使ってください。

## 8. 開発

```
pip install -e ".[dev]"
pytest
python examples/make_advisory_list.py     # サンプルの会社公表リストを作り直す
```

`examples/vulndb/` は、本物の OSV.dev / Amazon Linux のデータから、サンプルのパッケージに関係する記録だけを抜き出したものです（`update --import` で作成）。

GitHub Actions の CI（`.github/workflows/ci.yml`）が、push のたびに単体テストと、Windows Server・Amazon Linux 2023・Ubuntu 24.04 での回収から照合までの試験を行います。変更履歴は [CHANGELOG.md](../CHANGELOG.md)、不具合の記録は [DEFECTS.md](DEFECTS.md) にあります。

文書の図は `docs/images/*.drawio.png` です。図のデータを埋め込んだ PNG なので、draw.io（デスクトップ版、または https://app.diagrams.net ）でそのまま開いて編集し、同じ形式（PNG、「図のコピーを含める」をオン）で保存し直せます。

## 9. アンインストール（管理 PC）

管理 PC に残るものと、消す手順です。**レポート（作業フォルダの `reports` など）は対応の証跡なので、必要なら先に保管してください。**

| 残るもの | 場所 | 消し方 |
|---|---|---|
| ツールの登録（pip） | Python の中（`zk` コマンドなど） | `python -m pip uninstall -y zk` |
| 依存ライブラリ | Python の中 | 他で使っていなければ `python -m pip uninstall -y pyyaml packaging click openpyxl et-xmlfile` |
| ツールのフォルダ | 取得（`git clone` など）したフォルダ。中に、既定の脆弱性データ `vulndb`、Microsoft のデータのキャッシュ `cache`、出力 `out` / `work` ができる | フォルダごと削除する |
| 作業フォルダ | `check_all.ps1 -BaseDir` に指定したフォルダ（回収物、会社公表リスト、環境マスタ、レポート、ログ、キャッシュ） | フォルダごと削除する |
| 脆弱性データ（別の場所に置いた場合） | `--db-dir` や `config.yaml` の `vulndb.dir` に指定したフォルダ | フォルダごと削除する |
| Python | このツールのためだけに入れた場合 | Windows の「アプリ」から Python をアンインストールする |
| （0.4.0 以前を使っていた場合）タスクスケジューラの登録 | タスク名 `zk update` / `zk check` | `Unregister-ScheduledTask -TaskName "zk update" -Confirm:$false`（`zk check` も同じ）。0.5.0 以降は登録しない |

このツールは、上の表のほかにレジストリ・サービス・タスク・環境変数を変更しません。
