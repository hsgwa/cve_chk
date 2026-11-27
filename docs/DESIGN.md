# 脆弱確認（zk）の仕組み

この文書は、現在のコードがどう動くかを説明します。概要は [README](https://github.com/hsgwa/cve_chk/blob/main/README.md)、使い方は [docs/usage/](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/README.md)、設計の経緯は [PLAN.md](https://github.com/hsgwa/cve_chk/blob/main/docs/PLAN.md)、不具合の記録は [DEFECTS.md](https://github.com/hsgwa/cve_chk/blob/main/docs/DEFECTS.md)、他ツールとの比較は [COMPARISON.md](https://github.com/hsgwa/cve_chk/blob/main/docs/COMPARISON.md) にあります。

## 1. 全体の流れ

![全体の流れ: 対象マシンの回収スクリプトが出した回収物を管理 PC に置き、zk update が脆弱性データを取得して索引を作り、zk check が 1 台ずつ 6 段階（読み込み、PURL 付け、照合、Windows OS の判定、CVE の一覧の判定、出力）でレポートを出す](https://github.com/hsgwa/cve_chk/raw/main/docs/images/pipeline.drawio.png)

管理 PC で外部に接続するのは次の 3 つだけです。`zk check` が使う脆弱性データは `zk update` で取得済みのものだけです。

| 接続先 | 使う処理 | 省略する方法 |
|---|---|---|
| OSV.dev（`osv-vulnerabilities.storage.googleapis.com`）、Amazon Linux の公式リポジトリ | `zk update` | `zk update --import 名前=ZIP` で手元の zip を取り込む |
| MSRC（`api.msrc.microsoft.com`） | `zk check`（Windows OS の判定） | `--offline`（キャッシュだけ使う）、`--no-msrc` |
| Maven Central の検索 | `zk check --resolve-hashes` | 指定しない（既定） |

## 2. モジュール構成

| ファイル | 役割 |
|---|---|
| `cli.py` | コマンド `zk update` / `zk check` / `zk preview` / `zk scan-file` / `zk export-sbom` / `zk demo` / `zk init` |
| `config.py` | `config.yaml` の読み込みと既定値 |
| `models.py` | データ構造（`Component`、`EnvInventory`、`Finding`）と判定の値 |
| `inventory.py` | 回収ファイルの形式判別と読み込み（1 台ぶんのフォルダ） |
| `purl.py` | PURL の読み取り。ツール内で PURL を読むのはここだけ |
| `sbom_builder.py` | Windows の回収データに PURL を付ける。Trivy 用の CycloneDX も作る |
| `cvelist.py` | CVE の一覧（xlsx / xlsm / csv / txt）から CVE 番号を拾う |
| `vulndb/store.py` | 脆弱性データの取得・差分更新・索引（SQLite）・検索 |
| `vulndb/ecosystems.py` | コンポーネントから、照合するデータの系統とパッケージ名を決める |
| `vulndb/scanner.py` | 影響範囲の評価と照合 |
| `vulndb/versions.py` | エコシステムごとの版の比較（dpkg、RPM、Maven、PEP 440、semver、RubyGems、apk） |
| `vulndb/coverage.py` | データに現れる系統を「使う / 理由つきで使わない / 未分類」に分ける |
| `msrc.py` | Windows OS の CVE を、MSRC の修正ビルド番号で判定する |
| `judge.py` | 1 台の判定（見つかった脆弱性と、CVE の一覧の CVE ごとの影響の有無） |
| `report/tables.py`、`report/writers.py`、`report/diff.py` | 表の組み立て、Excel / CSV への書き出し、前回との比較 |
| `trivy_runner.py` | Trivy を使う場合の呼び出し（任意） |
| `archive_scan.py` | `zk scan-file`: zip / jar / war / ear / whl（と展開したフォルダ）をメモリ上で読み、入れ子の jar もたどって Java・Python・npm・NuGet のライブラリを探し、`inventory.json` の形（OS は `archive`）で書き出す |
| `maven_lookup.py` | jar の SHA-1 から Maven の座標を調べる（任意） |

## 3. 回収と読み込み

### 回収スクリプト

- **Linux**（`collect_linux.sh`）: 持ち込んだ syft の tar.gz を展開して実行し、CycloneDX の SBOM（`cdx_syft.json`）を作ります。OS 情報と収集の成否は `os_info.json` に入れます。
- **Windows**（`collect_win.ps1`）: exe を使わず、1 台 1 ファイルの `inventory.json` を作ります。内容は OS（ビルド番号と UBR）、適用済み KB、レジストリのインストール済みソフト、exe / dll の版情報、jar（pom.properties を読む。SHA-1 付き）、Python の dist-info、npm の package.json、NuGet の deps.json、実行中のプロセスとサービスです。項目ごとに `status`（`ok` / `failed` / `skipped`）と理由が入ります。jbom.jar は使いません（[PLAN.md](https://github.com/hsgwa/cve_chk/blob/main/docs/PLAN.md) の冒頭を参照）。

### 形式の判別（`inventory.py`）

回収物のフォルダ 1 つが 1 台です（`zk check` に渡すフォルダ）。フォルダ内の `*.json` を中身で判別して読みます。`zk update` と `zk export-sbom` は、1 台のフォルダでも、複数台のフォルダを並べたフォルダでも読みます。

| 判別のしかた | 形式 |
|---|---|
| `bomFormat: CycloneDX` | CycloneDX（syft、jbom、Amazon Inspector など） |
| `schema: vuln-triage-inventory/1` | Windows の `inventory.json` |
| `schema: vuln-triage-osinfo/1` | Linux の `os_info.json` |
| `Sources` がある | `winget export` |
| 配列で `HotFixID` がある | `Get-HotFix` |
| 配列で `ProductVersion` などがある | exe / dll の `VersionInfo` |

素の syft の出力（CycloneDX）だけを置いた環境も扱えます。OS は SBOM の `operating-system` の要素と PURL の `distro` から判別し、回収日時は `metadata.timestamp` を使います（`os_info.json` があればそちらを優先）。

古い回収物の `custom_products`（0.9 までの個別製品の表の結果）は読みません。

### CVE の一覧の読み込み（`cvelist.py`）

書式を決めず、Excel ならすべてのシートのすべてのセル、CSV とテキストならすべての行から、`CVE-年-番号`（番号は 4 桁以上）の形の文字列を拾います。NFKC で正規化するので全角でも読みます。出てきた順に並べ、重複は 1 つにします。`CVE` の後に数字が続くのに読めない記載（`CVE2024-1`、`CVE-2024-12`）は場所つきで警告し、CVE が 1 つも無ければ止めます。

### PURL の付与（`sbom_builder.assign_purls`）

syft の SBOM は最初から PURL を持っています。Windows の回収データには、種類ごとに PURL を付けます（`pkg:maven/<group>/<artifact>@<版>`、`pkg:pypi`、`pkg:npm`、`pkg:nuget`）。groupId の分からない jar には付けません。PURL のあるコンポーネントだけが脆弱性データでの照合の対象です。

## 4. 脆弱性データ（`vulndb/store.py`）

### データ源

| データ | 取得元 | 保存先 |
|---|---|---|
| ライブラリ（Maven、PyPI、npm、NuGet、Go、crates.io、RubyGems、Packagist、Hex、Pub） | OSV.dev のエコシステム別 `all.zip` | `vulndb/osv/<名前>.zip` |
| Ubuntu、Debian、Red Hat、Rocky Linux、AlmaLinux、Alpine | 同上 | 同上 |
| Amazon Linux 2 / 2023 | 公式リポジトリの `updateinfo.xml` を OSV 形式に変換 | `vulndb/amazon/amazon-linux-<版>.zip` |
| Amazon Linux 2 の extras（kernel-5.10 など 73 トピック） | 同上（トピックごと） | `vulndb/amazon/amazon-linux-2-extras-<トピック>.zip` |

`zk update --inventory-dir` は回収データを読み、必要なデータ（`ecosystems.needed_sources`）を自動で選びます。OS パッケージがあるときは、CVSS を引くために `score_sources`（既定 Debian）も取ります。2 回目以降に引数なしで実行すると、取得済みのデータをすべて更新します。

### 索引（`vulndb/index.sqlite`）

記録の本文は zip のまま保存し、SQLite には検索用の索引だけを入れます。メモリに全記録を載せないためです（Ubuntu のデータでメモリ不足になった不具合への対策）。

| テーブル | 内容 |
|---|---|
| `sources` | データごとの保存ファイル、URL、最終確認日時、件数、差分の起点（`cursor`）、全件取得日時（`full_at`）、Amazon のチェックサム |
| `entries` | （系統、正規化したパッケージ名、記録 ID、ファイル、zip 内の名前）。検索はこの表で行う |
| `records` | 差分更新で取った記録の本文（JSON）。`entries.file` は `#delta` |
| `scores` | （脆弱性 ID、ソース名、CVSS v3 の点数）。ソース名は記録 ID の接頭辞（`ghsa`、`ubuntu` など） |

パッケージ名は系統ごとに正規化します（PyPI は `-_.` を `-` にそろえて小文字、それ以外は小文字）。取り下げられた記録（`withdrawn`）は索引に入れません。

### 更新（全件と差分）

- **OSV.dev**: 普段は `modified_id.csv`（更新日時と記録 ID の一覧）を取り、前回の `cursor` より新しい記録だけを 1 件ずつ取り直して `records` に入れます。すべて取れてから反映するので、途中で失敗しても前回の内容が残ります。次のどれかに当たると `all.zip` を全件取り直します: 初回、`--full`、前回の全件取得から `full_refresh_days`（既定 7 日）以上、差分が `max_delta_records`（既定 3000 件）超、保存ファイルが無い。全件を取り直すと、差分で持っていた同じ記録は消します。
- **Amazon Linux**: ミラー一覧から `repomd.xml` を引き、updateinfo のチェックサムが前回と同じなら取得を省きます。CDN に届かない環境向けに、ミラー一覧と同じホストの同じパスも試します。
- 失敗したデータは前回の内容のまま残り、`zk update` は終了コード 1 を返します。
- `zk check` は、最終確認から `max_age_days`（既定 1 日）を超えたデータがあると警告します。

### Amazon Linux の変換

updateinfo の告知 1 件を OSV の記録 1 件にします。告知 ID（ALAS-…）が記録 ID、CVE が `aliases`、各パッケージの版が `fixed` です。src パッケージは除きます。

extras のトピックでは、影響範囲の下限（`introduced`）を「そのトピックでのそのパッケージの最も古い修正版」の系統（エポック:メジャー.マイナー）にします。例えば kernel-5.10 のトピックは下限が `5.10` なので、kernel 4.14 や 5.15 のホストには当たりません。告知ごとに下限を付けると、nginx1 のように同じトピックの中で版が上がるもの（1.20 から 1.22）を見落とします。

Amazon の公式情報には CVSS がありません。同じ CVE の点数を他のデータ（既定 Debian）の `scores` から引きます。

### 系統の分類（`vulndb/coverage.py`）

データに現れる系統（`Ubuntu:22.04:LTS`、`Red Hat:enterprise_linux:9::appstream` など）は、すべて「照合に使う」か「理由があって使わない」に分類してあります。どちらにも当たらない系統が現れると、`zk update` が警告します。データ提供元が新しい系統を足したときに見落としに気づくためです。使わない系統は [DEFECTS.md](https://github.com/hsgwa/cve_chk/blob/main/docs/DEFECTS.md) の 4 章にあります。

## 5. 照合（`vulndb/scanner.py`、`vulndb/ecosystems.py`）

### 問い合わせの組み立て（`build_query`）

コンポーネント 1 件ごとに、PURL から「必要なデータ、照合する系統、パッケージ名、版」を決めます。

| PURL の種類 | 系統 |
|---|---|
| `maven` `pypi` `npm` `nuget` `golang` `cargo` `gem` `composer` `hex` `pub` | 同名のライブラリの系統。Go は `v` を外し、v2 以降のモジュールは subpath 付きの名前にする |
| `deb`（Ubuntu） | `Ubuntu:<版>:LTS`、`Ubuntu:<版>`、`Ubuntu:Pro:<版>:LTS`、`Ubuntu:Pro:<版>` |
| `deb`（Debian） | `Debian:<メジャー版>` |
| `rpm`（Amazon Linux） | `Amazon Linux:2` または `Amazon Linux:2023` |
| `rpm`（RHEL） | `Red Hat:enterprise_linux:<メジャー>:%`（9 まで）と `Red Hat:enterprise_linux:<マイナー版>`（10 から） |
| `rpm`（Rocky / Alma） | `Rocky Linux:<メジャー>`、`AlmaLinux:<メジャー>` |
| `apk`（Alpine） | `Alpine:v<メジャー.マイナー>` |

- OS は PURL の `distro` から取り、無ければ環境の OS 情報を使います。
- OS パッケージは、バイナリパッケージ名に加えてソースパッケージ名（deb の `upstream`、rpm の `source`）でも引きます。ただし rpm で、ソースの版がバイナリの版と違うサブパッケージ（lvm2 2.02.187 の device-mapper 1.02.170 など）はソース名で引きません。RPM のエポックは版に付けます。
- syft が実行ファイルの ELF のパッケージ情報から作る OS パッケージ（`elf-binary-package-cataloger`。Amazon Linux 2023 の実行ファイルに入っている）は、rpm / dpkg のデータベースに同じ名前と版のパッケージがあれば照合しません（読み込み時に `inventory.py` で外す）。エポックを持たないため、エポック付きの修正版と比べると誤検出になるからです。
- 照合しないもの: 版が無い・数字を含まないもの、カーネルのヘッダだけのパッケージ（Ubuntu / Debian の `linux-libc-dev`、`linux-headers-*`、系統名つきの `linux-aws-7.0-headers-*` など）、対応の無い PURL の種類。これらは件数を「収集状況」シートに出します。対応の無い OS は「未対応の OS」として件数を出します。
- 必要なデータが未取得なら照合せず、環境の `missing_db` に件数を記録します。この台では、見つからなかった CVE を「影響なし」にせず「判定不能」にします。Amazon Linux 2 で extras のデータが無いときも同じです。

### 影響範囲の評価（`evaluate`、`evaluate_range`）

索引から記録を引き、記録内の `affected` のうち、系統とパッケージ名の両方が一致する項目だけを評価します。1 つの記録に複数のパッケージが載っているためです（名前を確かめずに評価した誤検出があった）。

- `versions` に版が載っていれば影響あり。
- `ranges`（`ECOSYSTEM` / `SEMVER`）は、イベント（`introduced`、`last_affected`、`fixed`）を版の順に並べて、インストール済みの版の位置で判定します。影響ありのときは次の `fixed` を修正版として出します。
- 版を比較できない範囲しか無く、ほかに当たりも無ければ「比較不能」として影響あり（比較不能）にします。
- 参考情報（RustSec の保守終了など `informational` の印があるもの）は除きます。

**Ubuntu Pro**: 通常の系統の情報があればそれだけを使います。Pro（ESM）の系統にしか情報が無いときも版番号で判定します。加えて、修正版から esm の印（`+esm1`、`~esm2`）を外した版と同じ版を入れていれば、影響ありにします（Pro の修正を含まない。`~esm` は番号の比較で通常の版より小さくなるため、番号の比較だけでは修正済みに見える）。備考に「修正版は Ubuntu Pro（ESM）でのみ提供」と出します。以前は版番号によらず影響ありとしていましたが、Livepatch の告知（LSN）を修正済みの新しいカーネルにも当てはめて大量に誤検出したため改めました。

**縮小版**: 64 KB 以上の記録（Ubuntu のカーネルの CVE。カーネルの系統ごとに 277 項目が並び、1 件 0.5 MB 前後）は、照合に使う項目だけを残した縮小版を zlib で圧縮して索引（`slim` テーブル）に入れ、照合ではこちらを読みます。`versions`（影響のある版の列挙）は、範囲（ECOSYSTEM / SEMVER）の無い項目だけ残します。0.2.0 より前の索引には縮小版が無いので、`zk update` の実行時に手元のデータから作ります。

**評価の使い回し**: Ubuntu のカーネルは 1 つのソースパッケージに数千件（1 件 0.5 MB 前後）の記録があり、同じソースのバイナリパッケージが 10 個前後あります。（系統、パッケージ名、版）が同じなら評価の結果を使い回します。

検出は記録内の CVE ごとに 1 件の `Finding` にします（CVE が無ければ記録 ID）。同じ環境・CVE・パッケージ・版・パスの重複はまとめます。

## 6. 版の比較

| 場所 | 用途 |
|---|---|
| `vulndb/versions.py` の `compare(系統, a, b)` | 脆弱性データの影響範囲の評価で使う比較の入口 |
| `vulndb/versions.py` の `sort_key(系統)` | 「要更新ソフト」で、修正版のうち最も新しい版を選ぶ |

系統ごとの規則は次のとおりです。専用の規則で読めない版は汎用の比較を試し、それでも読めなければ比較不能です。

| 規則 | 系統 |
|---|---|
| dpkg | Debian、Ubuntu |
| RPM（rpmvercmp） | Red Hat、Rocky、Alma、Amazon Linux など |
| Maven | Maven |
| PEP 440 | PyPI |
| semver | npm、Go、crates.io、Hex、Pub、NuGet、Packagist |
| RubyGems | RubyGems |
| apk | Alpine |

## 7. Windows OS の判定（`msrc.py`）

CVE の一覧を渡したとき、一覧の CVE ごとに MSRC の Security Update API でその CVE の修正情報（製品、KB、修正ビルド番号 `10.0.19045.3803` の形）を引きます。結果は `cache/msrc/<CVE>.json` に保存し、次回からはキャッシュを使います。

Windows の環境では、回収した OS ビルド（`10.0.<ビルド>.<UBR>`）と、同じ系列（先頭 3 つ）の修正ビルドを比べます。

| 状況 | 判定 |
|---|---|
| UBR が修正ビルドより小さい | 影響あり |
| UBR が修正ビルド以上 | 影響なし（適用済み） |
| 同じ系列の修正が無く、`msrc.eol_builds` のビルド | 判定不能（サポート切れ） |
| 同じ系列の修正が無い | 影響なし（この OS の版は対象外） |
| OS ビルドを回収できていない | 判定不能 |

MSRC に修正情報がある CVE は Windows OS の脆弱性とみなし、Windows 以外のサーバーは（脆弱性データで検出が無ければ）影響なしにします。OS を判別できないサーバーは判定不能です。累積更新は修正ビルドで判定するので、KB 番号は要りません。CVE の一覧を渡さないときは、Windows OS の判定はしません。

## 8. 判定（`judge.py`）

1 台ごとに次を出します。

- **見つかった脆弱性**: 5 章の検出をすべて。同じ CVE・パッケージ・版・場所の重複はまとめます。CVE の一覧にあるもの（CVE 番号のほか、検出の GHSA などの別 ID でも当たる）に印を付け、先に並べます。
- **CVE の一覧の判定**（一覧を渡したとき）: 一覧の CVE ごとに必ず 1 行以上を出します。

| 状況 | 判定 |
|---|---|
| 脆弱性データで検出した | 影響あり（版を比べられなければ影響あり（比較不能））。パッケージごとに 1 行 |
| Windows OS の CVE（7 章） | ビルド番号の比較の結果 |
| 検出が無く、照合していないパッケージがある（`missing_db`） | 判定不能 |
| 検出が無く、照合できたパッケージが 1 つも無い | 判定不能 |
| 検出が無く、回収が途中で止まっている | 判定不能 |
| それ以外 | 影響なし |

1 つの告知（ALAS など）に CVE が複数あるときは、CVE ごとの検出にしているので、一覧の CVE にはその CVE の検出だけが当たります。

## 9. 出力（`report/`）

| ファイル | 内容 |
|---|---|
| `report.xlsx` | シート「サマリ」「CVE の判定」「要更新ソフト」「前回との差分」「脆弱性の一覧」「収集状況」 |
| `report_cve.csv` | CVE の一覧の CVE ごとの判定（一覧を渡したときだけ） |
| `report_updates.csv` | ソフトウェア × 版 × 場所ごとにまとめた更新先。修正版のうち最も新しい版（6 章の規則で比べる）を「この版以上に更新」に出す |
| `report_vulns.csv` | 見つかった脆弱性すべて。次回の `--previous` の比較にも使う |
| `report_changes.csv` | 前回との差分（`--previous` のときだけ）。比べる単位は（脆弱性、ソフトウェア） |

「収集状況」シートには、回収ファイル、OS、ソフトウェアの件数、照合できたか、読めなかったフォルダ、走査範囲外で動いている実行ファイル、回収からの日数（`stale_days` 超で警告）を出します。CVSS や社内ランク、対応期限は出しません。

## 10. 任意の機能

- **Trivy**（`--scanner trivy`）: Windows の回収データから CycloneDX を作り（出力先の `sbom/`）、`trivy sbom` で照合します。syft の SBOM の Amazon Linux（OS 名 `amzn`）は Trivy では照合されないため、Amazon Linux を含む場合は既定の `osv` を使います。
- **jar の SHA-1 照会**（`--resolve-hashes`）: groupId の分からない jar を Maven Central で検索し、結果を `cache/maven_sha1.json` に保存します。外部に送るのはハッシュ値だけです。

## 11. 品質の確かめ方

| 方法 | 内容 |
|---|---|
| `pytest` | 単体テストと静的な検査（`tests/test_static_checks.py`）。PURL の読み取りは `purl.py` だけか、版の比較の入口は決まった場所だけか、記録の評価でパッケージ名を確かめているか、PowerShell の誤りやすい書き方が無いか、保存ファイル名が Windows で使えるか、`zk update` のオプションの組み合わせ |
| `tools/audit_vulndb.py` | 実データの監査。系統の分類（A）、extras の網羅（B）、版の比較規則と範囲の順序（C）、照合結果の不変条件（D1〜D5）。問題があれば終了コード 1 |
| 4 ツール比較 | 同じ SBOM を Trivy・Grype・OSV-Scanner にかけて比べる（[COMPARISON.md](https://github.com/hsgwa/cve_chk/blob/main/docs/COMPARISON.md)）。データ源や判定を変えたら再実行する |

実機での確認の結果は [COMPARISON.md](https://github.com/hsgwa/cve_chk/blob/main/docs/COMPARISON.md) の「実機での確認」にあります。CI（`.github/workflows/ci.yml`）は、push のたびに単体テスト（Windows / Linux、Python 3.10 / 3.13）、Windows Server 2025 での回収・照合・`check_all.ps1` の実行、配布物の試験、Amazon Linux 2023 と Ubuntu 24.04 のコンテナでの回収・照合を行います。まだ確かめていないこと: Maven Central への実際の接続（`--resolve-hashes`）と、Windows Server 2016 / 2019 などの古い版です。
