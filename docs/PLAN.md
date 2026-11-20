# vuln-triage 実装計画（第3版）

> **状態: 実装済み（初版）。** 使い方は [README](../README.md) を参照。この文書は設計の経緯と判断の記録で、実装時に次の点を計画から変更した。
>
> - **jbom.jar は使わない。** 実物（v1.2.1）で log4j-core 2.14.1 の jar を解析したところ、版が `core/pom`、PURL なしという誤った結果になり、Trivy で検出できなかった。Windows の jar は ps1 の自前解析（pom.properties → MANIFEST → ファイル名、入れ子対応）だけで取る。以下の本文で「jbom を併用」としている箇所はこの判断で無効。
> - **Windows の回収ファイルは 1 台 1 ファイル**（`inventory.json`）。
> - モジュール構成は `report/tables.py`・`report/writers.py`、`config.py` など一部が下記の構成図と異なる。
> - 「回収データが一部のみ（SBOM も inventory.json も無い）」の環境で製品が見つからない場合は、「未使用」ではなく「判定不能」にした。
> - 同じ jar が複数の場所にある場合、Trivy は 1 件にまとめて報告するため、SBOM から場所を引き直してすべての場所を出すようにした。
> - 検証状況: Linux の回収（syft 1.18.1）と Trivy 0.69.3 による判定は実物で確認済み。Windows 用スクリプトは Linux 上の PowerShell 7 でファイル解析部分のみ確認（レジストリ・KB・OS 情報は Windows 実機で未検証）。Microsoft の公開データ（MSRC）と Maven Central への接続は、開発環境から到達できず未検証。

## Context
オフライン環境（AWS EC2/EMR/Lambda、Linux、Windows）で使っているソフトの一覧を回収し、会社公表の脆弱性リスト（Excel）と突き合わせて、**会社公表の脆弱性1件ごとに「未使用 / 影響なし / 影響あり」**と社内ランク・対応期限を出す Python CLI を新規構築する。リポジトリ `hsgwa/cve_chk` は空なので直下に作成し、ブランチ `ccr-62d85a9c-eh5nfl` に commit & push（PR は作らない）。

### 今回の方針転換（2点）
1. **回収方法を OS で分ける**
   - **Linux: syft を使う**（公式の `syft_<版>_linux_amd64.tar.gz` を持ち込み、展開して実行。可能と確認済み）。syft が CycloneDX を直接出すので、OS パッケージ（rpm/deb）・jar・pip・npm を1回で正確に取れる。
   - **Windows: exe は持ち込めない** → **PowerShell スクリプトだけ**で、OS 標準機能を使って「生のインベントリ JSON」を取る。CycloneDX への変換は管理 PC 側でこのツールが行う。
2. **出力は会社公表の脆弱性が起点** → 主レポートは「通達 × 環境」で `未使用 / 影響なし / 影響あり / 判定不能` を必ず埋める。通達に無い Trivy 検出（新規検出）は別シートの参考情報に格下げ。

補足: jbom.jar 等で作った CycloneDX を環境フォルダに置いた場合も、そのまま読める。

## 全体の流れ
```
[オフライン Linux]   collect_linux.sh（syft を呼ぶ） → out/<ホスト名>/cdx_syft.json + os_info.json
[オフライン Windows] collect_win.ps1（スクリプトのみ）→ out/<ホスト名>/inventory.json
[管理PC (Windows)] vuln-triage run
   1. 環境フォルダ内の JSON を形式判別して読む（CycloneDX / inventory.json ほか）
   2. Windows の inventory.json から CycloneDX SBOM を生成（jar・pip・npm・NuGet の purl 付き）→ work/sbom/<環境>.cdx.json
   3. trivy sbom で CVE 照合（CVE 指定の通達用）
   4. 製品名＋バージョン条件 / KB をルール照合（CVE 無しの通達用）
   5. 通達 × 環境 の判定表を作り、Excel / CSV / サマリを出力
```

## ユースケース
- **UC1 棚卸し**: 担当者が Linux 用に syft の tar.gz＋sh、Windows 用に ps1（テキスト）を持ち込む → 現場作業者が各ホストで実行 → `out/<ホスト名>/` を回収 → 管理 PC の `inventory/<環境名>/` に置く → `env_master.csv` に公開区分を登録。
- **UC2 通達対応（日常）**: 会社の Excel をそのまま渡して実行 → 通達ごとに「未使用／影響なし／影響あり」が出る → 影響ありをランク・期限順に対応 → ブックをそのまま回答証跡として提出。
- **UC3 CVE 指定**（例 CVE-2021-44228）: `web-ec2` の `log4j-core 2.14.1` で**影響あり**（Rank-S、期限、jar のパス）、`batch-emr` は log4j 2.17.1 で**影響なし**、`win-pc01` は log4j 自体なしで**未使用**。
- **UC4 CVE 無し（製品名＋版）**: 「Tomcat `9.0.*`」「OpenSSL `<=3.0.12`」→ インストール済みソフト・jar・実行ファイルの版と照合。版が比較できない時は安全側で**影響あり（比較不能）**。
- **UC5 Windows パッチ**: 「KB5034441 適用」→ 未適用の Windows は**影響あり**、適用済みは**影響なし**、Linux 環境は**対象外**。
- **UC6 定期再実行**: インベントリを取り直さなくても Trivy DB 更新で結果が変わるので、同じデータで月次再実行。
- **UC7 参考: 新規検出**: 通達に無い CVE を別シートに一覧（`--only-advisory` で出さない）。

## 回収スクリプト（collectors/）
生成ファイル数: **Windows は1台 1〜2 ファイル**（`inventory.json`、Java があれば `cdx_java.json`）、**Linux は1台 2 ファイル**（`cdx_syft.json`, `os_info.json`）。どちらも実行ログ `collect.log` が付く。Windows の各セクションが取れなかった場合は `"status": "failed|skipped"` と理由を入れる（→ 判定不能の根拠になる）。

**Windows: `collect_win.ps1`**（`powershell -ExecutionPolicy Bypass -File collect_win.ps1` で実行。PowerShell 5.1 標準機能が土台で、Java があれば jbom.jar を追加で使う）

Windows の精度を上げる工夫（確認結果: exe 不可／Java・Python あり／ps1 実行可／ファイルを管理 PC へ持ち出すのは不可）:
1. **Java があれば jbom.jar を併用**（jar は exe ではないので持ち込み可）: ps1 が `java` を見つけたら `java -jar jbom.jar -d <対象フォルダ> -o cdx_java.json` を実行。入れ子 jar・シェーディングされた jar まで正確に CycloneDX 化できる。Java が無い/失敗した端末は下表の `java_archives`（ps1 自前解析）に自動で切り替え。
2. **jar の SHA-1 を記録** → 管理 PC 側で、名前が分からない jar を Maven Central のハッシュ検索で特定（`--resolve-hashes`、結果はキャッシュ。送るのはハッシュ値だけ）。
3. **Python パッケージは ps1 が dist-info を直接読む**: 端末内のすべての Python 環境（venv 含む）を python を起動せずに拾える。cyclonedx-py はオフラインで依存ライブラリの持ち込みが必要になるため使わない。
4. **Windows OS の脆弱性は CVE から自動判定**（下の「Windows OS 判定」）。通達に KB を書かなくてよくなり、累積更新による「未適用」の誤判定がなくなる。
5. **実行中プロセスとサービスの実行ファイルパスも記録** → スキャン対象フォルダの指定漏れに気づける（収集状況シートに「スキャン範囲外で動いている実行ファイル」として表示）。
→ 生成ファイル: `inventory.json`（必ず）＋ `cdx_java.json`（Java がある場合）＝ **1台 1〜2 ファイル**。
| セクション | 取得方法 | 用途 |
|---|---|---|
| `os` | レジストリ `CurrentVersion`（製品名・DisplayVersion・ビルド・UBR 例 `10.0.19045.3803`・アーキテクチャ）、ホスト名、回収日時 | 証跡・Windows OS 判定 |
| `running` | プロセス・サービスの実行ファイルパス（重複除去） | スキャン範囲の漏れ検知 |
| `hotfixes` | `Get-HotFix` | KB 判定 |
| `installed_software` | レジストリ `Uninstall`（HKLM 64/32bit＋HKCU）の名前・版・発行元 | 商用ソフトの版照合 |
| `executables` | 指定フォルダ配下の exe/dll の `VersionInfo`（ProductName/FileName/ProductVersion） | ポータブル配置のランタイム・dll |
| `java_archives` | 指定フォルダ配下の jar/war/ear を .NET の `System.IO.Compression` で開き `META-INF/maven/**/pom.properties`（groupId/artifactId/version）を読む。無ければ MANIFEST、最後はファイル名から推定。war 内の入れ子 jar も1階層たどる。各 jar の SHA-1 も記録 | log4j 等（jbom が使えない時の代替＋ハッシュ特定用） |
| `python_packages` | `site-packages/*.dist-info/METADATA` の Name/Version を読む（python 実行不要） | pip パッケージ |
| `node_packages` | `node_modules/**/package.json` の name/version | npm |
| `dotnet_packages` | `*.deps.json` の libraries | NuGet |

### Windows での syft 代替の検討結果
syft は Go 製の単一バイナリで、Windows 向けは `syft.exe` しか配布されていない（jar・dll・スクリプト版は無い）。代替を検討した結果、**現行の「ps1 自前解析 + jbom.jar」を採用**する。
| 方法 | 判断 | 理由 |
|---|---|---|
| ps1 自前解析 + jbom.jar | **採用** | 持ち込みがテキストと jar だけ。追加の前提なし |
| Linux 上の syft で Windows のファイルを読む（フォルダコピー / 共有 / EBS スナップショットを Linux に接続） | 不採用（現状は実施不可） | 精度は syft と同等になるが、AWS 側の操作や Linux への持ち出しができない |
| Amazon Inspector の SBOM エクスポート、SSM での一括実行 | 不採用（現状は利用不可） | 対象環境で使えない／権限不明 |
| WSL 上で Linux 版 syft | 不採用 | 対象 Windows に WSL が無い |
| 自作 Python 収集スクリプト | 不採用 | Python が無い端末用に ps1 も必要で二重実装になる |
| cdxgen / Microsoft sbom-tool / OWASP Dependency-Check | 不採用 | Node.js や .NET ランタイムが必要、jar の中身を見ない、脆弱性 DB の持ち込みが必要、のいずれか |
- 自前解析が syft より弱い点: Go/Rust バイナリに埋め込まれた依存、jbom が使えない端末でのシェーディング jar。前者は `executables`（VersionInfo）と通達の製品名照合で補う。
- 将来 AWS 側の手段（Inspector、スナップショット経由の syft）が使えるようになった場合、出力された CycloneDX を環境フォルダに置くだけで読める（ツール側の変更は不要）。

#### 代替できる範囲（syft で Windows のフォルダを走査した場合との比較）
| 対象 | syft | 代替（ps1 + jbom.jar） | 差 |
|---|---|---|---|
| Java（jar/war/ear、入れ子） | ○ | ○ jbom が使える端末は同等。無い端末は ps1 が pom.properties・MANIFEST・ファイル名・SHA-1 で特定 | Java が無い端末で、情報を持たない改名 jar は取りこぼしうる |
| Python（インストール済み） | ○ | ○ dist-info / egg-info | ほぼ同等 |
| Node.js / .NET | ○ | ○ package.json / deps.json | ほぼ同等（対象 Windows では未使用のため優先度低） |
| Go / Rust 製 exe の内部依存 | ○ | × | 代替不可。製品名＋版の通達なら exe のバージョン情報で拾える |
| 既知バイナリの版（java.exe、python.exe、OpenSSL dll 等） | ○ | ○ VersionInfo | Windows ではむしろ確実 |
| インストール済み商用ソフト、KB、OS ビルド | × | ○ | 代替のほうが上 |
- 自前スクリプトは新規に書くものなので、実機で1回、結果の突き合わせ確認を行う（README に手順）。

### 対象ソフト別の方針（確認結果: Windows は Java・Python・HULFT・DataMagic、Linux は HULFT・DataMagic と EMR の Spark）
**注意: Linux の HULFT / DataMagic は syft では検出できない**（rpm/deb ではなくインストーラで任意のフォルダに置かれる商用ソフトのため）。Linux でも下の「個別製品の版取得」が必須で、`collect_linux.sh` は syft の実行に加えてこの取得を必ず行い、結果を `os_info.json` の `custom_products` に書く。取得できなかった場合は「失敗」と記録し、該当通達の判定を「未使用」ではなく**「判定不能」**にする（入っているのに未使用と誤判定するのを防ぐ）。
| 対象 | 取り方 | 判定 |
|---|---|---|
| **Java / Python（Windows）** | jbom.jar ＋ ps1（上記） | Trivy で CVE 照合 |
| **HULFT / DataMagic**（商用。Trivy の DB にはほぼ載らない。Windows・Linux の両方にある） | Windows: レジストリのインストール情報＋インストール先 exe/dll の VersionInfo。Linux: 「個別製品の版取得」で、インストール先（環境変数やよくある配置先、実行中プロセスのパスから探す）の版情報ファイルまたは版表示コマンドから取る。見つけた場所は「検出パス」に出す | 通達の「製品名＋版条件」とのルール照合。`config.yaml` の `aliases` に表記ゆれ（例 `HULFT8`, `HULFT8 for Windows`）を登録 |
| **EMR の Spark** | EMR ノード（マスター1台＋コア1台で可。同じクラスタ内のノードは同構成）で syft。`/usr/lib/spark/jars` 等の jar と OS パッケージが取れる | Trivy で CVE 照合。版に `-amzn-N` が付く（例 `3.4.1-amzn-2`）ため、版比較の正規化でこの接尾辞を扱う。EMR リリースラベル（例 `emr-6.15.0`）も os_info に記録し、「EMR x.y 以前」という通達に対応 |

**個別製品の版取得（collectors 共通の仕組み）**: syft や標準の収集で取れない製品のために、収集スクリプトの冒頭に「製品名・版の取り方」を数行で足せる表を用意する。取り方は ①指定ファイルの VersionInfo（Windows）②指定ファイルの中身から正規表現で抜く ③指定コマンドの出力から正規表現で抜く、の3種類。結果は `custom_products` セクションに `{name, version, source}` で記録し、ルール照合の対象にする。
- HULFT / DataMagic の版の取り方（インストール先、版を表示するコマンドやファイル）は環境依存で、こちらでは確認できない。**実装時に実機の情報（インストール先のパスと、版が分かる画面/コマンド）を教えてもらい、表の初期値として入れる**。

**Linux（EC2 / EMR 各ノード）: `collect_linux.sh`**
持ち込むもの: `collect_linux.sh` と `syft_<版>_linux_amd64.tar.gz`（arm64 の Graviton インスタンスがあれば arm64 版も）。スクリプトが同じフォルダの tar.gz を一時フォルダに展開して実行する（インストール不要、終了時に削除）。
| ファイル | 取得方法 |
|---|---|
| `cdx_syft.json` | `./syft scan dir:/ --exclude ./proc --exclude ./sys --exclude ./dev --exclude ./run（＋変数で追加可） -o cyclonedx-json=cdx_syft.json`。rpm/deb・jar（入れ子含む）・pip・npm・Go バイナリを1ファイルに。OS 情報入りなので Trivy が OS パッケージの CVE を判定できる |
| `os_info.json` | `/etc/os-release`、`uname -r`、ホスト名、回収日時、syft のバージョンと終了コード、EMR リリースラベル、`custom_products`（HULFT / DataMagic 等の版と取得の成否） |
- syft はオフラインで動く（スクリプト内で `SYFT_CHECK_FOR_APP_UPDATE=false` を設定）。全ファイルを読むため root（sudo）での実行を推奨、時間がかかる場合に備え対象ディレクトリを絞る変数を用意。
- `/tmp` が noexec で実行できない場合に備え、展開先を変数で変更可能にする。

**Lambda**: 中で実行できないため、デプロイ zip を展開したフォルダ（またはコンテナイメージ）に対して管理側の Linux で `syft scan dir:<展開先>` を実行。Amazon Inspector の CycloneDX エクスポートも読める。

## 限界（取得・判定できないケース）
このツールの「未使用」「影響なし」は**回収できた範囲での結果**であり、以下は範囲外または取りこぼしうる。レポートのサマリシートにもこの注意書きを載せる。

### 1. 対象外（現行の方法では取れない）
| 対象 | 理由 | 対処 |
|---|---|---|
| Lambda の実行環境そのもの | 中でスクリプトを実行できない | デプロイ用 zip／イメージを別途 syft で解析して環境フォルダに置く |
| コンテナの中身（Docker 等） | ホストを走査してもイメージ内のファイルは通常の形では見えない | イメージごとに別途解析が必要（現計画には含めていない。利用有無は未確認） |
| Windows の Go / Rust 製 exe の内部依存 | exe の製品名・版しか分からない | 通達が製品名＋版指定なら照合できる。CVE 番号だけの通達は拾えない |
| AWS マネージドサービス側（RDS、EMR の制御部分など） | 利用者から見えない領域 | 対象外。AWS の公表情報で別途確認 |
| Windows 以外の Microsoft 製品（Office、SQL Server 等）の CVE 自動判定 | Windows OS 判定は OS のビルド番号だけを見る | インストール済みソフトの版と、通達の製品名＋版条件で照合 |

### 2. 環境によって取りこぼすもの
| ケース | 起きること | ツールでの検知 |
|---|---|---|
| 権限不足（root / 管理者でない） | 読めないフォルダの中のソフトが漏れる | 読めなかったフォルダの一覧を記録し、収集状況シートに出す |
| スキャン対象フォルダの指定漏れ（Windows） | 指定外のドライブ・フォルダのソフトが出ない | 実行中のものはプロセスのパスから検知。**止まっているものは検知できない**（全ドライブ走査のオプションを用意。時間はかかる） |
| ネットワークドライブ・NFS・S3 マウント上のソフト | 既定で除外するため出ない | 除外したマウント先を記録 |
| Linux で syft が実行できない（noexec、SELinux、CPU 種別違い） | その端末の Linux 側 CVE 判定ができない | 失敗を記録 → CVE 通達は「判定不能」 |
| Windows で Java が無い／jbom が失敗 | ps1 の自前解析になり、情報を持たない jar を取りこぼしうる | どちらの方法で取ったかを記録 |
| 巨大なディスクで時間切れ・途中で中断 | 途中までの結果しか残らない | 完了の印が無いファイルは「未完了」として扱い「判定不能」 |
| EMR の一時クラスタが終了済み | 取れない | 検知不可。稼働中に回収する運用で対処 |
| 回収後に構成が変わった | 古い情報で判定する | 回収日時をレポートに出し、古いもの（既定 90 日超）は警告 |

### 3. 見つかっても版が特定できないもの
- 改名・再パッケージされ情報を持たない jar（SHA-1 照合でも不一致の場合）
- バージョン情報が埋め込まれていない exe / dll
- HULFT / DataMagic で、想定した場所・方法で版が取れない場合
- ソースからビルドして置いたソフト（パッケージ管理外で版の手がかりが無い）
→ 製品が見つかった場合は「影響あり（比較不能）」、取得自体が失敗した場合は「判定不能」とし、「未使用」「影響なし」にはしない。

### 4. 判定そのものの限界
- **Trivy の DB に載っていない脆弱性は検出されない**（商用ソフト、公表直後の CVE）。会社公表リストに製品名＋版条件を書くことで補う。
- **CVE 番号だけで製品名が無い通達**は「未使用」と「影響なし」を区別できない場合がある。
- **名前照合は表記ゆれに弱い**。別名辞書（`aliases`）に無い呼び方だと「未使用」になりうるため、初回は check-inputs で通達の製品名がインベントリのどれに当たったかを確認する。
- **「影響あり」は版の一致を意味し、実際に攻撃可能かは判定しない**（設定で無効化されている、該当機能を使っていない等は人が判断）。
- **Linux ディストリビューションが独自に修正を取り込んだパッケージ**（版は古いが修正済み）は Trivy が OS 情報を使って判定するが、製品名＋版条件のルール照合では「影響あり」と出うる。
- 収集スクリプトは新規作成であり、syft のような広い利用実績は無い。初回に実機で結果を突き合わせて確認する。

## 管理 PC 側ツール
```
pyproject.toml (pyyaml, packaging, click, openpyxl / dev: pytest)  config.yaml  README.md  .gitattributes
src/vuln_triage/
  models.py          # Component, EnvInventory(持っているデータ種別を含む), Advisory, Finding, Verdict
  inventory.py       # inventory.json 読込（utf-8/utf-16 BOM 自動判別）。CycloneDX・winget・Get-HotFix・VersionInfo の単体ファイルも判別して読める
  advisory.py        # Excel/CSV 読込（見出し対応表）
  sbom_builder.py    # Component → CycloneDX 1.5 JSON（purl 生成）
  trivy_runner.py    # trivy sbom 実行・結果解析・未導入時のエラー案内
  msrc.py            # Microsoft 公開データから CVE→修正ビルド/KB を取得・キャッシュ
  maven_lookup.py    # jar の SHA-1 → Maven 座標（任意、キャッシュ付き）
  matching/names.py, versions.py, rules.py, rank.py
  verdict.py         # 通達 × 環境 の判定
  report/xlsx.py, csv.py, summary.py
  cli.py
collectors/ collect_win.ps1, collect_linux.sh
examples/  env_master.csv, advisory_list.xlsx, inventory/<web-ec2|batch-emr|win-pc01>/inventory.json, trivy_fixtures/
tests/
```

### sbom_builder.py（要点）
- 対象は **Windows の inventory.json だけ**（Linux は syft の CycloneDX をそのまま Trivy に渡す）。
- purl: `pkg:maven/<group>/<artifact>@<ver>` / `pkg:pypi/<name>@<ver>` / `pkg:npm/<name>@<ver>` / `pkg:nuget/<name>@<ver>`。ファイルパスは `properties` に入れ、レポートの「検出パス」に出す。実装時に実 Trivy で検出されることを確認する。
- `installed_software` / `executables` は purl を付けられないので Trivy には渡さず、ルール照合だけに使う。Windows OS 自体の脆弱性は Trivy では見られないため、下の「Windows OS 判定」（MSRC）と KB 通達で判定する。

### Windows OS 判定（msrc.py）
- CVE 指定の通達について、管理 PC が Microsoft 公式の公開データ（MSRC Security Update API、認証不要）から、その CVE の「製品ごとの修正ビルド番号と KB」を取得し `cache/msrc/` に保存（2回目以降は再取得しない。`--offline` でキャッシュのみ使用）。
- 回収した OS ビルド（例 `10.0.19045.3803`）と、**同じビルド系列（10.0.19045）の修正ビルド**を比較:
  - 修正ビルドより古い → **影響あり**（備考に必要な KB と修正ビルド）
  - 修正ビルド以上 → **影響なし**（適用済み）
  - その CVE に自分のビルド系列が載っていない → **対象外**（その OS 版は影響を受けない）。ただしサポート切れ OS は修正自体が出ないため、config の `eol_builds` に載っている系列は **判定不能（サポート切れ・要確認）** とする
  - Microsoft の CVE ではない / 取得失敗 → この判定は使わず、従来の判定（Trivy・ルール・KB）のみ
- 補助として HotFix 一覧に該当 KB があれば「影響なし」の根拠として備考に記載。
- 通達に KB を直接書く方式（`affected_version=missing`、`KB1|KB2`）も引き続き使える。
- 実装時に実際の API 応答で形式を確認し、その応答をテスト用 fixture として保存する。

### 会社公表リスト（advisory.py）
`.xlsx/.xlsm/.csv` 対応。config.yaml で `sheet` / `header_row` / `fill_merged` / `columns`（ツール項目名 → 会社の見出し候補。例 `cve_id: ["CVE番号","CVE"]`）を指定。項目: `advisory_id, cve_id, product_name, affected_version, published_date, company_rank, deadline_days, note`。見出しの空白・改行・全半角差は無視、必須列が無ければ見つかった見出しを表示してエラー。1セル複数 CVE は展開、「14日」→14。
- 書き方: ①CVE 指定 ②製品名＋版条件（`>=2.0,<2.17.1` / `<=3.0.12` / `9.0.*`）③`product_name=KB5034441`＋`affected_version=missing`（`KB1|KB2` はいずれか適用で OK）。

### 判定（verdict.py）— 通達1件 × 環境1つごとに必ず1つ決める
| 結果 | 条件 |
|---|---|
| **影響あり** | Trivy がその CVE を検出、または製品名一致かつ版が条件内、または KB 未適用 |
| **影響あり（比較不能）** | 製品はあるが版を比較できない（安全側） |
| **影響なし** | 製品は使っているが、版が条件外／Trivy 未検出／KB 適用済み |
| **未使用** | その製品がインベントリに存在しない |
| **対象外** | KB 通達に対する Linux 環境など |
| **判定不能** | 判定に必要なセクションが回収できていない（例: KB 通達なのに hotfixes が failed） |
- CVE だけで製品名が無い通達は「未使用」と「影響なし」を区別できないため、Trivy の脆弱性情報から対象パッケージ名を補完できればそれで判定し、できなければ「影響なし（CVE 未検出）」と表示。README で **product_name の記入を推奨**。
- 名前照合: 正規化（小文字、`_ . 空白`→`-`）した完全一致を、パッケージ名・`group:artifact`・purl 名・ソフト表示名・ProductName・ファイル名で試す＋config の `aliases`＋`re:` 正規表現。
- 版比較: PEP440 → 失敗時は正規化（epoch、`-1ubuntu…`、`.Final`、`8u392`→`8.392`）→ それでも無理なら比較不能。
- ランク・期限: 通達の `company_rank`/`deadline_days` 優先、無ければ CVSS(NVD 優先→最大)×公開区分のマトリクス（config、既定 S3/A14/B30/C90）。期限 = 公表日（無ければ実行日、`--base-date` で上書き）+ 日数。影響ありの行だけに付ける。

### 出力
- **Excel `report.xlsx`**
  1. **通達別一覧（主）**: 1行=通達。`社内通達ID, CVE_ID, 製品名, 影響条件, 総合判定（影響あり＞判定不能＞影響なし＞未使用）, 影響あり環境, 影響なし環境, 未使用環境, 判定不能環境, 社内ランク(最も厳しいもの), 対応期限(最も早いもの), 備考`
  2. **通達×環境マトリクス**: 行=通達、列=環境、セル=判定（色分け）
  3. **明細**: 1行=通達×環境×パッケージ。列は当初仕様どおり `判定区分, CVE_ID, 社内通達ID, 製品・パッケージ名, 現在バージョン, 影響条件/修正バージョン, 影響有無, 社内ランク, 対応期限, 該当環境, 公開区分, 検出パス/ソース, CVSS_v3, 備考`。未使用・影響なしも1行ずつ出す（証跡）
  4. **新規検出（参考）**: 通達に無い Trivy 検出（`--only-advisory` で省略）
  5. **収集状況**: 環境ごとの回収日時・OS・各セクションの件数/成否
- **CSV**（utf-8-sig）: `report_summary.csv`（=1）と `report_detail.csv`（=3）。
- 標準出力サマリ: 判定別の通達数、ランク別件数、env_master 未登録環境の警告。

### CLI
```
vuln-triage run --inventory-dir DIR --env-master CSV --advisory XLSX|CSV [--config config.yaml]
   [--out-dir out/] [--only-advisory] [--base-date YYYY-MM-DD]
   [--skip-trivy] [--trivy-results-dir DIR] [--save-trivy-json DIR]
vuln-triage build-sbom --inventory-dir DIR --out-dir DIR   # SBOM 生成だけ
vuln-triage check-inputs ...                               # Excel 見出し・インベントリの読込確認だけ
```

## テスト（pytest）
versions／names／advisory Excel（日本語見出し・header_row・結合セル・複数 CVE・必須列欠落）／inventory 読込（utf-16、failed セクション、旧来の単体 JSON 形式）／sbom_builder（各エコシステムの purl、OS メタデータ）／verdict（6種の判定それぞれ、CVE＋ルール統合、KB `|`）／rank（境界・通達優先・期限）／trivy（未導入エラー、CVSS 優先順）／report（通達別一覧の集約、utf-8-sig）／cli e2e（examples＋fixtures）。syft 出力の CycloneDX サンプル（rpm・deb・maven を含む）の読込テストも含める。

## 検証
1. `pip install -e .[dev] && pytest -q` 全件パス。
2. このコンテナに syft の tar.gz と Trivy を取得できれば、`collect_linux.sh` を実行 → `trivy sbom` で OS パッケージと jar の CVE が実際に検出されること、および Windows サンプル inventory から `vuln-triage build-sbom` で作った SBOM でも検出されることを確認（取得できない場合は fixtures のみで確認し、その旨を報告）。
3. `vuln-triage run --inventory-dir examples/inventory --env-master examples/env_master.csv --advisory examples/advisory_list.xlsx --trivy-results-dir examples/trivy_fixtures --out-dir out/` → 通達別一覧に 未使用／影響なし／影響あり／対象外／判定不能 がそろって出ることを確認。
4. MSRC の実データを1件取得し、サンプルの Windows ビルド番号で 影響あり／影響なし／対象外 が出ることを確認（このコンテナから接続できない場合は fixture のみ）。
5. `collect_win.ps1` はこの環境では実行できないため（PowerShell を入れられれば Linux 上で構文と jar/dist-info 解析部分だけ確認）、サンプル出力に基づくテストが中心。**Windows 実機での動作確認は利用者側で必要**（README にチェック手順を書く）。
