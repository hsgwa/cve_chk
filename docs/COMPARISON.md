# 他の脆弱性チェッカーとの結果比較

本ツール（`vuln-triage`、手元の脆弱性データで照合）の検出結果を、代表的な3つのチェッカーと、同じ SBOM で比べた記録です。

- 実施日: 2026-11-20
- 他のツールは、比較のために検証用の環境でだけ使いました。本ツールの動作には不要です。

## 比較したツールとデータ

| ツール | バージョン | 脆弱性データ |
|---|---|---|
| 本ツール | 本リポジトリ（比較で見つけた不具合を直した後） | OSV.dev のエコシステム別データ、Amazon Linux 公式の updateinfo（2026-11-20 取得） |
| Trivy（Aqua Security） | 0.69.3 | Trivy DB（2026-11-20 取得） |
| Grype（Anchore） | 0.104.0 | Grype DB v6.1.10（2026-11-20 06:21 UTC 作成） |
| OSV-Scanner（Google） | 2.3.0 | オフライン用の OSV データ（2026-11-20 取得） |

| 比較の対象 | SBOM | 内容 |
|---|---|---|
| container | syft 1.18.1 で開発コンテナ全体を走査した CycloneDX | Ubuntu 24.04 の OS パッケージ、Java / Python / npm / Go / Rust / Ruby のライブラリ |
| al2 / al2023 | Amazon Linux 2 / 2023 の OS パッケージ 9 件 / 7 件（実在する古い版。openssl、curl、glibc、python3 など） | syft と同じ書式（OS 名 `amzn`） |

すべてのツールに同じ SBOM を渡しました。例外は Trivy の Amazon Linux で、後述の理由により Trivy 向けの書式に直した SBOM を使っています。

## 数え方

ツールごとに、報告の単位が違います。

| ツール | 報告の単位 |
|---|---|
| Grype | Amazon の告知（ALAS）1件ごとに、関連する複数の CVE をまとめて報告 |
| 本ツール | 同じ脆弱性でも、見つかった場所ごとに報告 |
| OSV-Scanner | OS パッケージをソースパッケージ名で報告 |

そこで、すべてを次の単位にそろえてから数えました。

- **単位は「パッケージ × 脆弱性」**。同じパッケージ・同じ版の、同じ CVE は 1 件として数えます。
- **脆弱性は CVE 番号でそろえる**。1件に CVE が複数あれば CVE ごとに分けます。CVE 番号の無いもの（GHSA、RUSTSEC、ALAS だけのもの）は、どれかのツールが同じ ID と CVE を並べていれば、その CVE に寄せます。
- **OS パッケージはソースパッケージ単位**（例: `libavcodec60` → `ffmpeg`）。ツールによってバイナリ名とソース名のどちらで報告するかが違うためです。
- ID の大文字小文字はそろえています。

## 結果

表の見方:
- 「全ツール」は、4ツールすべてが検出した件数です。
- 「◯だけ」は、そのツールしか検出していない件数です。
- 「◯だけ無い」は、他の3ツールが検出していて、そのツールだけが検出していない件数です。

### Amazon Linux 2 / 2023（OS パッケージ）

| | 本ツール | Trivy | Grype | OSV-Scanner |
|---|---|---|---|---|
| Amazon Linux 2 | **318** | 313 | **318** | 0 |
| Amazon Linux 2023 | **315** | 313 | **315** | 0 |

- **本ツールと Grype は完全に一致しました。**
- Trivy の不足分（Amazon Linux 2 で 5 件、2023 で 2 件）は、CVE 番号の無い Amazon の告知（ALAS）です。
- **Trivy は、syft の SBOM のまま渡すと 0 件です。** OS 名 `amzn` を「未対応の OS」として扱い、OS パッケージを照合しません。上の 313 件は、SBOM を Trivy 向けの書式（OS 名 `amazon`、PURL の名前空間 `amazon`）に直して出した数字です。
- **OSV-Scanner は 0 件です。** OSV.dev に Amazon Linux のデータが無く、Amazon Linux のパッケージを「照合できない」として外しました。

### 開発コンテナ（Ubuntu 24.04 とライブラリ）

| 種類 | 本ツール | Trivy | Grype | OSV-Scanner | 全ツール | 本ツールだけ | 本ツールだけ無い | 他ツールの「だけ」「だけ無い」 |
|---|---|---|---|---|---|---|---|---|
| OS（Ubuntu） | 1,358 | 219 | 1,315 | 1,503 | 216 | 31 | **0** | Trivy だけ無い 509、OSV-Scanner だけ 763、Grype だけ 1 |
| Java | 31 | 31 | 31 | 31 | 31 | 0 | 0 | なし |
| Python | 251 | 243 | 246 | 253 | 243 | 0 | 0 | OSV-Scanner だけ 2、Trivy だけ無い 3 |
| npm | 73 | 73 | 73 | 73 | 73 | 0 | 0 | なし |
| Go | 530 | 524 | 629 | 674 | 513 | 0 | 0 | Grype だけ 99、OSV-Scanner だけ 157、OSV-Scanner だけ無い 11、Trivy だけ無い 4 |
| Rust | 22 | 4 | 4 | 42 | 4 | 0 | 0 | OSV-Scanner だけ 20 |
| Ruby | 94 | 97 | 94 | 94 | 89 | 0 | 0 | Trivy だけ 8、Trivy だけ無い 5 |
| その他（実行ファイル） | 0 | 0 | 336 | 0 | 0 | 0 | 0 | Grype だけ 336 |

**本ツールだけが見落としているもの（他の3ツールがそろって検出しているもの）は、どの種類でも 0 件でした。**

## 食い違いの原因（具体例を確認したもの）

| 食い違い | 原因 | どちらが妥当か |
|---|---|---|
| Ubuntu: Trivy だけ無い 509 件 | Trivy の Ubuntu データには、他の3ツールが「影響あり（未修正）」とする脆弱性の多くが入っていない | 他の3ツール。Ubuntu の OS パッケージで Trivy の結果は少なく出る |
| Ubuntu: OSV-Scanner だけ 763 件 | Ubuntu 14.04 など**別のリリースにしか載っていない記録を、24.04 に当てはめている**（例: binutils CVE-2014-9939。記録は 14.04 向けだけ） | 誤検出（OSV-Scanner 側） |
| Ubuntu: 本ツールだけ 31 件 | 17 件は今月（2026-11）公表の脆弱性。Grype のデータは本ツールより約 1.5 時間前に作られており、取得時刻の差と見られる。残りはデータの扱いの違い（php8.3、libreoffice など） | 確定できず。参考として表示 |
| Ubuntu: Grype だけ 1 件 | ninja-build CVE-2024-36823。Ubuntu のデータには無い | 確定できず |
| Go: Grype だけ 99 件 | Go 本体（stdlib）について、NVD の CPE（製品名と版の範囲）で照合する Grype 独自の方式による検出 | Grype の方式は範囲が広く、誤検出も含みうる |
| Go: OSV-Scanner だけ 157 件・だけ無い 11 件 | `github.com/cli/cli/v2` のような v2 以降のモジュールを、v1 の `github.com/cli/cli` と取り違えている（SBOM の PURL の `#v2` を読んでいない） | 誤検出と見落とし（OSV-Scanner 側） |
| Rust: OSV-Scanner だけ 20 件 | RustSec の参考情報（`unsound` など。脆弱性ではない） | 本ツール・Trivy・Grype は意図して対象外にしている |
| Python: OSV-Scanner だけ 2 件 | python-apt（Ubuntu のパッケージ）の版 `2.7.7+ubuntu5.3` を、修正版 `0.8.3ubuntu7.5` と比べられず、安全側で検出扱いにしている | 版としては修正版より新しい。本ツールの「影響なし」が妥当 |
| Ruby: Trivy だけ 8 件 | Trivy 独自のデータ源（ruby-advisory-db）の記録 | OSV.dev に無い分。本ツールでは拾えない |
| その他: Grype だけ 336 件 | ruby・python・node などの実行ファイルを、CPE で照合した検出 | 他のツールはこの方式を使わない |

## 追加の比較: Amazon Linux 2 の kernel 5.10（extras）

類似不良の調査で、Amazon Linux 2 の kernel 5.10 / 5.15 の修正情報が core に無いことが分かり、extras のトピックにも対応しました（[DEFECTS.md](DEFECTS.md) の #18・#19）。kernel 5.10 の古い版（`5.10.102-99.473.amzn2`）と nginx（nginx1 トピック）を入れた SBOM で比べた結果です。

| | 本ツール（対応前） | 本ツール（対応後） | Trivy | Grype |
|---|---|---|---|---|
| kernel | 0 | 3,867 | 0 | 4,548 |
| nginx | 0 | 40 | 0 | 40 |

- Trivy は extras の情報を持たず、kernel 5.10 も nginx も 0 件でした。
- Grype だけにある kernel の 1,416 件（kernel と kernel-headers の合計）は、すべて kernel-5.15 トピックの告知でした。kernel 5.10 のホストに 5.15 の修正版を当てはめた、Grype の誤検出です。kernel-5.10 トピックの告知は、本ツールがすべて検出しています。
- 本ツールだけにあるもの（Trivy・Grype のどちらにも無いもの）は 0 件でした。

## 比較で見つけて直した本ツールの不具合

比較の途中で、本ツールの不具合が2つ見つかったので直しました。上の表は修正後の数字です。

1. **Ubuntu Pro（ESM）でしか修正版が出ていない脆弱性を見落としていた。**
   - 内容: Ubuntu 24.04 の universe のパッケージ（ffmpeg、git-lfs など）は、修正版が Ubuntu Pro にしか無いことがあります。この場合、OSV.dev の情報は Pro 用（`Ubuntu:Pro:24.04:LTS`）にしか載りません。本ツールは Pro 用の情報を見ていなかったため、通常の 24.04 では未修正の脆弱性を見落としていました（修正前の集計で、他の3ツールが検出していて本ツールだけ無いものが 62 件）。
   - 修正: 通常用の情報が無い場合は Pro 用の情報で判定します。Pro の版（`+esm` を含む版）を入れていなければ、版番号によらず未修正とします（Trivy・Grype と同じ扱い）。備考に「修正版は Ubuntu Pro（ESM）でのみ提供」と出します。
2. **カーネルのヘッダだけのパッケージ（`linux-libc-dev`）に、カーネル本体の脆弱性を当てはめていた。**
   - 内容: ソースパッケージが `linux` であるため、カーネルの脆弱性約 450 件がそのまま当てはまっていました。
   - 修正: Trivy・Grype と同じく照合しないようにしました。

## 結論

| 種類 | 本ツールの結果の扱い |
|---|---|
| Amazon Linux 2 / 2023 の OS パッケージ | **信頼できる。** Grype と完全に一致し、Trivy より多い。Trivy は syft の SBOM では照合できず、OSV-Scanner は照合対象外 |
| Java / Python / npm / Go / Rust のライブラリ | **信頼できる。** 他のツールの検出の共通部分をすべて含む。他ツールだけの検出は、ツール側の誤検出か、独自の照合方式（CPE）によるもの |
| Ruby | おおむね信頼できる。Trivy 独自のデータ源の分（8 件）だけ少ない |
| Ubuntu の OS パッケージ | **Grype とほぼ一致**（本ツールだけ 31 件、Grype だけ 1 件）。Trivy は大幅に少なく、OSV-Scanner は誤検出が多い |
| 実行ファイル自体（ruby・python・node のバイナリなど） | 本ツールは照合しない（Grype の CPE 照合に相当する機能は無い） |

## 再実行の手順

比較に使ったコマンドです（Linux）。数え方は上の「数え方」のとおりで、集計用のスクリプトはリポジトリに入れていません。

```
# SBOM（例: このコンテナ全体）
syft scan dir:/ --exclude ./proc --exclude ./sys --exclude ./dev -o cyclonedx-json=container.cdx.json

# 本ツール
python -m vuln_triage db-update --inventory-dir inventory      # inventory/<環境名>/container.cdx.json
python -m vuln_triage run --inventory-dir inventory --advisory 通達.xlsx --out-dir out   # 新規検出シートに全検出

# Trivy（Amazon Linux は OS 名・PURL を amazon に直した SBOM で）
trivy sbom --format json container.cdx.json > trivy.json

# Grype
grype db update
grype sbom:container.cdx.json -o json --file grype.json

# OSV-Scanner（オフラインのデータで）
osv-scanner scan source -L container.cdx.json --offline-vulnerabilities --download-offline-databases --format json --output osvscanner.json
```
