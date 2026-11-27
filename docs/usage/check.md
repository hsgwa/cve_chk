# 調べる

## 1 台を調べる

```
zk check D:\vuln\inventory\web01
zk check D:\vuln\inventory\web01 --cve-list D:\vuln\cve_list\通達.xlsx
```

- 引数は、1 台ぶんの回収物のフォルダです（対象マシンの `out\<ホスト名>\` をそのまま置いたもの）。
- レポートは `out\<サーバー名>\` に出ます（`--out-dir` で変更）。
- `--cve-list` を付けると、その CVE ごとの影響の有無（「CVE の判定」シート）も出します。
- 先に脆弱性の情報が要ります。初回やソフトの種類が増えたときは、`zk update --inventory-dir D:\vuln\inventory\web01` を実行します。

主なオプション（全部は `zk check --help`）:

| オプション | 内容 |
|---|---|
| `--cve-list ファイル` | 調べたい CVE の一覧（[files.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/files.md)） |
| `--out-dir フォルダ` | レポートの出力先（既定 `out\<サーバー名>`） |
| `--previous フォルダ` | 前回の出力フォルダ。比べて「前回との差分」を出す（出力先とは別のフォルダ） |
| `--db-dir フォルダ` | 脆弱性の情報の場所（既定 `vulndb`） |
| `--no-msrc` / `--offline` | Windows OS の判定をしない / キャッシュだけで行う |
| `--resolve-hashes` | 名前の分からない jar を SHA-1 で Maven Central に照会する（送るのは SHA-1 だけ） |
| `--no-xlsx` | Excel を出さない（CSV だけ） |
| `--scanner trivy` | 手元の脆弱性の情報の代わりに Trivy で照合する（下を参照） |

読み込みだけ確かめるときは `zk preview D:\vuln\inventory\web01 --cve-list D:\vuln\cve_list\通達.xlsx` を使います（照合はしません）。

## 全サーバーを 1 台ずつ調べる

ツールのフォルダで実行します。脆弱性の情報を 1 回更新し、`inventory\` の下のサーバーごとに `zk check` を実行します。

```
powershell -ExecutionPolicy Bypass -File scripts\check_all.ps1 -BaseDir D:\vuln
```

- 作業フォルダの決まった場所を使います（[files.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/files.md)）。`cve_list\` に一覧があれば、最も新しいファイルを使います。
- レポートは `D:\vuln\reports\<日付>\<サーバー名>\` に出ます。同じ日の 2 回目は `<日付>_<時刻>\` です。
- 前回のレポートがあれば、サーバーごとに「前回との差分」も出します。
- 結果は `D:\vuln\logs\run_<日付>.log` の最後の行（「終了: 成功」/「終了: 失敗」）で確かめます。
- 終了コード: 0 = 成功、1 = 脆弱性の情報の更新の一部に失敗（前回の情報で照合した）、2 = 調べられなかったサーバーがある。

| 引数 | 内容 |
|---|---|
| `-BaseDir` | 作業フォルダ（必須） |
| `-SkipDbUpdate` | 脆弱性の情報を更新しない（同じ日に更新済みのとき） |
| `-DbDir` / `-Config` | 脆弱性の情報の場所 / 設定ファイル |
| `-Python` | python.exe の場所（既定は同梱の Python、無ければ PATH の python） |

## Trivy を使う場合（任意）

```
zk check D:\vuln\inventory\web01 --scanner trivy [--save-trivy-json フォルダ] [--trivy-results-dir フォルダ]
```

`trivy.exe` は PATH に置くか、`config.yaml` の `trivy.path` に書きます。**Trivy は syft の SBOM の Amazon Linux を「未対応の OS」として扱い、OS パッケージを照合しません。** Amazon Linux なら既定の照合を使います。
