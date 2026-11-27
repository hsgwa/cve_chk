# 調査の実行

## まとめて実行する（ふだんはこれ）

ツールのフォルダで実行します。脆弱性データの更新、照合、レポートの作成を順に行います。

```
powershell -ExecutionPolicy Bypass -File scripts\check_all.ps1 -BaseDir D:\vuln
```

- 作業フォルダの決まった場所を使います（[files.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/files.md)）。
- レポートは `D:\vuln\reports\<日付>\` に出ます。同じ日の 2 回目は `<日付>_<時刻>\` です。
- 前回のレポートがあれば「前回との差分」も出します。
- 結果は `D:\vuln\logs\run_<日付>.log` の最後の行（「終了: 成功」/「終了: 失敗」）で確かめます。
- 終了コード: 0 = 成功、1 = データの更新の一部に失敗（前回のデータで照合した）、2 = 照合できなかった。

| 引数 | 内容 |
|---|---|
| `-BaseDir` | 作業フォルダ（必須） |
| `-SkipDbUpdate` | 脆弱性データを更新しない（同じ日に更新済みのとき） |
| `-DbDir` / `-Config` | 脆弱性データの場所 / 設定ファイル |
| `-Python` | python.exe の場所（既定は同梱の Python、無ければ PATH の python） |

## 個別に実行する

```
zk update --inventory-dir D:\vuln\inventory
zk preview --inventory-dir D:\vuln\inventory --env-master D:\vuln\env_master.csv --advisory D:\vuln\advisory\通達.xlsx
zk check --inventory-dir D:\vuln\inventory --env-master D:\vuln\env_master.csv --advisory D:\vuln\advisory\通達.xlsx --out-dir D:\vuln\reports\手動
```

`zk preview` は判定せず、回収物の読み込み結果と、通達の製品名がどの回収物に当たったかを出します。**新しい通達を置いたら、まず `zk preview` で「該当なし」が表記ゆれでないかを確かめます。**

`zk check` の主なオプション:

| オプション | 内容 |
|---|---|
| `--previous DIR` | 前回の出力フォルダと比べ、「前回との差分」を出す（`--out-dir` と別のフォルダ） |
| `--only-advisory` | 会社公表リストにある脆弱性だけを出す |
| `--base-date YYYY-MM-DD` | 実行日として扱う日付 |
| `--db-dir DIR` | 脆弱性データの場所（既定 `vulndb`） |
| `--no-msrc` / `--offline` | Windows OS の判定をしない / キャッシュだけで行う |
| `--resolve-hashes` | 名前の分からない jar を SHA-1 で Maven Central に照会する（送るのは SHA-1 だけ） |
| `--scanner osv / trivy / none` | CVE の照合方法（既定 `osv`） |

## Trivy を使う場合（任意）

```
zk check ... --scanner trivy [--save-trivy-json DIR] [--trivy-results-dir DIR]
```

`trivy.exe` は PATH に置くか、`config.yaml` の `trivy.path` に書きます。**Trivy は syft の SBOM の Amazon Linux を「未対応の OS」として扱い、OS パッケージを照合しません。** Amazon Linux があれば既定の `osv` を使います。
