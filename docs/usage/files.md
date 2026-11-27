# ファイルと形式

## 作業フォルダ

```
D:\vuln\
  inventory\<環境名>\   回収物（人が置く）
  advisory\             会社公表リスト（人が置く。最も新しいファイルを使う）
  env_master.csv        環境マスタ（人が用意する）
  reports\<日付>\       レポート（自動。reports\latest.txt に最新のフォルダ名）
  logs\                 実行ログ（自動。90 日で消える）
```

ローカルのディスクに作ります。`%TEMP%` など自動で掃除される場所は使いません。

## 回収物 `inventory\<環境名>\`

フォルダ名が環境名になります。

```
inventory\
  web-ec2\      cdx_syft.json  os_info.json
  batch-emr\    cdx_syft.json  os_info.json
  win-app01\    inventory.json
  lambda-api\   archive_inventory.json
```

読み込む形式:

| 形式 | 作るもの |
|---|---|
| `cdx_syft.json` + `os_info.json` | `collect_linux.sh` |
| `inventory.json` | `collect_win.ps1` |
| `archive_inventory.json` | `zk scan-file` |
| CycloneDX JSON（`*.json`） | syft、Amazon Inspector など |
| `winget export`、`Get-HotFix \| ConvertTo-Json`、`VersionInfo` の JSON | Windows のコマンド |

## 環境マスタ `env_master.csv`

```
env_name,exposure,system_name
web-ec2,internet,受発注Web
batch-emr,internal,分析基盤
```

- `exposure` は `internet`（外部公開）か `internal`（社内限定）。ランクの決め方が変わります。未登録の環境は `internal` として扱い、警告します。
- **対象ホストの台帳として使います。** 登録済みで回収物が無い環境は「判定不能（回収漏れ）」になります。対象のホストはすべて登録します。

## 会社公表リスト `advisory\*.xlsx` / `.xlsm` / `.csv`

会社の Excel をそのまま置きます。見出しの対応は `config.yaml` の `advisory_input` に書きます（`columns`、`sheet`、見出し行、`fill_merged`）。

| 項目 | 内容 |
|---|---|
| `advisory_id` | 通達番号 |
| `cve_id` | CVE 番号。1 セルに複数あれば CVE ごとに判定 |
| `product_name` | 製品名 |
| `affected_version` | 影響する版の条件 |
| `published_date` | 公表日。対応期限の起点 |
| `company_rank` / `deadline_days` | 社内ランクと期限日数。書いてあれば最優先 |
| `note` | 備考 |

1 行の書き方:

| 種類 | 書き方 | 判定 |
|---|---|---|
| CVE | `cve_id`。`product_name` と `affected_version` も書くと精度が上がる | 脆弱性データ。Windows OS は OS のビルド番号 |
| 製品名＋版 | `product_name` と `affected_version`（例 `>=2.0.0,<2.17.1`、`<=3.0.12`、`9.0.*`） | 回収物の名前と版 |
| Windows パッチ | `product_name` に KB 番号、`affected_version` に `missing`。`KB5034441\|KB5035845` はどれかが適用済みなら可 | 適用済み KB |

- **版の条件は Excel で文字列として入力します。** 数値の `9.0` は `9` になります。
- 製品名は大文字小文字と区切り（空白、`_`、`.`、`-`）を無視した完全一致です。`Apache Tomcat*`（ワイルドカード）、`re:^HULFT\d`（正規表現）も使えます。呼び名の違いは `config.yaml` の `aliases` に登録します。
- **製品名の無い CVE だけの行は、「未使用」と「影響なし」を区別できません**（「影響なし（CVE未検出）」）。
- 読み落としの恐れがあれば警告します: データのある他のシート（読むのは 1 シートだけ）、縦の結合セル（`fill_merged: false` のとき）、CVE 番号として読めない記載。`zk preview` で確かめられます。
