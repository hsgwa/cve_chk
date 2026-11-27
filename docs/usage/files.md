# ファイルと形式

## 作業フォルダ

```
D:\vuln\
  inventory\<サーバー名>\   回収物（人が置く）
  cve_list\                CVE の一覧（任意。人が置く。最も新しいファイルを使う）
  reports\<日付>\<サーバー名>\   レポート（自動。reports\latest.txt に最新の日付）
  logs\                    実行ログ（自動。90 日で消える）
```

`zk init D:\vuln` で作れます。ローカルのディスクに作ります。`%TEMP%` など自動で掃除される場所は使いません。

## 回収物 `inventory\<サーバー名>\`

サーバー 1 台につきフォルダ 1 つです。フォルダ名がサーバー名になります。

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

## CVE の一覧 `cve_list\`

調べたい CVE 番号の一覧です。**無くてもかまいません。** 無ければ、見つかった脆弱性をすべてレポートに出します。

- 形式: Excel（`.xlsx` / `.xlsm`）、CSV、テキスト。古い Excel 形式（`.xls`）は `.xlsx` で保存し直します。
- **書式は問いません。** すべてのシートのすべてのセルから、`CVE-年-番号` の形の文字列を拾います。会社の通達の Excel をそのまま置けます。列の名前や並びを設定する必要はありません。
- 全角や小文字（`ｃｖｅ－２０２１－４４２２８`）でも読みます。同じ CVE が何度出てきても 1 つにします。
- `CVE2024-0001`（ハイフン抜け）や `CVE-2024-123`（桁不足）のような書き損じは、場所を示して警告します。`zk preview <回収物> --cve-list <ファイル>` で確かめられます。
- CVE 番号の無い通達（製品名と版だけのもの）は読めません。そのような製品は、レポートの「脆弱性の一覧」や回収物で人が確かめます。

例（会社の通達の Excel）:

| 通達番号 | CVE番号 | 備考 |
|---|---|---|
| ADV-001 | CVE-2021-44228 | Log4Shell |
| ADV-002 | CVE-2022-42889, CVE-2023-32681 | 1 つのセルに複数あってもよい |
