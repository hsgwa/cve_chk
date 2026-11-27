# 管理 PC の準備

## ツールを置く

[リリース](https://github.com/hsgwa/cve_chk/releases)から zip を取得し、ローカルのディスクに展開します。インストールも管理者の権限も要りません。

| ファイル | 対象 |
|---|---|
| `zeijaku-kakunin-<版>-windows-x64.zip` | Windows（Python 同梱） |
| `zeijaku-kakunin-<版>-windows-arm64.zip` | ARM の Windows（Python 同梱） |
| `zeijaku-kakunin-<版>.zip` | Python 3.10 以降がある PC（Linux も可。コマンドは `./zk`） |

- 中身: `zk.cmd` / `zk`（コマンド）、`zk.pyz`（ツール本体と依存ライブラリ）、`python\`（python.org の埋め込み用 Python）、`scripts\check_all.ps1`、`collectors\`（回収スクリプト）、`examples\`（サンプル）、`config.yaml`、ライセンス。
- 同梱の Python は展開したフォルダの中だけを使います。PC の Python や設定には触れません。
- 脆弱性データ（`vulndb\`）とキャッシュ（`cache\`）は、ツールのフォルダにできます。

動作確認: `zk demo` で、同梱のサンプルからレポートの見本（`demo\report.xlsx`）を作ります。ネット接続は要りません。

### pip で入れる場合（開発者向け）

リポジトリを取得したフォルダで `pip install -e .` を実行すると `zk` コマンドが使えます（Python 3.10 以降）。

- `zk` が見つからなければ、`python -m zeijaku_kakunin` で実行します。
- 別のツールの `zk` と重なる場合は、同じ働きの `zeijaku-kakunin` を使います。
- 0.7.0 までの名前（`vuln-triage`、`db-update`、`run` など）もしばらく使えます。

## 脆弱性データを取得する

照合は、手元に取得した脆弱性データだけで行います。**`check_all.ps1` が照合の前に自動で取得・更新するので、ふだんは何もしなくてかまいません。** 初回は数十分かかり、約 2.3 GB を使います（空きは 5 GB 以上）。

手で取得する場合は、回収物を置いてから実行します。

```
zk update --inventory-dir D:\vuln\inventory
```

回収物に出てくるパッケージの種類だけを取得し、照合用の索引（SQLite）を作ります。

- 2 回目以降は差分だけを取り直します（OSV.dev の `modified_id.csv`）。7 日ごと（`vulndb.full_refresh_days`）と `--full` のときは全件を取り直します。
- 更新に失敗したデータは前回の内容のまま残ります（終了コード 1）。
- 最後の更新から 1 日を超えたデータで照合すると、サマリに警告が出ます。
- 取得済みのデータは `zk update --list` で確認できます。
- 分類していない系統がデータに現れると警告します（[DEFECTS.md](https://github.com/hsgwa/cve_chk/blob/main/docs/DEFECTS.md) の手順で確認）。

| データ | 取得元 | 初回の大きさ |
|---|---|---|
| Maven / PyPI / npm / NuGet / Go / Rust / Ruby など | OSV.dev | Maven 10 MB、PyPI 37 MB、npm 212 MB など |
| Amazon Linux 2 / 2023 | 公式リポジトリの updateinfo | 各 2〜3 MB |
| Ubuntu / Debian / RHEL / Rocky / AlmaLinux | OSV.dev | Ubuntu 784 MB、Debian 80 MB、Red Hat 28 MB |

接続先（HTTPS。Amazon Linux 2 は HTTP）: `osv-vulnerabilities.storage.googleapis.com`、`amazonlinux.default.amazonaws.com`、`cdn.amazonlinux.com`、`al2023-repos-*.s3.dualstack.*.amazonaws.com`、`api.msrc.microsoft.com`（Windows OS の判定）。プロキシは `HTTPS_PROXY` / `HTTP_PROXY` で指定します。送るのはダウンロードの要求だけです。

接続できない場合は、別の PC で `https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip` などを保存し、`zk update --import Maven=Maven.zip` で取り込みます（差分更新はできません）。

## ツールを新しい版にする

新しい zip を別のフォルダに展開し、古いフォルダの `vulndb\` と `cache\` を移します（移さなければ次の `update` で取り直します）。`config.yaml` を変えていれば、それも移します。

## アンインストール

**レポート（`D:\vuln\reports\`）は証跡なので、必要なら先に保管してください。**

| 消すもの | 消し方 |
|---|---|
| ツールのフォルダ（`vulndb\`、`cache\`、`out\` を含む） | フォルダごと削除 |
| 作業フォルダ（`D:\vuln`） | フォルダごと削除 |
| 別の場所に置いた脆弱性データ（`--db-dir`、`vulndb.dir`） | フォルダごと削除 |
| pip で入れた場合のツール | `python -m pip uninstall -y zeijaku-kakunin`（0.7.0 以前は `vuln-triage`） |
| pip で入れた場合の依存ライブラリ | 他で使っていなければ `python -m pip uninstall -y pyyaml packaging click openpyxl et-xmlfile` |
| 0.4.0 以前のタスクスケジューラの登録 | `Unregister-ScheduledTask -TaskName "vuln-triage db-update" -Confirm:$false`（`vuln-triage run` も同じ） |

このほかにレジストリ・サービス・タスク・環境変数は変更しません。
