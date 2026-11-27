# はじめに

初めて使う人は、このページを上から順に読んで進めてください。

## このツールでできること

会社から「この脆弱性に対応すること」という通達が出たときに、**社内のどのサーバーが該当するか**を調べて Excel のレポートにします。インターネットにつながらないサーバーも調べられます。

![全体の構成](https://github.com/hsgwa/cve_chk/raw/main/docs/images/architecture.drawio.png)

1. 調べたいサーバーで、入っているソフトの一覧を作る（**回収**）。
2. 一覧を、インターネットにつながる PC（**管理 PC**）に持ってくる。
3. 管理 PC で、一覧と脆弱性の情報を突き合わせ、レポートを作る。

## 言葉

| 言葉 | 意味 |
|---|---|
| 対象マシン | 脆弱性を調べたいサーバー |
| 管理 PC | このツールを動かす PC。インターネットにつながっていること |
| 回収物 | 対象マシンで作った、ソフトの一覧のファイル |
| サーバー一覧 | 調べる対象マシンを書いた表（`env_master.csv`）。下の手順 3 で書く |
| 会社公表リスト | 会社が出す脆弱性の通達の一覧（Excel か CSV） |
| 作業フォルダ | 回収物・サーバー一覧・会社公表リスト・レポートを置くフォルダ。この文書では `D:\vuln` |

## まず試す（5 分）

1. [リリース](https://github.com/hsgwa/cve_chk/releases)から `zeijaku-kakunin-<版>-windows-x64.zip` を取得し、展開する（例 `D:\zk`）。インストールも管理者の権限も要りません。
2. 展開したフォルダでコマンドプロンプトを開き、次を実行する。

   ```
   zk demo
   ```

3. 表示された `report.xlsx` を開く。同梱のサンプル（架空のサーバー 4 台、通達 11 件）でのレポートの見本です。読み方は [report.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/report.md) にあります。

コマンドは、展開したフォルダ（ツールのフォルダ）で実行します。PowerShell では `zk` の代わりに `.\zk` と打ちます。

## 本番で使う

### 1. 作業フォルダを作る

```
zk init D:\vuln
```

`D:\vuln` に、置き場所のフォルダ（`inventory`、`advisory`）、空のサーバー一覧（`env_master.csv`）、説明（`はじめに.txt`）ができます。

### 2. 対象マシンで回収する

ツールのフォルダの `collectors\` にある回収スクリプトを、対象マシンに持っていって実行します。

| 対象マシン | 実行するもの |
|---|---|
| Linux | `collect_linux.sh` と [syft](https://github.com/anchore/syft/releases)（`syft_<版>_linux_amd64.tar.gz` と `syft_<版>_checksums.txt`）を同じフォルダに置き、`sudo bash collect_linux.sh` |
| Windows | `collect_win.ps1` を置き、管理者の PowerShell で `powershell -ExecutionPolicy Bypass -File collect_win.ps1` |

できた `out\<ホスト名>\` フォルダを管理 PC に持ってきて、`D:\vuln\inventory\` の下にフォルダごと置きます。対象マシンでは、スクリプトを置いたフォルダを消せば元どおりです。詳しくは [collect.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/collect.md)。

### 3. サーバー一覧を書く

`D:\vuln\env_master.csv` を Excel かメモ帳で開き、調べる対象マシンを 1 行ずつ書きます。

```
env_name,exposure,system_name
web01,internet,受発注Web
batch01,internal,分析基盤
```

| 列 | 書くこと |
|---|---|
| `env_name` | `inventory\` の下に置いたフォルダの名前（ふつうはホスト名） |
| `exposure` | `internet`（インターネットに公開している）か `internal`（社内だけ）。対応期限の決め方が変わる |
| `system_name` | システム名（メモ。空でもよい） |

ここに書いたのに回収物が無いサーバーは、レポートで「回収漏れ」と出ます。**回収し忘れに気づけるよう、対象のサーバーはすべて書いてください。**

### 4. 会社公表リストを置く

会社の通達の Excel を `D:\vuln\advisory\` に置きます。初めての書式なら、列の対応を `config.yaml` に書き、次で正しく読めるかを確かめます（[files.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/files.md)）。

```
zk preview --inventory-dir D:\vuln\inventory --advisory D:\vuln\advisory\通達.xlsx
```

### 5. 調査を実行する

```
powershell -ExecutionPolicy Bypass -File scripts\check_all.ps1 -BaseDir D:\vuln
```

インターネットから脆弱性の情報を取得（2 回目からは差分だけ更新）してから照合し、`D:\vuln\reports\<日付>\report.xlsx` を作ります。最後に「終了: 成功」と出れば完了です。**初回は情報の取得（約 2.3 GB）に数十分かかります。** 空きを 5 GB 以上用意してください。

### 6. レポートを見る

「要更新パッケージ」シートから見ます。サーバーごとに、どのソフトをどの版に上げればよいかが並んでいます（[report.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/report.md)）。

次からは、通達が出たら手順 4 と 5、サーバーのソフトが変わったら手順 2 と 5 を繰り返します。

## 詳しい説明

| ページ | 内容 |
|---|---|
| [setup.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/setup.md) | 管理 PC の準備、脆弱性の情報の取得、版の入れ替え、アンインストール |
| [collect.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/collect.md) | 対象マシンでの回収 |
| [scan-file.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/scan-file.md) | zip・jar・war のファイルを調べる（Lambda など） |
| [files.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/files.md) | 作業フォルダ、回収物、サーバー一覧、会社公表リストの書き方 |
| [check.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/check.md) | 調査の実行とオプション |
| [report.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/report.md) | レポートの読み方、判定の意味、結果の限界 |
| [OPERATIONS.md](https://github.com/hsgwa/cve_chk/blob/main/docs/OPERATIONS.md) | 運用の注意と、困ったとき |
| [ROLLOUT.md](https://github.com/hsgwa/cve_chk/blob/main/docs/ROLLOUT.md) | 本番導入の計画（分担、チェックリスト、リスク） |

## コマンドの一覧

| コマンド | すること |
|---|---|
| `zk demo` | サンプルでレポートの見本を作る |
| `zk init <フォルダ>` | 作業フォルダを作る |
| `zk update` | 脆弱性の情報を最新にする |
| `zk preview` | 回収物と会社公表リストの読み込み結果を見る（判定しない） |
| `zk check` | 照合してレポートを出す |
| `zk scan-file` | zip・jar などのファイルを調べて回収物にする |
| `zk export-sbom` | Windows の回収物から SBOM を書き出す（Trivy を使う場合） |
| `scripts\check_all.ps1` | `zk update` と `zk check` をまとめて実行する（ふだんはこれ） |

オプションは `zk <コマンド> --help` で見られます。
