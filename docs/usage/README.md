# 使い方

ツールの概要と用語は [README](https://github.com/hsgwa/cve_chk/blob/main/README.md) を見てください。

## 流れ

1. 管理 PC にツールを置き、脆弱性データを取得する: [setup.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/setup.md)
2. 対象マシンで回収する: [collect.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/collect.md)（zip・jar などのファイルは [scan-file.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/scan-file.md)）
3. 回収物・環境マスタ・会社公表リストを作業フォルダに置く: [files.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/files.md)
4. 調査を実行する: [check.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/check.md)
5. レポートを読む: [report.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/report.md)

本番導入の計画は [ROLLOUT.md](https://github.com/hsgwa/cve_chk/blob/main/docs/ROLLOUT.md)、運用と困ったときは [OPERATIONS.md](https://github.com/hsgwa/cve_chk/blob/main/docs/OPERATIONS.md)、開発は [DEVELOPMENT.md](https://github.com/hsgwa/cve_chk/blob/main/docs/DEVELOPMENT.md) にあります。

## この文書の書き方

- 管理 PC のコマンドは `zk <コマンド>` と書きます。**ツールのフォルダ（zip を展開したフォルダ）で実行します。** PowerShell では `.\zk` と打ちます。
- 作業フォルダは `D:\vuln` とします（構成は [files.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/files.md)）。
- 対象マシンでは、回収スクリプトを置くフォルダを Linux は `/opt/vuln-collect`、Windows は `C:\vuln-collect` とします。

## コマンド

| コマンド | すること |
|---|---|
| `zk update` | 脆弱性データを最新にする |
| `zk preview` | 入力の読み込み結果だけを見る（判定しない） |
| `zk check` | 照合してレポートを出す |
| `zk scan-file` | zip・jar・war などのファイルを調べて回収物にする |
| `zk export-sbom` | Windows の回収物から SBOM を書き出す（Trivy を使う場合） |
| `scripts\check_all.ps1` | `update` と `check` をまとめて実行する（ふだんはこれ） |

オプションの一覧は `zk <コマンド> --help` で見られます。
