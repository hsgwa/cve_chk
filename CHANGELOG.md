# 変更履歴

## 未リリース

### 変更
- 使い方の文書を `docs/usage/` に分けた（準備、回収、zip・jar の調べ方、ファイルと形式、調査の実行、レポートの読み方）。開発は `docs/DEVELOPMENT.md`。重複と冗長な説明を削った。
- 文書のコマンドの書き方を `zk <コマンド>`（ツールのフォルダで実行）と作業フォルダ `D:\vuln` にそろえた。
- インストール不要の配布物にサンプル（`examples/`）を入れた。zip だけで動作確認ができる。

## 0.9.0（2026-11-27）

### 追加
- **インストール不要の配布物（ポータブル版）**。リリースに zip を付ける: Windows x64 / ARM64 用（python.org の「埋め込み用」Python を同梱。Python のインストールも不要）と、Python 3.10 以降で動く版。展開して `zk.cmd` を使い、要らなくなればフォルダごと消す。中身はツールと依存ライブラリを 1 つにした `zk.pyz`、`zk.cmd` / `zk`、`scripts/check_all.ps1`、回収スクリプト、`config.yaml`、ライセンス（同梱したライブラリと Python のものを含む）。
- CI で、ポータブル版を作り、Windows Server で同梱の Python だけを使って照合と `check_all.ps1` を試す。リリースを公開すると、配布物を作って添付する（`.github/workflows/release.yml`）。

### 修正
- `check_all.ps1` の起動の引数の不具合（[docs/DEFECTS.md](https://github.com/hsgwa/cve_chk/blob/main/docs/DEFECTS.md) の #48）。
- 名前の変更で、文書のアンインストールの手順の一部が誤っていた（`pip uninstall -y zk` → `zeijaku-kakunin`、0.4.0 以前のタスク名）。

## 0.8.0（2026-11-27）

### 変更（名前）
- ツール名を **脆弱確認（zk）** にした。コマンドは `zk`、パッケージ名は `zeijaku-kakunin`（PyPI・GitHub で使われていない名前）、Python のモジュール名は `zeijaku_kakunin`。同じ働きの長いコマンド名 `zeijaku-kakunin` もある（別のツールの `zk` と重なる場合用）。
- コマンド名: `db-update` → `update`、`run` → `check`、`check-inputs` → `preview`、`scan-archive` → `scan-file`、`build-sbom` → `export-sbom`。スクリプト: `run_check.ps1` → `check_all.ps1`。
- 旧名（`vuln-triage` と上の旧コマンド名）もしばらく使える。使うと新しい名前を案内する。
- 回収物の形式（`vuln-triage-inventory/1` など）は変えていない。これまでの回収物はそのまま使える。
- 移行: `pip uninstall vuln-triage` のあと `pip install -e .` をやり直す。

## 0.7.0（2026-11-27）

### 追加
- `vuln-triage scan-archive`: zip・jar・war・ear・whl（と展開したフォルダ）の中のライブラリを管理 PC で直接調べ、回収物として置く。Lambda のデプロイ用 zip とレイヤー、war や fat jar（入れ子の jar もたどる）、Python・npm・.NET に対応。syft も展開も使わない。実物（`pip install requests==2.25.0` で作った Lambda の zip と log4j の jar）で、依存ライブラリまで見つけて影響ありと判定することを確かめた。

### 文書
- 使う容量の実測値（対象マシン、管理 PC の脆弱性データとレポート）。管理 PC の空きの目安を 5 GB に直した。

## 0.6.0（2026-11-27）

- 対象マシンでは、回収スクリプトを置いたフォルダの中だけに書き込むようにした（Linux の syft の一時ファイル・キャッシュも含む）。回収後にフォルダを消せば元の状態に戻る。実行前とフォルダ削除後で差が無いことを CI で確かめる（Amazon Linux 2023・Ubuntu 24.04 はファイルシステム全体、Windows Server はプロファイル・一時フォルダ・ProgramData・インストール済みソフト・サービス・タスク）。
- 回収スクリプトは、出力先の空きが 500 MB 未満なら何も書かずに止める（終了コード 4）。Linux の syft にメモリの目安（`SYFT_MEMORY_LIMIT`、既定 1 GiB）。
- 修正: [docs/DEFECTS.md](https://github.com/hsgwa/cve_chk/blob/main/docs/DEFECTS.md) の #45〜#47（Linux の作業フォルダの削除、Windows のファイルの開き方、syft の一時ファイルの置き場所）。
- 管理 PC のアンインストールの手順（[docs/usage/setup.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/setup.md)）。
- 文書の図を draw.io の図（`docs/images/*.drawio.png`。図のデータを埋め込んだ PNG で、draw.io でそのまま編集できる）にした。全体の構成、処理の流れ、照合と判定の仕組み、仕組みの全体の流れの 4 枚。

## 0.5.0（2026-11-27）

### 変更
- 調査は都度スクリプトを実行する形にした。`scripts/daily_run.ps1` を `scripts/run_check.ps1` に改名し（データの更新 → 照合 → レポート、前回との差分つき）、タスクスケジューラへの登録（`register_daily_task.ps1`）とデータの更新だけのスクリプト（`daily_db_update.ps1`）を削除した。
- README を概要（特徴、用語、構成と仕組みの図、処理の流れ）だけにし、使い方を [docs/usage/](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/README.md) に移した。図は、どの表示環境でも崩れない文字の図にした。

## 0.4.0（2026-11-27）

### 追加
- 毎日の自動実行 `scripts/daily_run.ps1`（データの更新 → 照合 → `reports/<日付>/`、前回との差分つき）。`register_daily_task.ps1 -Run -BaseDir <作業フォルダ>` で登録する。
- Linux の回収で、syft の tar.gz を配布元のチェックサム（`syft_<版>_checksums.txt`）で確かめる。一致しなければ実行しない。`REQUIRE_SYFT_CHECKSUM=1` で確かめられないときも実行しない。
- [docs/ROLLOUT.md](https://github.com/hsgwa/cve_chk/blob/main/docs/ROLLOUT.md)（本番導入の計画: 自動化の範囲、人の作業、チェックリスト、リスク、判定できない範囲）。
- CI: 毎日の自動実行をタスクスケジューラで 2 回実行して確かめる。最新の syft でも回収から照合まで試す。改ざんした syft を実行しないことを確かめる。

### 修正
- 回収に使う syft の tar.gz を、版の順で最も新しいものにした（文字の順では 1.9 が 1.18 より新しく見えた）。

## 0.3.0（2026-11-27）

### 追加
- `run --previous <前回の出力フォルダ>`: 「前回との差分」シートと `report_changes.csv`。新たに影響あり / 解消 / 継続 / 今回の回収なし。
- Excel の 1 シートの行数の上限（`xlsx_max_rows`、既定 10 万行）。超えた分は CSV にだけ出し、サマリに注意を出す。

### 改善
- Ubuntu の照合を速くした（実機の Ubuntu 24.04 を含む 4 環境で 349 秒 → 121 秒、結果は同じ）。大きな記録（カーネルの CVE など）の縮小版を索引に入れる。既存の索引には、次の `db-update` で縮小版を作る（初回のみ数分）。
- `--resolve-hashes` を Maven Central に実際に接続して確かめた。

## 0.2.0（2026-11-26）

実機（Windows 11、Windows Server、Ubuntu 24.04、Amazon Linux 2 / 2023）で回収から照合までを確かめ、現在の Grype と結果を比べた版です（[docs/COMPARISON.md](https://github.com/hsgwa/cve_chk/blob/main/docs/COMPARISON.md)）。

### 追加
- 「要更新パッケージ」シートと `report_updates.csv`。影響ありの検出を環境 × パッケージにまとめ、すべてが直る版を出す。
- 回収スクリプトは既定で優先度を下げて実行する（Linux: `nice -n 19`、`ionice -c3`。Windows: 通常以下）。所要時間を記録する。
- Linux の回収で syft の打ち切り時間（`SYFT_TIMEOUT_SEC`、既定 3 時間）。
- syft だけで回収した SBOM での照合（README の手順）。
- `register_daily_task.ps1 -NoPassword`（パスワードを保存せずにログオフ中も実行する）。
- 環境マスタにあって回収されていない環境を「判定不能（回収漏れ）」として出す。
- 会社公表リストの読み落とし（他のシート、結合セル、読めない CVE 番号）の警告。
- CI（GitHub Actions）。Windows と Linux での単体テスト、Windows Server と Amazon Linux / Ubuntu での回収から照合までの試験、タスクの登録の試験。
- [docs/DESIGN.md](https://github.com/hsgwa/cve_chk/blob/main/docs/DESIGN.md)（仕組み）、[docs/OPERATIONS.md](https://github.com/hsgwa/cve_chk/blob/main/docs/OPERATIONS.md)（運用の手引き）。
- ライセンス: MIT No Attribution（MIT-0）。

### 修正
- [docs/DEFECTS.md](https://github.com/hsgwa/cve_chk/blob/main/docs/DEFECTS.md) の #32〜#44。主なもの:
  - Windows の `-ScanRoots 'a','b'` で走査対象が空になる（#37）。
  - Amazon Linux 2023 の実行ファイルのパッケージ情報、系統名つきのカーネルのヘッダ、rpm のサブパッケージ、Ubuntu Pro の Livepatch の告知による誤検出（#38〜#41）。
  - Ubuntu のカーネルの照合と Excel の書き出しが遅い（#42、#43）。
  - OS を判別できない環境を、KB と Windows OS の CVE で「対象外」にする（#36）。
  - 英語版 Windows などで、日本語の表示のところで止まる（#44）。

## 0.1.0（2026-11-20）

最初の版。
