# 変更履歴

## 0.4.0（2026-11-27）

### 追加
- 毎日の自動実行 `scripts/daily_run.ps1`（データの更新 → 照合 → `reports/<日付>/`、前回との差分つき）。`register_daily_task.ps1 -Run -BaseDir <作業フォルダ>` で登録する。
- Linux の回収で、syft の tar.gz を配布元のチェックサム（`syft_<版>_checksums.txt`）で確かめる。一致しなければ実行しない。`REQUIRE_SYFT_CHECKSUM=1` で確かめられないときも実行しない。
- [docs/ROLLOUT.md](docs/ROLLOUT.md)（本番導入の計画: 自動化の範囲、人の作業、チェックリスト、リスク、判定できない範囲）。
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

実機（Windows 11、Windows Server、Ubuntu 24.04、Amazon Linux 2 / 2023）で回収から照合までを確かめ、現在の Grype と結果を比べた版です（[docs/COMPARISON.md](docs/COMPARISON.md)）。

### 追加
- 「要更新パッケージ」シートと `report_updates.csv`。影響ありの検出を環境 × パッケージにまとめ、すべてが直る版を出す。
- 回収スクリプトは既定で優先度を下げて実行する（Linux: `nice -n 19`、`ionice -c3`。Windows: 通常以下）。所要時間を記録する。
- Linux の回収で syft の打ち切り時間（`SYFT_TIMEOUT_SEC`、既定 3 時間）。
- syft だけで回収した SBOM での照合（README の手順）。
- `register_daily_task.ps1 -NoPassword`（パスワードを保存せずにログオフ中も実行する）。
- 環境マスタにあって回収されていない環境を「判定不能（回収漏れ）」として出す。
- 会社公表リストの読み落とし（他のシート、結合セル、読めない CVE 番号）の警告。
- CI（GitHub Actions）。Windows と Linux での単体テスト、Windows Server と Amazon Linux / Ubuntu での回収から照合までの試験、タスクの登録の試験。
- [docs/DESIGN.md](docs/DESIGN.md)（仕組み）、[docs/OPERATIONS.md](docs/OPERATIONS.md)（運用の手引き）。
- ライセンス: MIT No Attribution（MIT-0）。

### 修正
- [docs/DEFECTS.md](docs/DEFECTS.md) の #32〜#44。主なもの:
  - Windows の `-ScanRoots 'a','b'` で走査対象が空になる（#37）。
  - Amazon Linux 2023 の実行ファイルのパッケージ情報、系統名つきのカーネルのヘッダ、rpm のサブパッケージ、Ubuntu Pro の Livepatch の告知による誤検出（#38〜#41）。
  - Ubuntu のカーネルの照合と Excel の書き出しが遅い（#42、#43）。
  - OS を判別できない環境を、KB と Windows OS の CVE で「対象外」にする（#36）。
  - 英語版 Windows などで、日本語の表示のところで止まる（#44）。

## 0.1.0（2026-11-20）

最初の版。
