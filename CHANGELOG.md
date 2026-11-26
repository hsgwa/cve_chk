# 変更履歴

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

### 修正
- [docs/DEFECTS.md](docs/DEFECTS.md) の #32〜#44。主なもの:
  - Windows の `-ScanRoots 'a','b'` で走査対象が空になる（#37）。
  - Amazon Linux 2023 の実行ファイルのパッケージ情報、系統名つきのカーネルのヘッダ、rpm のサブパッケージ、Ubuntu Pro の Livepatch の告知による誤検出（#38〜#41）。
  - Ubuntu のカーネルの照合と Excel の書き出しが遅い（#42、#43）。
  - OS を判別できない環境を、KB と Windows OS の CVE で「対象外」にする（#36）。
  - 英語版 Windows などで、日本語の表示のところで止まる（#44）。

## 0.1.0（2026-11-20）

最初の版。
