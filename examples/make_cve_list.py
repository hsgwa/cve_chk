"""サンプルの CVE の一覧（cve_list.xlsx / cve_list.csv）を作り直すスクリプト。

会社の通達の Excel を想定した形にしている。ツールは CVE 番号だけを読むので、ほかの列は何でもよい。
"""
import csv
from pathlib import Path

from openpyxl import Workbook

HERE = Path(__file__).parent
HEADER = ["通達番号", "CVE番号", "備考"]
ROWS = [
    ["ADV-001", "CVE-2021-44228", "Log4Shell（log4j-core）"],
    ["ADV-002", "CVE-2022-42889", "Text4Shell（commons-text）"],
    ["ADV-003", "CVE-2023-32681", "requests"],
    ["ADV-004", "CVE-2024-21338", "Windows OS（ビルド番号で判定）"],
    ["ADV-005", "CVE-2099-0001", "どのサーバーにも無い例"],
]


def main() -> None:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "脆弱性一覧"
    sheet.append(HEADER)
    for row in ROWS:
        sheet.append(row)
    workbook.save(HERE / "cve_list.xlsx")
    with open(HERE / "cve_list.csv", "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(HEADER)
        writer.writerows(ROWS)


if __name__ == "__main__":
    main()
