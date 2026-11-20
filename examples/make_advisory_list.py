"""サンプルの会社公表リスト（advisory_list.xlsx / advisory_list.csv）を作り直すスクリプト。"""
import csv
from datetime import date
from pathlib import Path

from openpyxl import Workbook

HERE = Path(__file__).parent
HEADER = ["通達番号", "CVE番号", "製品名", "影響バージョン", "公表日", "社内ランク", "対応期限(日)", "備考"]
ROWS = [
    ["ADV-001", "CVE-2021-44228", "log4j-core", ">=2.0,<2.15.0", date(2026, 11, 2), "Rank-S", 3, "Log4Shell"],
    ["ADV-002", "CVE-2022-42889", "commons-text", "", date(2026, 11, 2), "", "", "Text4Shell（版の記載なし）"],
    ["ADV-003", "CVE-2023-32681", "", "", date(2026, 11, 5), "", "", "製品名の記載なし（CVE のみ）"],
    ["ADV-004", "", "HULFT", "<8.5.0", date(2026, 11, 5), "Rank-A", 14, "商用ソフト（CVE なし）"],
    ["ADV-005", "", "DataMagic", "<3.0.0", date(2026, 11, 5), "Rank-B", 30, "商用ソフト（CVE なし）"],
    ["ADV-006", "", "Apache Tomcat*", "9.0.*", date(2026, 11, 9), "", "", "9.0 系は更新すること"],
    ["ADV-007", "", "The OpenSSL Toolkit", "<=3.0.12", date(2026, 11, 9), "Rank-B", 30, "dll / exe のバージョン情報で判定"],
    ["ADV-008", "", "KB5034768", "missing", date(2026, 11, 9), "Rank-A", 14, "Windows 更新プログラムの適用"],
    ["ADV-009", "CVE-2024-21338", "", "", date(2026, 11, 9), "", "", "Windows OS（ビルド番号で自動判定）"],
    ["ADV-010", "", "amazon-emr", "<6.16.0", date(2026, 11, 12), "Rank-C", 90, "EMR リリースラベルで判定"],
    ["ADV-011", "CVE-2099-0001", "nginx", "<1.25.0", date(2026, 11, 12), "", "", "どの環境でも使っていない例"],
]


def main() -> None:
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "脆弱性一覧"
    sheet.append(HEADER)
    for row in ROWS:
        sheet.append(row)
    for column, width in zip("ABCDEFGH", (12, 18, 22, 18, 12, 10, 12, 40)):
        sheet.column_dimensions[column].width = width
    workbook.save(HERE / "advisory_list.xlsx")

    english = ["advisory_id", "cve_id", "product_name", "affected_version", "published_date",
               "company_rank", "deadline_days", "note"]
    with open(HERE / "advisory_list.csv", "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(english)
        for row in ROWS:
            writer.writerow([cell.isoformat() if isinstance(cell, date) else cell for cell in row])


if __name__ == "__main__":
    main()
