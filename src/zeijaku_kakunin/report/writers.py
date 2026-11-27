"""CSV と Excel の書き出し（1 台のサーバーぶん）。"""
from __future__ import annotations

import csv
from datetime import date
from pathlib import Path
from typing import Any

from ..judge import Result
from ..models import AFFECTED, AFFECTED_UNCOMPARABLE, NOT_AFFECTED, UNKNOWN, EnvInventory
from . import tables

_FILL = {AFFECTED: "F8CBAD", AFFECTED_UNCOMPARABLE: "F8CBAD", UNKNOWN: "FFE699", NOT_AFFECTED: "C6E0B4"}


def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def _add_sheet(workbook, title: str, header: list[str], rows: list[list[str]], status_column: int | None = None):
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.utils import get_column_letter

    sheet = workbook.create_sheet(title)
    sheet.append(header)
    for row in rows:
        sheet.append(row)
    for cell in sheet[1]:
        cell.font = Font(bold=True, color="FFFFFF")
        cell.fill = PatternFill("solid", fgColor="44546A")
        cell.alignment = Alignment(vertical="center", wrap_text=True)
    sheet.freeze_panes = "A2"
    if rows:
        sheet.auto_filter.ref = sheet.dimensions
    for index, name in enumerate(header, start=1):
        longest = max([len(str(name))] + [len(str(r[index - 1]).split("\n")[0]) for r in rows[:500]])
        sheet.column_dimensions[get_column_letter(index)].width = min(max(10, longest * 1.7 + 2), 60)
    top = Alignment(vertical="top", wrap_text=True)     # 1 つを使い回す（行ごとに作ると数万行で遅い）
    fills = {color: PatternFill("solid", fgColor=color) for color in set(_FILL.values())}
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = top
        if status_column is not None:
            color = _FILL.get(str(row[status_column].value or ""))
            if color:
                row[status_column].fill = fills[color]
    return sheet


def write_reports(
    out_dir: str | Path,
    env: EnvInventory,
    result: Result,
    cve_list: list[str] | None,
    config: dict[str, Any],
    today: date,
    xlsx: bool = True,
    db_info: dict[str, dict] | None = None,
    previous: dict | None = None,
) -> tuple[list[Path], list[str]]:
    out = Path(out_dir)
    updates = tables.update_table(result)
    vulns = tables.vuln_table(result)
    cves = tables.cve_table(result) if cve_list is not None else None
    lines = tables.summary_lines(env, result, cve_list, updates, db_info)

    written = []
    if cves is not None:
        written.append(out / "report_cve.csv")
        write_csv(written[-1], tables.CVE_HEADER, cves)
    written.append(out / "report_updates.csv")
    write_csv(written[-1], tables.UPDATE_HEADER, updates)
    written.append(out / "report_vulns.csv")
    write_csv(written[-1], tables.VULN_HEADER, vulns)
    changes = None
    if previous is not None:
        from .diff import DIFF_HEADER, diff_table

        changes, counts = diff_table(result, previous)
        written.append(out / "report_changes.csv")
        write_csv(written[-1], DIFF_HEADER, changes)
        lines.append("前回との差分: " + "、".join(f"{k} {v} 件" for k, v in counts.items())
                     + "（「前回との差分」シート / report_changes.csv）")

    if xlsx:
        from openpyxl import Workbook
        from openpyxl.styles import Font

        limit = int(config.get("xlsx_max_rows") or 100000)
        for name, rows, csv_name in (("脆弱性の一覧", vulns, "report_vulns.csv"),
                                     ("前回との差分", changes or [], "report_changes.csv")):
            if len(rows) > limit:
                lines.append(f"注意: Excel の「{name}」は先頭 {limit:,} 行だけを書きました（全 {len(rows):,} 行は {csv_name}）")
        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "サマリ"
        sheet.append([f"脆弱性の確認結果: {env.name}"])
        sheet["A1"].font = Font(bold=True, size=14)
        sheet.append([f"実行日: {today.isoformat()}"])
        sheet.append([])
        for line in lines:
            sheet.append([line])
        sheet.append([])
        sheet.append(["この結果の限界"])
        sheet.cell(row=sheet.max_row, column=1).font = Font(bold=True)
        for note in tables.LIMITATION_NOTES:
            sheet.append([f"・{note}"])
        sheet.column_dimensions["A"].width = 120

        if cves is not None:
            _add_sheet(workbook, "CVE の判定", tables.CVE_HEADER, cves, status_column=1)
        _add_sheet(workbook, "要更新ソフト", tables.UPDATE_HEADER, updates)
        if changes is not None:
            from .diff import DIFF_HEADER

            _add_sheet(workbook, "前回との差分", DIFF_HEADER, changes[:limit])
        _add_sheet(workbook, "脆弱性の一覧", tables.VULN_HEADER, vulns[:limit], status_column=1)
        _add_sheet(workbook, "収集状況", ["項目", "内容"], tables.collection_table(env, today, config))
        written.append(out / "report.xlsx")
        workbook.save(written[-1])
    return written, lines
