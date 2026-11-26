"""CSV / Excel / 標準出力サマリの書き出し。"""
from __future__ import annotations

import csv
from datetime import date
from pathlib import Path
from typing import Any

from ..matching.rank import rank_sort_key
from ..models import AFFECTED, NOT_APPLICABLE, UNKNOWN, UNUSED, Advisory, EnvInventory
from ..verdict import JudgeResult
from . import tables

_FILL = {
    AFFECTED: "F8CBAD", UNKNOWN: "FFE699", "影響なし": "C6E0B4", NOT_APPLICABLE: "D9D9D9", UNUSED: "DDEBF7",
}


def write_csv(path: Path, header: list[str], rows: list[list[str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8-sig", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(header)
        writer.writerows(rows)


def _add_sheet(workbook, title: str, header: list[str], rows: list[list[str]], status_columns: list[int] = ()):
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
    fills = {color: PatternFill("solid", fgColor=color) for color in _FILL.values()}
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.alignment = top
        for column in status_columns:
            cell = row[column]
            color = _FILL.get(tables.simple_status(str(cell.value or "")))
            if not color and str(cell.value or "").startswith(AFFECTED):
                color = _FILL[AFFECTED]
            if color:
                cell.fill = fills[color]
    return sheet


def overview_lines(info: dict[str, Any], config: dict[str, Any], messages: list[str]) -> list[str]:
    lines = [f"通達 {info['advisories']} 件 × 環境 {info['environments']} 件"]
    lines.append("総合判定: " + "、".join(f"{k} {v} 件" for k, v in info["overall"].items()))
    if info["rank"]:
        ranks = sorted(info["rank"].items(), key=lambda kv: rank_sort_key(kv[0], config))
        lines.append("影響ありのランク別（行数）: " + "、".join(f"{k} {v}" for k, v in ranks))
    if info["env_affected"]:
        lines.append("影響ありの環境別（行数）: " + "、".join(f"{k} {v}" for k, v in sorted(info["env_affected"].items())))
    if info["overdue"]:
        lines.append(f"期限超過: {info['overdue']} 行")
    lines.append(f"通達に無い新規検出（参考）: {info['new_findings']} 件")
    if info.get("db"):
        lines.append("脆弱性データの更新日時: " + "、".join(f"{k} {v.strip()}" for k, v in info["db"].items()))
    if info["unregistered"]:
        lines.append("注意: env_master 未登録のため internal 扱いにした環境: " + "、".join(info["unregistered"]))
    if info.get("not_collected"):
        lines.append("注意: env_master に登録済みだが回収データが無い環境（判定不能として出力）: "
                     + "、".join(info["not_collected"]))
    lines.extend(f"注意: {m}" for m in messages)
    return lines


def write_reports(
    out_dir: str | Path,
    advisories: list[Advisory],
    envs: list[EnvInventory],
    result: JudgeResult,
    config: dict[str, Any],
    today: date,
    xlsx: bool = True,
    db_info: dict[str, dict] | None = None,
) -> tuple[list[Path], list[str]]:
    out = Path(out_dir)
    summary = tables.summary_table(advisories, result.rows, config)
    detail = tables.detail_table(result.rows, config)
    new = tables.detail_table(result.new_findings, config)
    coverage = tables.coverage_table(envs, today, config)
    matrix_header, matrix = tables.matrix_table(advisories, result.rows, envs)
    info = tables.overview(advisories, result.rows, result.new_findings, envs, config, db_info)
    lines = overview_lines(info, config, result.messages)

    written = [out / "report_summary.csv", out / "report_detail.csv"]
    write_csv(written[0], tables.SUMMARY_HEADER, summary)
    write_csv(written[1], tables.DETAIL_HEADER, detail)
    if new:
        written.append(out / "report_new_findings.csv")
        write_csv(written[-1], tables.DETAIL_HEADER, new)

    if xlsx:
        from openpyxl import Workbook
        from openpyxl.styles import Font

        workbook = Workbook()
        sheet = workbook.active
        sheet.title = "サマリ"
        sheet.append(["脆弱性トリアージ結果"])
        sheet["A1"].font = Font(bold=True, size=14)
        sheet.append([f"実行日（基準日）: {today.isoformat()}"])
        sheet.append([])
        for line in lines:
            sheet.append([line])
        sheet.append([])
        sheet.append(["この結果の限界"])
        sheet.cell(row=sheet.max_row, column=1).font = Font(bold=True)
        for note in tables.LIMITATION_NOTES:
            sheet.append([f"・{note}"])
        sheet.column_dimensions["A"].width = 120

        _add_sheet(workbook, "通達別一覧", tables.SUMMARY_HEADER, summary, status_columns=[4])
        _add_sheet(workbook, "通達×環境", matrix_header, matrix,
                   status_columns=list(range(3, len(matrix_header))))
        _add_sheet(workbook, "明細", tables.DETAIL_HEADER, detail, status_columns=[6])
        _add_sheet(workbook, "新規検出（参考）", tables.DETAIL_HEADER, new, status_columns=[6])
        _add_sheet(workbook, "収集状況", tables.COVERAGE_HEADER, coverage)
        written.append(out / "report.xlsx")
        workbook.save(written[-1])
    return written, lines
