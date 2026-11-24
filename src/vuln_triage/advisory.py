"""会社公表の脆弱性リスト（Excel / CSV）の読み込み。

会社独自の見出しは config.yaml の advisory_input.columns で対応付ける。
"""
from __future__ import annotations

import csv
import re
import unicodedata
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Any

from .inventory import read_text
from .models import Advisory

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CVE_LIKE = re.compile(r"CVE|\d{4}\s*-\s*\d+", re.IGNORECASE)   # CVE 番号の書き損じ
_DATE = re.compile(r"(\d{4})[-/.年](\d{1,2})[-/.月](\d{1,2})")


class AdvisoryFormatError(ValueError):
    pass


def _normalize_header(text: Any) -> str:
    value = unicodedata.normalize("NFKC", str(text if text is not None else ""))
    return re.sub(r"\s+", "", value).lower()


def _cell_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, (datetime, date)):
        return value.strftime("%Y-%m-%d")
    return str(value).strip()


def _nfkc(value: Any) -> str:
    return unicodedata.normalize("NFKC", _cell_text(value)).strip()


_EXCEL_EPOCH = date(1899, 12, 30)


def _parse_date(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        # 「日付」でなく「数値」書式のセルは Excel の通し番号（1900 年基準）になる。1990〜2100 年の範囲だけ日付とみなす
        if 32874 <= value <= 73051:
            return _EXCEL_EPOCH + timedelta(days=int(value))
        return None
    match = _DATE.search(_nfkc(value))
    if not match:
        return None
    try:
        return date(int(match.group(1)), int(match.group(2)), int(match.group(3)))
    except ValueError:
        return None


def _parse_days(value: Any) -> int | None:
    match = re.search(r"\d+", _nfkc(value))
    return int(match.group(0)) if match else None


def _has_data(sheet) -> bool:
    return any(value not in (None, "") for row in sheet.iter_rows(values_only=True) for value in row)


def _read_xlsx(path: Path, settings: dict[str, Any], warnings: list[str]) -> list[list[Any]]:
    from openpyxl import load_workbook

    fill_merged = bool(settings.get("fill_merged", True))
    # 結合セルを調べるため read_only では開かない（read_only では結合の情報が取れない）
    workbook = load_workbook(path, data_only=True)
    sheet_name = settings.get("sheet") or ""
    if sheet_name:
        if sheet_name not in workbook.sheetnames:
            raise AdvisoryFormatError(
                f"シート「{sheet_name}」がありません。存在するシート: {', '.join(workbook.sheetnames)}")
        sheet = workbook[sheet_name]
    else:
        sheet = workbook.worksheets[0]
    # 読まないシートにデータがあれば知らせる（通達が別のシートにあると黙って漏れるため）
    others = [ws.title for ws in workbook.worksheets if ws.title != sheet.title and _has_data(ws)]
    if others:
        warnings.append(
            f"会社公表リストのシート「{sheet.title}」だけを読みました。データのある他のシート（"
            + "、".join(f"「{name}」" for name in others)
            + "）は読んでいません。通達があるなら、シートごとに config.yaml の advisory_input.sheet を指定して実行してください")
    rows = [list(row) for row in sheet.iter_rows(values_only=True)]
    header_row = int(settings.get("header_row") or 1)
    merged_ranges = [m for m in sheet.merged_cells.ranges if m.max_row > header_row and m.max_row > m.min_row]
    if fill_merged:
        for merged in merged_ranges:
            value = rows[merged.min_row - 1][merged.min_col - 1]
            for r in range(merged.min_row - 1, merged.max_row):
                for c in range(merged.min_col - 1, merged.max_col):
                    rows[r][c] = value
    elif merged_ranges:
        warnings.append(
            f"会社公表リストに縦に結合したセルが {len(merged_ranges)} 個あります（例: {merged_ranges[0].coord}）。"
            "fill_merged が false のため、結合の 2 行目以降は空として読んでいます")
    workbook.close()
    return rows


def _read_csv(path: Path) -> list[list[Any]]:
    return [row for row in csv.reader(read_text(path).splitlines())]


def load_advisories(path: str | Path, config: dict[str, Any], warnings: list[str] | None = None) -> list[Advisory]:
    """会社公表リストを読む。読み落としの恐れがあるもの（他のシート、結合セル、読めない CVE 番号）は
    warnings に追加する。"""
    path = Path(path)
    settings = config.get("advisory_input") or {}
    warnings = warnings if warnings is not None else []
    if path.suffix.lower() in (".xlsx", ".xlsm"):
        rows = _read_xlsx(path, settings, warnings)
    else:
        rows = _read_csv(path)

    header_index = int(settings.get("header_row") or 1) - 1
    if header_index >= len(rows):
        raise AdvisoryFormatError(f"見出し行（{header_index + 1} 行目）がありません: {path}")
    headers = [_normalize_header(cell) for cell in rows[header_index]]

    columns: dict[str, int] = {}
    for field, candidates in (settings.get("columns") or {}).items():
        for candidate in [candidates] if isinstance(candidates, str) else candidates or []:
            normalized = _normalize_header(candidate)
            if normalized in headers:
                columns[field] = headers.index(normalized)
                break
    if "cve_id" not in columns and "product_name" not in columns:
        found = "、".join(str(c) for c in rows[header_index] if c not in (None, ""))
        raise AdvisoryFormatError(
            "会社公表リストに CVE 番号の列も製品名の列も見つかりません。\n"
            f"  見つかった見出し（{header_index + 1} 行目）: {found}\n"
            "  config.yaml の advisory_input.columns に見出しの対応を追加してください。")

    def get(row: list[Any], field: str) -> Any:
        index = columns.get(field)
        return row[index] if index is not None and index < len(row) else None

    advisories: list[Advisory] = []
    for number, row in enumerate(rows[header_index + 1:], start=header_index + 2):
        cve_text = _nfkc(get(row, "cve_id"))
        product = _cell_text(get(row, "product_name"))
        if not cve_text and not product:
            continue
        cves = list(dict.fromkeys(m.upper() for m in _CVE.findall(cve_text))) or [""]
        leftover = _CVE.sub("", cve_text)
        if _CVE_LIKE.search(leftover):
            warnings.append(f"{number} 行目: CVE 番号として読めない記載があります（{cve_text}）。"
                            "CVE-年-番号（番号は 4 桁以上）の形か確認してください")
        common = dict(
            advisory_id=_cell_text(get(row, "advisory_id")) or f"行{number}",
            product_name=product,
            affected_version=_nfkc(get(row, "affected_version")),
            published_date=_parse_date(get(row, "published_date")),
            company_rank=_nfkc(get(row, "company_rank")),
            deadline_days=_parse_days(get(row, "deadline_days")),
            note=_cell_text(get(row, "note")),
            row=number,
        )
        for cve in cves:
            advisories.append(Advisory(cve_id=cve, **common))
    return advisories
