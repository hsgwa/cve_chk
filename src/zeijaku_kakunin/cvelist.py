"""調べたい CVE の一覧（会社公表リストなど）を読む。

書式は問わない。Excel（すべてのシートのすべてのセル）、CSV、テキストから CVE 番号（CVE-年-番号）を拾う。
列の名前や並びを設定する必要は無い。
"""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path

_CVE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CVE_TYPO = re.compile(r"CVE[\s_‐-]*\d", re.IGNORECASE)   # CVE 番号の書き損じ（CVE2024-1、CVE-2024-12 など）


class CveListError(ValueError):
    pass


def _texts(path: Path):
    """(場所, セルの文字列) を順に返す。"""
    suffix = path.suffix.lower()
    if suffix in (".xlsx", ".xlsm"):
        from openpyxl import load_workbook

        workbook = load_workbook(path, read_only=True, data_only=True)
        try:
            for sheet in workbook.worksheets:
                for number, row in enumerate(sheet.iter_rows(values_only=True), start=1):
                    for value in row:
                        if value is not None:
                            yield f"{sheet.title} の {number} 行目", str(value)
        finally:
            workbook.close()
        return
    if suffix == ".xls":
        raise CveListError(f"古い Excel 形式（.xls）は読めません。.xlsx で保存し直してください: {path}")
    data = path.read_bytes()
    for encoding in ("utf-8-sig", "cp932", "utf-16"):
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    else:
        raise CveListError(f"文字コードが分かりません（UTF-8 か Shift_JIS で保存してください）: {path}")
    for number, line in enumerate(text.splitlines(), start=1):
        yield f"{number} 行目", line


def load_cve_list(path: str | Path) -> tuple[list[str], list[str]]:
    """(CVE 番号の一覧（出てきた順、重複なし）, 注意)。"""
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"CVE の一覧がありません: {path}")
    cves: dict[str, None] = {}
    warnings: list[str] = []
    for where, raw in _texts(path):
        text = unicodedata.normalize("NFKC", raw)
        for match in _CVE.findall(text):
            cves.setdefault(match.upper(), None)
        leftover = _CVE.sub("", text)
        if _CVE_TYPO.search(leftover):
            warnings.append(f"{where}: CVE 番号として読めない記載があります（{raw.strip()[:80]}）。"
                            "CVE-年-番号（番号は 4 桁以上）の形か確認してください")
    if not cves:
        raise CveListError(f"CVE 番号（CVE-年-番号）が 1 つもありません: {path}")
    return list(cves), warnings
