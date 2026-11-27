"""前回の結果（出力フォルダの report_vulns.csv）との比較。「新たに見つかった」「解消」「継続」を出す。

比べる単位は（脆弱性、ソフトウェア）。版が上がっても同じ脆弱性が残っていれば「継続」とする。
"""
from __future__ import annotations

import csv
from pathlib import Path

from ..judge import Result

DIFF_HEADER = ["変化", "CVE など", "ソフトウェア", "前回のバージョン", "今回のバージョン", "修正バージョン", "見つかった場所"]
NEW, RESOLVED, CONTINUED = "新たに見つかった", "解消", "継続"
_ORDER = {NEW: 0, RESOLVED: 1, CONTINUED: 2}


class PreviousReportError(ValueError):
    pass


def load_previous(path: str | Path) -> dict[tuple[str, str], dict[str, str]]:
    """前回の出力フォルダから、見つかった脆弱性を読む。"""
    file = Path(path) / "report_vulns.csv"
    if not file.is_file():
        raise PreviousReportError(f"前回の結果がありません: {file}（--previous には前回の出力フォルダを指定します）")
    previous: dict[tuple[str, str], dict[str, str]] = {}
    with file.open(encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            previous.setdefault((row.get("CVE など", "").upper(), row.get("ソフトウェア", "")), row)
    return previous


def diff_table(result: Result, previous: dict[tuple[str, str], dict[str, str]]) -> tuple[list[list[str]], dict[str, int]]:
    current = {}
    for row in result.vulns:
        current.setdefault((row.cve_id.upper(), row.package), row)
    table = []
    for key, row in current.items():
        before = previous.get(key)
        table.append([CONTINUED if before else NEW, row.cve_id, row.package,
                      before.get("現在のバージョン", "") if before else "", row.version, row.fixed, row.path])
    for key, before in previous.items():
        if key not in current:
            table.append([RESOLVED, before.get("CVE など", ""), key[1], before.get("現在のバージョン", ""), "",
                          before.get("修正バージョン", ""), before.get("見つかった場所", "")])
    table.sort(key=lambda r: (_ORDER[r[0]], r[2].lower(), r[1]))
    counts = {name: sum(1 for r in table if r[0] == name) for name in (NEW, RESOLVED, CONTINUED)}
    return table, counts
