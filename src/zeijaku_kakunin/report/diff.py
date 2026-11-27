"""前回の結果（出力フォルダの CSV）との比較。月次などで再実行したときの「新たに影響あり」「解消」を出す。

比べる単位は（環境、脆弱性、パッケージ）。脆弱性は CVE 番号、CVE の無い通達は通達 ID。
版が上がっても同じ脆弱性が残っていれば「継続」とする。今回その環境を回収していなければ「解消」ではなく
「今回の回収なし」とする（回収漏れを解消と取り違えないため）。
"""
from __future__ import annotations

import csv
from pathlib import Path

from typing import Any

from ..matching.rank import rank_sort_key
from ..models import AFFECTED, EnvInventory, Verdict

DIFF_HEADER = [
    "変化", "社内ランク", "対応期限", "該当環境", "製品・パッケージ名", "前回のバージョン", "今回のバージョン",
    "CVE_ID / 通達ID", "社内通達ID", "CVSS_v3", "検出パス/ソース",
]
NEW, RESOLVED, CONTINUED, NOT_COLLECTED = "新たに影響あり", "解消", "継続", "今回の回収なし"
_ORDER = {NEW: 0, NOT_COLLECTED: 1, RESOLVED: 2, CONTINUED: 3}


class PreviousReportError(ValueError):
    pass


def _key(env: str, vuln: str, package: str) -> tuple[str, str, str]:
    return env, vuln.upper(), package


def load_previous(path: str | Path) -> dict[tuple[str, str, str], dict[str, str]]:
    """前回の出力フォルダ（report_detail.csv と report_new_findings.csv）から、影響ありの行を読む。"""
    folder = Path(path)
    detail = folder / "report_detail.csv"
    if not detail.is_file():
        raise PreviousReportError(f"前回の結果がありません: {detail}（--previous には前回の出力フォルダを指定します）")
    previous: dict[tuple[str, str, str], dict[str, str]] = {}
    for file in (detail, folder / "report_new_findings.csv"):
        if not file.is_file():
            continue
        with file.open(encoding="utf-8-sig", newline="") as handle:
            for row in csv.DictReader(handle):
                if not str(row.get("影響有無", "")).startswith(AFFECTED):
                    continue
                vuln = row.get("CVE_ID") or row.get("社内通達ID") or ""
                previous.setdefault(_key(row.get("該当環境", ""), vuln, row.get("製品・パッケージ名", "")), row)
    return previous


def diff_table(rows: list[Verdict], new_findings: list[Verdict], envs: list[EnvInventory],
               previous: dict[tuple[str, str, str], dict[str, str]],
               config: dict[str, Any]) -> tuple[list[list[str]], dict[str, int]]:
    """(表, {変化: 件数})。継続も表に含める（並びは 新たに影響あり → 今回の回収なし → 解消 → 継続）。"""
    from .tables import _fmt_cvss, _fmt_date

    current: dict[tuple[str, str, str], Verdict] = {}
    for row in [*rows, *new_findings]:
        if row.affected or row.status.startswith(AFFECTED):
            current.setdefault(_key(row.env, row.cve_id or row.advisory_id, row.package), row)
    collected = {env.name for env in envs if not env.not_collected and env.files}

    table = []
    for key, row in current.items():
        before = previous.get(key)
        change = CONTINUED if before else NEW
        table.append([change, row.rank, _fmt_date(row.deadline), row.env, row.package,
                      before.get("現在バージョン", "") if before else "", row.version, key[1], row.advisory_id,
                      _fmt_cvss(row.cvss), row.path])
    for key, before in previous.items():
        if key in current:
            continue
        change = RESOLVED if key[0] in collected else NOT_COLLECTED
        table.append([change, before.get("社内ランク", ""), before.get("対応期限", ""), key[0], key[2],
                      before.get("現在バージョン", ""), "", key[1], before.get("社内通達ID", ""),
                      before.get("CVSS_v3", ""), before.get("検出パス/ソース", "")])
    table.sort(key=lambda r: (_ORDER[r[0]], rank_sort_key(r[1], config) if r[1] else 99, r[2] or "9999", r[3], r[4], r[7]))
    counts = {name: sum(1 for r in table if r[0] == name) for name in (NEW, RESOLVED, CONTINUED, NOT_COLLECTED)}
    return table, counts
