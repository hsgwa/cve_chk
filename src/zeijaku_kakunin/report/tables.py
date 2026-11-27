"""レポートの表（見出しと行）。CSV と Excel の両方で使う。1 台のサーバーぶん。"""
from __future__ import annotations

from collections import Counter
from datetime import date, datetime
from typing import Any

from ..judge import Result, Row
from ..models import AFFECTED, AFFECTED_UNCOMPARABLE, NOT_AFFECTED, UNKNOWN, EnvInventory

CVE_HEADER = ["CVE", "影響有無", "ソフトウェア", "現在のバージョン", "修正バージョン", "見つかった場所", "備考"]
UPDATE_HEADER = ["ソフトウェア", "現在のバージョン", "この版以上に更新", "脆弱性（件）", "うち CVE の一覧にあるもの（件）",
                 "修正版の無いもの（件）", "見つかった場所", "CVE（先頭 10 件）"]
VULN_HEADER = ["CVE など", "影響有無", "ソフトウェア", "現在のバージョン", "修正バージョン", "CVE の一覧にある",
               "見つかった場所", "備考"]
STATUS_ORDER = [AFFECTED, AFFECTED_UNCOMPARABLE, UNKNOWN, NOT_AFFECTED]

LIMITATION_NOTES = [
    "「影響なし」は、回収できたソフトと脆弱性データ（OSV.dev、Amazon Linux の公式情報、Microsoft の公開データ）で"
    "確かめた範囲での結果です。",
    "脆弱性データに無いソフト（商用ソフトなど）、実行ファイルそのもの（カーネルのイメージ、node・python のバイナリ）、"
    "コンテナの中身は判定できません。",
    "Windows OS そのものの脆弱性は、CVE の一覧を渡したときだけ判定します（一覧の CVE を Microsoft の公開データで調べます）。",
    "「影響あり」は版の一致です。実際に攻撃できるか（設定や使い方）は判定していません。",
]


def _cves(rows: list[Row]) -> str:
    ids = list(dict.fromkeys(r.cve_id for r in rows))
    return "、".join(ids[:10]) + (f" ほか {len(ids) - 10} 件" if len(ids) > 10 else "")


def _max_version(ecosystem: str, versions: list[str]) -> str:
    """修正版のうち最も新しいもの（すべての脆弱性が直る版）。比べられなければ文字列の順で選ぶ。"""
    from ..vulndb.versions import sort_key

    versions = sorted({v for v in versions if v})
    if not versions:
        return ""
    try:
        return max(versions, key=sort_key(ecosystem or "generic"))
    except (ValueError, TypeError):
        return versions[-1]


def cve_table(result: Result) -> list[list[str]]:
    return [[r.cve_id, r.status, r.package, r.version, r.fixed, r.path, r.note] for r in result.cve_rows]


def update_table(result: Result) -> list[list[str]]:
    """見つかった脆弱性を、ソフトウェア × 版 × 場所ごとにまとめる（何をどの版に上げれば直るか）。"""
    groups: dict[tuple[str, str, str], list[Row]] = {}
    for row in [*result.vulns, *(r for r in result.cve_rows if r.path == "OS ビルド番号")]:
        if row.affected and row.package:
            groups.setdefault((row.package, row.version, row.path), []).append(row)
    table = []
    for (package, version, path), rows in groups.items():
        ids = {r.cve_id for r in rows}
        fixed = _max_version(next((r.ecosystem for r in rows if r.ecosystem), ""), [r.fixed for r in rows])
        table.append([package, version, fixed if path != "OS ビルド番号" else "Windows Update で最新にする",
                      str(len(ids)), str(len({r.cve_id for r in rows if r.in_list})),
                      str(len({r.cve_id for r in rows if not r.fixed and r.path != "OS ビルド番号"})), path,
                      _cves(rows)])
    table.sort(key=lambda r: (-int(r[4]), -int(r[3]), r[0].lower(), r[1]))
    return table


def vuln_table(result: Result) -> list[list[str]]:
    return [[r.cve_id, r.status, r.package, r.version, r.fixed, "○" if r.in_list else "", r.path, r.note]
            for r in result.vulns]


def parse_collected_at(text: str) -> datetime | None:
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")) if text else None
    except ValueError:
        return None


def collection_table(env: EnvInventory, today: date, config: dict[str, Any]) -> list[list[str]]:
    """回収物の状況（項目, 内容）。"""
    notes = list(env.warnings)
    collected = parse_collected_at(env.collected_at)
    stale_days = int(config.get("stale_days") or 90)
    if collected and (today - collected.date()).days > stale_days:
        notes.append(f"回収から {(today - collected.date()).days} 日経過しています（回収し直してください）")
    notes.extend(f"{name}: {s.status}（{s.reason}）" for name, s in env.sections.items()
                 if s.status in ("failed", "skipped") and name != "syft")
    if not env.cve_coverage:
        coverage = "不可"
    elif env.missing_db:
        coverage = "一部のみ（" + "、".join(f"{k} {v} 件" for k, v in sorted(env.missing_db.items())) + " は脆弱性データが無い）"
    else:
        coverage = "可"
    if env.hotfixes is not None:
        hotfix = f"{len(env.hotfixes)} 件"
    else:
        hotfix = "対象外" if env.os_family != "windows" else "回収なし"
    return [
        ["サーバー", env.name],
        ["OS", " ".join(p for p in (env.os_name or env.os_family, env.os_build) if p)],
        ["回収日時", env.collected_at],
        ["回収ファイル", "\n".join(env.files) or "（読めるファイルなし）"],
        ["ソフトウェア（件）", str(len(env.components))],
        ["脆弱性データとの照合", coverage],
        ["適用済みの更新プログラム（KB）", hotfix],
        ["注意事項", "\n".join(notes)],
        ["読めなかったフォルダ", "\n".join(env.unreadable[:50])],
        ["走査範囲の外で動いているプログラム", "\n".join(sorted(set(env.out_of_scope_running))[:50])],
    ]


def db_summary(db_info: dict[str, dict]) -> dict[str, str]:
    """データごとの更新日時。Amazon Linux 2 の extras（70 以上のトピック）は 1 つにまとめ、最も古い日時を出す。"""
    def stamp(info: dict) -> str:
        return str(info.get("updated_at", "")).replace("T", " ").replace("Z", " UTC")[:20]

    result: dict[str, str] = {}
    extras = sorted(stamp(info) for name, info in db_info.items() if name.startswith("Amazon Linux:2:extras:"))
    for name, info in sorted(db_info.items()):
        if not name.startswith("Amazon Linux:2:extras:"):
            result[name] = stamp(info)
    if extras:
        result[f"Amazon Linux:2 extras（{len(extras)} トピック）"] = extras[0]
    return result


def summary_lines(env: EnvInventory, result: Result, cve_list: list[str] | None, updates: list[list[str]],
                  db_info: dict[str, dict] | None) -> list[str]:
    lines = [f"サーバー: {env.name}（{env.os_name or env.os_family}）"]
    if cve_list is not None:
        by_cve: dict[str, str] = {}
        for row in result.cve_rows:
            current = by_cve.get(row.cve_id)
            if current is None or STATUS_ORDER.index(row.status) < STATUS_ORDER.index(current):
                by_cve[row.cve_id] = row.status
        counts = Counter(AFFECTED if s == AFFECTED_UNCOMPARABLE else s for s in by_cve.values())
        lines.append(f"CVE の一覧 {len(cve_list)} 件: 影響あり {counts.get(AFFECTED, 0)} 件、"
                     f"影響なし {counts.get(NOT_AFFECTED, 0)} 件、判定不能 {counts.get(UNKNOWN, 0)} 件"
                     "（「CVE の判定」シート / report_cve.csv）")
    packages = {(r.package, r.version) for r in result.vulns}
    lines.append(f"見つかった脆弱性: {len({r.cve_id for r in result.vulns})} 件（ソフトウェア {len(packages)} 件）"
                 "（「脆弱性の一覧」シート / report_vulns.csv）")
    lines.append(f"更新が必要なソフトウェア: {len(updates)} 件（「要更新ソフト」シート / report_updates.csv）")
    if db_info:
        lines.append("脆弱性データの更新日時: " + "、".join(f"{k} {v.strip()}" for k, v in db_summary(db_info).items()))
    lines.extend(f"注意: {w}" for w in env.warnings)
    lines.extend(f"注意: {m}" for m in result.messages)
    return lines
