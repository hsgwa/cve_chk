"""レポートの表（見出しと行）を組み立てる。CSV と Excel の両方で使う。"""
from __future__ import annotations

from collections import Counter
from datetime import date, datetime
from typing import Any

from ..matching.rank import rank_sort_key
from ..models import (
    AFFECTED,
    AFFECTED_STATUSES,
    NOT_AFFECTED_STATUSES,
    NOT_APPLICABLE,
    UNKNOWN,
    UNUSED,
    Advisory,
    EnvInventory,
    Verdict,
)

DETAIL_HEADER = [
    "判定区分", "CVE_ID", "社内通達ID", "製品・パッケージ名", "現在バージョン", "影響条件/修正バージョン",
    "影響有無", "社内ランク", "対応期限", "該当環境", "公開区分", "検出パス/ソース", "CVSS_v3", "備考",
]
SUMMARY_HEADER = [
    "社内通達ID", "CVE_ID", "製品名", "影響条件", "総合判定", "影響あり環境", "影響なし環境", "未使用環境",
    "対象外環境", "判定不能環境", "社内ランク", "対応期限", "備考",
]
COVERAGE_HEADER = [
    "環境", "公開区分", "システム名", "env_master登録", "OS", "OSビルド", "回収日時", "回収ファイル",
    "コンポーネント数", "CVE判定", "適用済みKB", "注意事項", "読めなかったフォルダ", "スキャン範囲外で動作中",
]

# 総合判定の優先順（左ほど優先）
_OVERALL = [AFFECTED, UNKNOWN, "影響なし", NOT_APPLICABLE, UNUSED]

LIMITATION_NOTES = [
    "「未使用」「影響なし」は回収できた範囲での結果です。「収集状況」シートで回収漏れが無いか確認してください。",
    "コンテナの中身、Lambda の実行環境、AWS マネージドサービス側、Windows の Go/Rust 製 exe の内部依存は対象外です。",
    "「影響あり」はバージョンの一致を意味し、実際に攻撃可能かどうかは判定していません。",
    "脆弱性データベース（OSV.dev、Amazon Linux の公式情報）に載っていない脆弱性（商用ソフト等）は、通達に製品名とバージョン条件が無いと検出できません。",
    "Ubuntu の OS パッケージで修正版が Ubuntu Pro（ESM）にしか無いものは、Pro の版を入れていなければ影響ありと判定し、備考に記載します。",
    "Amazon Linux の公式情報には CVSS が無いため、他のデータ（Debian 等）の同じ CVE から点数を引いています。見つからない場合は CVSS 不明（Rank-C）です。",
    "製品名の表記が回収データと異なると「未使用」になります。config.yaml の aliases で対応付けてください。",
]


def _fmt_date(value: date | None) -> str:
    return value.isoformat() if value else ""


def _fmt_cvss(value: float | None) -> str:
    return "" if value is None else f"{value:.1f}"


def simple_status(status: str) -> str:
    if status in AFFECTED_STATUSES:
        return AFFECTED
    if status in NOT_AFFECTED_STATUSES:
        return "影響なし"
    return status


def detail_row(row: Verdict) -> list[str]:
    return [
        row.category, row.cve_id, row.advisory_id, row.package, row.version, row.condition, row.status,
        row.rank, _fmt_date(row.deadline), row.env, row.exposure, row.path, _fmt_cvss(row.cvss), row.note,
    ]


def sort_rows(rows: list[Verdict], config: dict[str, Any]) -> list[Verdict]:
    def key(row: Verdict):
        return (
            0 if row.affected or row.status.startswith(AFFECTED) else 1,
            rank_sort_key(row.rank, config) if row.rank else 99,
            row.deadline or date.max,
            row.advisory.row if row.advisory else 0,
            row.env, row.package,
        )
    return sorted(rows, key=key)


UPDATE_HEADER = [
    "社内ランク（最も厳しい）", "対応期限（最も早い）", "該当環境", "公開区分", "製品・パッケージ名", "現在バージョン",
    "この版以上に更新", "脆弱性（件）", "うち会社公表の通達", "修正版の無いもの（件）", "最大CVSS", "検出パス/ソース",
    "CVE（CVSS の高い順、先頭 10 件）",
]


def _max_version(ecosystem: str, versions: list[str]) -> str:
    """修正版のうち最も新しいもの（すべての脆弱性が直る版）。比較できなければ文字列の順で選ぶ。"""
    from ..vulndb.versions import compare, sort_key

    versions = sorted({v for v in versions if v})
    if not versions:
        return ""
    try:
        return max(versions, key=sort_key(ecosystem or "generic"))
    except (ValueError, TypeError):
        return versions[-1]


def update_table(rows: list[Verdict], new_findings: list[Verdict], config: dict[str, Any]) -> list[list[str]]:
    """影響ありの検出を、環境 × パッケージ × 版 × 場所ごとにまとめる（「どれを更新すれば直るか」の一覧）。

    通達の判定と新規検出の両方を含む。修正版が分かるものは、そのうち最も新しい版を「この版以上に更新」に出す。
    """
    groups: dict[tuple, list[Verdict]] = {}
    for row in [*rows, *new_findings]:
        if not (row.affected or row.status.startswith(AFFECTED)) or not row.package:
            continue
        groups.setdefault((row.env, row.package, row.version, row.path), []).append(row)
    table = []
    for (env, package, version, path), items in groups.items():
        by_cve: dict[str, Verdict] = {}
        for item in items:
            key = item.cve_id or item.advisory_id or item.package
            if key not in by_cve or (item.cvss or 0) > (by_cve[key].cvss or 0):
                by_cve[key] = item
        cves = sorted(by_cve, key=lambda k: -(by_cve[k].cvss or 0))
        ranks = [i.rank for i in items if i.rank]
        rank = min(ranks, key=lambda r: rank_sort_key(r, config)) if ranks else ""
        deadlines = [i.deadline for i in items if i.deadline]
        ecosystem = next((i.ecosystem for i in items if i.ecosystem), "")
        fixed = _max_version(ecosystem, [i.fixed for i in items])
        advisories = sorted({i.advisory_id for i in items if i.advisory_id})
        cvss = max((i.cvss for i in items if i.cvss is not None), default=None)
        table.append([
            rank, _fmt_date(min(deadlines) if deadlines else None), env, items[0].exposure, package, version,
            fixed, str(len(by_cve)), "、".join(advisories), str(sum(1 for k in by_cve if not by_cve[k].fixed)),
            _fmt_cvss(cvss), path, "、".join(cves[:10]) + (f" ほか {len(cves) - 10} 件" if len(cves) > 10 else ""),
        ])
    table.sort(key=lambda r: (rank_sort_key(r[0], config) if r[0] else 99, r[1] or "9999", -int(r[7]), r[2], r[4]))
    return table


def detail_table(rows: list[Verdict], config: dict[str, Any]) -> list[list[str]]:
    return [detail_row(r) for r in sort_rows(rows, config)]


def group_by_advisory(advisories: list[Advisory], rows: list[Verdict]) -> list[tuple[Advisory, list[Verdict]]]:
    by_key: dict[int, list[Verdict]] = {}
    for row in rows:
        by_key.setdefault(id(row.advisory), []).append(row)
    return [(advisory, by_key.get(id(advisory), [])) for advisory in advisories]


def env_status(rows: list[Verdict]) -> dict[str, str]:
    """環境ごとの代表判定（1環境に複数行ある場合は最も重いもの）。"""
    result: dict[str, str] = {}
    for row in rows:
        status = simple_status(row.status)
        current = result.get(row.env)
        if current is None or _OVERALL.index(status) < _OVERALL.index(current):
            result[row.env] = status
    return result


def summary_table(advisories: list[Advisory], rows: list[Verdict], config: dict[str, Any]) -> list[list[str]]:
    table = []
    for advisory, group in group_by_advisory(advisories, rows):
        statuses = env_status(group)
        overall = next((s for s in _OVERALL if s in statuses.values()), UNUSED)
        affected = [r for r in group if r.affected]
        rank = min((r.rank for r in affected if r.rank), key=lambda r: rank_sort_key(r, config), default="")
        deadline = min((r.deadline for r in affected if r.deadline), default=None)
        notes = list(dict.fromkeys(n for n in [advisory.note, *(
            "比較不能あり" for r in affected if r.status != AFFECTED)] if n))

        def names(status: str) -> str:
            return "; ".join(env for env, s in statuses.items() if s == status)

        table.append([
            advisory.advisory_id, advisory.cve_id, advisory.product_name, advisory.affected_version, overall,
            names(AFFECTED), names("影響なし"), names(UNUSED), names(NOT_APPLICABLE), names(UNKNOWN),
            rank, _fmt_date(deadline), " / ".join(notes),
        ])
    return table


def matrix_table(advisories: list[Advisory], rows: list[Verdict], envs: list[EnvInventory]) -> tuple[list[str], list[list[str]]]:
    header = ["社内通達ID", "CVE_ID", "製品名", *[e.name for e in envs]]
    table = []
    for advisory, group in group_by_advisory(advisories, rows):
        statuses = env_status(group)
        table.append([advisory.advisory_id, advisory.cve_id, advisory.product_name,
                      *[statuses.get(e.name, "") for e in envs]])
    return header, table


def parse_collected_at(text: str) -> datetime | None:
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")) if text else None
    except ValueError:
        return None


def stale_warning(env: EnvInventory, today: date, stale_days: int) -> str:
    collected = parse_collected_at(env.collected_at)
    if collected and (today - collected.date()).days > stale_days:
        return f"回収から {(today - collected.date()).days} 日経過しています"
    return ""


def coverage_table(envs: list[EnvInventory], today: date, config: dict[str, Any]) -> list[list[str]]:
    table = []
    for env in envs:
        notes = list(env.warnings)
        stale = stale_warning(env, today, int(config.get("stale_days") or 90))
        if stale:
            notes.append(stale)
        notes.extend(f"製品の版取得に失敗: {p.name}（{p.reason}）" for p in env.failed_probes)
        notes.extend(f"{name}: {s.status}（{s.reason}）" for name, s in env.sections.items()
                     if s.status in ("failed", "skipped") and name != "syft")
        if not env.cve_coverage:
            coverage = "不可"
        elif env.missing_db:
            coverage = "一部のみ"
        else:
            coverage = "可"
        if env.hotfixes is not None:
            hotfix = f"{len(env.hotfixes)} 件"
        else:
            hotfix = "対象外" if env.os_family == "linux" else "回収なし"
        table.append([
            env.name, env.exposure, env.system_name, "登録済み" if env.registered else "未登録",
            env.os_name or env.os_family, env.os_build, env.collected_at,
            "\n".join(env.files) or ("（回収フォルダなし）" if env.not_collected else "（読めるファイルなし）"),
            str(len(env.components)), coverage, hotfix,
            "\n".join(notes), "\n".join(env.unreadable[:50]), "\n".join(sorted(set(env.out_of_scope_running))[:50]),
        ])
    return table


def _db_summary(db_info: dict[str, dict]) -> dict[str, str]:
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


def overview(advisories: list[Advisory], rows: list[Verdict], new_findings: list[Verdict],
             envs: list[EnvInventory], config: dict[str, Any], db_info: dict[str, dict] | None = None) -> dict[str, Any]:
    """標準出力とサマリシートに出す集計。"""
    summary = summary_table(advisories, rows, config)
    overall = Counter(line[4] for line in summary)
    affected = [r for r in rows if r.affected]
    return {
        "advisories": len(advisories),
        "environments": len(envs),
        "overall": {status: overall.get(status, 0) for status in _OVERALL},
        "rank": dict(Counter(r.rank for r in affected)),
        "env_affected": dict(Counter(r.env for r in affected)),
        "overdue": sum(1 for r in affected if "期限超過" in r.note),
        "new_findings": len(new_findings),
        "updates": len(update_table(rows, new_findings, config)),
        "unregistered": [e.name for e in envs if not e.registered],
        "not_collected": [e.name for e in envs if e.not_collected],
        "db": _db_summary(db_info or {}),
    }
