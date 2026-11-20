"""手元の脆弱性データベースで、回収したコンポーネントを照合する。"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable

from ..models import EnvInventory, Finding
from .ecosystems import Query, build_query, normalize_package
from .store import VulnDB, record_ids
from .versions import UncomparableVersion, compare

_EVENT_ORDER = {"introduced": 0, "last_affected": 1, "fixed": 2, "limit": 3}


def _events(range_: dict) -> list[tuple[str, str]]:
    events = []
    for event in range_.get("events") or []:
        for kind, value in event.items():
            if kind in _EVENT_ORDER and value is not None:
                events.append((kind, str(value)))
    return events


def evaluate_range(ecosystem: str, version: str, range_: dict) -> tuple[bool, str]:
    """1つの影響範囲を評価して (影響あり, 修正バージョン) を返す。比較できなければ例外。"""
    events = _events(range_)

    def less(a: str, b: str) -> bool:
        if a == "0":
            return b != "0"
        if b == "0":
            return False
        return compare(ecosystem, a, b) < 0

    # バージョン順に並べる（同じ版なら introduced → last_affected → fixed）
    ordered: list[tuple[str, str]] = []
    for item in sorted(events, key=lambda e: _EVENT_ORDER[e[0]]):
        position = len(ordered)
        for index, other in enumerate(ordered):
            if less(item[1], other[1]):
                position = index
                break
        ordered.insert(position, item)

    affected = False
    fixed = ""
    for kind, value in ordered:
        if kind == "limit":
            continue
        if value != "0" and compare(ecosystem, version, value) < 0:
            if affected and kind == "fixed" and not fixed:
                fixed = value
            break
        if kind == "introduced":
            affected = True
        elif kind == "fixed":
            affected = False
        elif kind == "last_affected":
            affected = compare(ecosystem, version, value) == 0
    return affected, fixed


def evaluate(ecosystem: str, version: str, affected: dict) -> tuple[bool | None, str]:
    """1つの affected 項目を評価する。(影響あり / なし / 比較不能=None, 修正バージョン)"""
    if version in (affected.get("versions") or []):
        hit, fixed = True, ""
    else:
        hit, fixed = False, ""
    uncomparable = False
    for range_ in affected.get("ranges") or []:
        if range_.get("type") not in ("ECOSYSTEM", "SEMVER"):
            continue
        try:
            range_hit, range_fixed = evaluate_range(ecosystem, version, range_)
        except (UncomparableVersion, ValueError):
            uncomparable = True
            continue
        if range_hit:
            hit = True
            fixed = fixed or range_fixed
    if not hit and uncomparable:
        return None, ""
    return hit, fixed


def _matches_ecosystem(pattern: str, ecosystem: str) -> bool:
    return ecosystem.startswith(pattern[:-1]) if pattern.endswith("%") else ecosystem == pattern


def _is_informational(record: dict) -> bool:
    """脆弱性ではない参考情報（RustSec の「保守終了」など）か。Trivy と同じく対象外にする。"""
    for affected in record.get("affected") or []:
        if (affected.get("database_specific") or {}).get("informational"):
            return True
    return bool((record.get("database_specific") or {}).get("informational"))


def pick_score(scores: dict[str, float], priority: list[str]) -> float | None:
    for source in priority or []:
        if source.lower() in scores:
            return scores[source.lower()]
    return max(scores.values()) if scores else None


def scan_with_vulndb(
    envs: list[EnvInventory],
    db: VulnDB,
    config: dict[str, Any],
    log: Callable[[str], None] = lambda m: None,
) -> list[Finding]:
    settings = config.get("vulndb") or {}
    priority = config.get("cvss_source_priority") or ["nvd"]
    available = db.sources()
    max_age = int(settings.get("max_age_days") or 7)
    now = datetime.now(timezone.utc)
    for source, info in sorted(available.items()):
        try:
            updated = datetime.fromisoformat(str(info["updated_at"]).replace("Z", "+00:00"))
        except ValueError:
            continue
        if (now - updated).days > max_age:
            for env in envs:
                env.warnings.append(f"脆弱性データ {source} が {(now - updated).days} 日前のものです（db-update で更新）")
            break

    findings: list[Finding] = []
    for env in envs:
        missing: Counter = Counter()
        for component in env.components:
            if not component.scannable or not component.purl:
                continue
            query = build_query(component, env, bool(settings.get("ubuntu_pro")))
            if query is None:
                continue
            if not query.ecosystems or query.source not in available:
                missing[query.source] += 1
                continue
            component.checked = True
            findings.extend(_scan_component(env, component, query, db, priority))
        env.missing_db = dict(missing)
        for source, count in sorted(missing.items()):
            env.warnings.append(f"{source} の脆弱性データが無いため、{count} 件のパッケージを照合していません")
        log(f"照合: {env.name}（{sum(1 for c in env.components if c.checked)} 件）")

    unique: dict[tuple, Finding] = {}
    for finding in findings:
        key = (finding.env, finding.cve_id, finding.pkg_name, finding.installed_version, finding.path)
        if key in unique:
            unique[key].ids = tuple(dict.fromkeys((*unique[key].ids, *finding.ids)))
        else:
            unique[key] = finding
    return list(unique.values())


def _scan_component(env: EnvInventory, component, query: Query, db: VulnDB, priority: list[str]) -> list[Finding]:
    results = []
    for ecosystem, record in db.lookup(query.ecosystems, query.names):
        hit = None
        fixed = ""
        if _is_informational(record):
            continue
        for affected in record.get("affected") or []:
            package = affected.get("package") or {}
            package_ecosystem = str(package.get("ecosystem") or "")
            if not any(_matches_ecosystem(p, package_ecosystem) for p in query.ecosystems):
                continue
            # 1つの記録に複数のパッケージが載っていることがあるので、名前も確かめる
            if normalize_package(package_ecosystem, str(package.get("name") or "")) not in query.names:
                continue
            result, result_fixed = evaluate(ecosystem, query.version, affected)
            if result:
                hit, fixed = True, fixed or result_fixed
                break
            if result is None and hit is None:
                hit = "uncomparable"
        if not hit:
            continue
        ids = record_ids(record)
        cves = [i.upper() for i in ids if i.upper().startswith("CVE-")]
        scores = db.scores(ids)
        cvss = pick_score(scores, priority)
        vendor = str((record.get("database_specific") or {}).get("severity") or "")
        title = str(record.get("summary") or "")
        if record.get("id") and not title.startswith(str(record["id"])):
            title = f"{record['id']}: {title}" if title else str(record["id"])
        for vuln_id in cves or [str(record.get("id"))]:
            results.append(Finding(
                env=env.name, cve_id=vuln_id, pkg_name=query.display, installed_version=query.version,
                fixed_version=fixed, path=component.path, cvss=cvss, severity=vendor, title=title,
                sbom=query.source, ids=tuple(ids), uncomparable=hit == "uncomparable",
            ))
    return results
