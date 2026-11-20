"""手元の脆弱性データベースで、回収したコンポーネントを照合する。"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable

from ..models import EnvInventory, Finding
from .ecosystems import Query, build_query, normalize_package, skip_reason
from .ecosystems import AMAZON_PREFIX
from .store import EXTRAS_PREFIX, VulnDB, record_ids
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


def stale_sources(db: VulnDB, config: dict[str, Any], now: datetime | None = None) -> list[str]:
    """更新が古くなっているデータの説明（例: 「Maven（2 日前）」）。"""
    max_age = int(((config.get("vulndb") or {}).get("max_age_days")) or 1)
    now = now or datetime.now(timezone.utc)
    result = []
    for source, info in sorted(db.sources().items()):
        try:
            updated = datetime.fromisoformat(str(info["updated_at"]).replace("Z", "+00:00"))
        except ValueError:
            result.append(f"{source}（更新日時不明）")
            continue
        age = now - updated
        if age.total_seconds() > max_age * 86400:
            result.append(f"{source}（{age.days} 日前）" if age.days else f"{source}（{int(age.total_seconds() // 3600)} 時間前）")
    return result


def _source_of(component, env: EnvInventory) -> str:
    query = build_query(component, env)
    return query.source if query else ""


def _first_fixed(affected: dict) -> str:
    for range_ in affected.get("ranges") or []:
        for event in range_.get("events") or []:
            if event.get("fixed"):
                return str(event["fixed"])
    return ""


def _is_informational(record: dict, affected: dict | None = None) -> bool:
    """脆弱性ではない参考情報（RustSec の「保守終了」など）か。Trivy と同じく対象外にする。

    記録全体の印と、照合しているパッケージの項目の印だけを見る（他のパッケージの項目の印で、
    記録ごと捨てないようにするため）。
    """
    if (record.get("database_specific") or {}).get("informational"):
        return True
    return bool(affected is not None and (affected.get("database_specific") or {}).get("informational"))


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

    findings: list[Finding] = []
    for env in envs:
        missing: Counter = Counter()
        unsupported: Counter = Counter()
        for component in env.components:
            if not component.scannable or not component.purl:
                continue
            query = build_query(component, env)
            if query is None:
                reason = skip_reason(component)
                if reason:
                    unsupported[reason] += 1
                continue
            if not query.ecosystems or query.source not in available:
                missing[query.source] += 1
                continue
            component.checked = True
            findings.extend(_scan_component(env, component, query, db, priority))
        # Amazon Linux 2 は extras（kernel-5.10 など）の情報が無いと、そのパッケージの脆弱性を見落とす
        al2 = sum(1 for c in env.components if c.checked and _source_of(c, env) == f"{AMAZON_PREFIX}2")
        extras_expected = settings.get("amazon_extras", "all") not in ([], "", "none", False)
        if al2 and extras_expected and not any(name.startswith(EXTRAS_PREFIX) for name in available):
            missing[f"{AMAZON_PREFIX}2 extras"] += al2
        env.missing_db = dict(missing)
        if unsupported:
            # 黙って飛ばさず、照合しなかったものを件数で示す
            env.warnings.append("照合の対象外: " + "、".join(f"{k} {v} 件" for k, v in unsupported.most_common()))
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
        entries = []
        for affected in record.get("affected") or []:
            package = affected.get("package") or {}
            package_ecosystem = str(package.get("ecosystem") or "")
            if not any(_matches_ecosystem(p, package_ecosystem) for p in query.ecosystems):
                continue
            # 1つの記録に複数のパッケージが載っていることがあるので、名前も確かめる
            if normalize_package(package_ecosystem, str(package.get("name") or "")) not in query.names:
                continue
            if _is_informational(record, affected):
                continue
            entries.append((package_ecosystem, affected))
        # Ubuntu: 通常の情報があればそれを使い、Pro（ESM）の情報しか無いときだけ Pro の情報で判定する
        standard = [e for e in entries if ":Pro:" not in e[0]]
        pro_only = bool(entries) and not standard
        for package_ecosystem, affected in (standard or entries):
            if pro_only and "esm" not in query.version:
                # Pro の修正は通常の配布物に入らないので、Pro の版を入れていなければ版番号によらず未修正
                hit, fixed = True, fixed or _first_fixed(affected)
                break
            result, result_fixed = evaluate(package_ecosystem, query.version, affected)
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
        if pro_only:
            title = f"修正版は Ubuntu Pro（ESM）でのみ提供 / {title}"
        for vuln_id in cves or [str(record.get("id"))]:
            results.append(Finding(
                env=env.name, cve_id=vuln_id, pkg_name=query.display, installed_version=query.version,
                fixed_version=fixed, path=component.path, cvss=cvss, severity=vendor, title=title,
                sbom=query.source, ids=tuple(ids), uncomparable=hit == "uncomparable",
            ))
    return results
