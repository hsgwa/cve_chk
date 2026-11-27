"""1 台のサーバーの判定。

- 見つかった脆弱性の一覧（脆弱性データとの照合で検出したもの、すべて）
- CVE の一覧を渡したときは、その CVE ごとに 影響あり / 影響なし / 判定不能
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .models import AFFECTED, AFFECTED_UNCOMPARABLE, NOT_AFFECTED, NOT_APPLICABLE, UNKNOWN, EnvInventory, Finding
from .msrc import MsrcClient, evaluate_build


@dataclass
class Row:
    """判定 1 行（CVE × ソフトウェア）。"""

    cve_id: str
    status: str = AFFECTED
    package: str = ""
    version: str = ""
    fixed: str = ""             # この版で直る（分からなければ空）
    path: str = ""              # 見つかった場所
    note: str = ""
    ecosystem: str = ""         # 版の比べ方（Ubuntu、Maven など）
    in_list: bool = False       # 渡された CVE の一覧にあるか

    @property
    def affected(self) -> bool:
        return self.status in (AFFECTED, AFFECTED_UNCOMPARABLE)


@dataclass
class Result:
    vulns: list[Row] = field(default_factory=list)       # 見つかった脆弱性（すべて）
    cve_rows: list[Row] = field(default_factory=list)    # CVE の一覧の CVE ごとの判定（一覧を渡したときだけ）
    messages: list[str] = field(default_factory=list)


def _finding_row(finding: Finding) -> Row:
    notes = []
    if finding.uncomparable:
        notes.append("版を比べられないため、安全側で影響ありとした")
    if finding.title:
        notes.append(finding.title)
    return Row(
        cve_id=finding.cve_id, status=AFFECTED_UNCOMPARABLE if finding.uncomparable else AFFECTED,
        package=finding.pkg_name, version=finding.installed_version, fixed=finding.fixed_version,
        path=finding.path or (f"{finding.sbom} のパッケージ" if finding.sbom else ""), note=" / ".join(notes), ecosystem=finding.sbom,
    )


class Judge:
    def __init__(self, env: EnvInventory, findings: list[Finding], config: dict[str, Any],
                 msrc: MsrcClient | None = None) -> None:
        self.env = env
        self.findings = findings
        self.config = config
        self.msrc = msrc

    def _not_found(self, cve: str) -> Row:
        """脆弱性データとの照合で見つからなかった CVE。確かめられないときは「影響なし」にしない。"""
        env = self.env
        if env.missing_db:
            missing = "、".join(f"{k}（{v} 件）" for k, v in sorted(env.missing_db.items()))
            return Row(cve, UNKNOWN, note=f"脆弱性データが無く照合していないソフトがあります: {missing}（zk update で取得）")
        if not env.cve_coverage:
            return Row(cve, UNKNOWN, note="脆弱性データと照合できるソフトがありません（回収物を確かめてください）")
        if env.incomplete:
            return Row(cve, UNKNOWN, note="回収が途中で止まっているため、無いとは言い切れません")
        return Row(cve, NOT_AFFECTED, note="このサーバーのソフトからは見つかりませんでした")

    def _windows_os(self, cve: str) -> Row | None:
        """Windows OS の脆弱性（Microsoft の公開データ）。この CVE が Windows OS のものでなければ None。"""
        if self.msrc is None:
            return None
        info = self.msrc.lookup(cve)
        if not info or not info.get("fixes"):
            return None
        env = self.env
        if env.os_family == "unknown":
            return Row(cve, UNKNOWN, package="Windows", note="Windows OS の脆弱性ですが、このサーバーの OS が分かりません")
        if env.os_family != "windows":
            return Row(cve, NOT_AFFECTED, note="Windows OS の脆弱性です（このサーバーは Windows ではありません）")
        eol = (self.config.get("msrc") or {}).get("eol_builds") or []
        status, detail = evaluate_build(env.os_build, info, eol)
        if status == NOT_APPLICABLE:
            status = NOT_AFFECTED
        return Row(cve, status, package=env.os_name or "Windows", version=env.os_build, path="OS ビルド番号",
                   note=detail)

    def run(self, cve_list: list[str] | None = None) -> Result:
        result = Result()
        wanted = {c.upper() for c in cve_list or []}
        by_id: dict[str, list[Row]] = {}
        seen = set()
        for finding in self.findings:
            row = _finding_row(finding)
            key = (row.cve_id.upper(), row.package, row.version, row.path)
            if key in seen:
                continue
            seen.add(key)
            hits = finding.match_ids & wanted
            row.in_list = bool(hits)
            result.vulns.append(row)
            for vuln_id in hits:
                by_id.setdefault(vuln_id, []).append(row)
        result.vulns.sort(key=lambda r: (not r.in_list, r.package.lower(), r.version, r.cve_id))

        for cve in cve_list or []:
            rows = [Row(cve, r.status, r.package, r.version, r.fixed, r.path, r.note, r.ecosystem, True)
                    for r in by_id.get(cve.upper(), [])]
            os_row = self._windows_os(cve)
            if os_row is not None and (os_row.affected or os_row.status == UNKNOWN or not rows):
                rows.append(os_row)
            affected = [r for r in rows if r.affected]
            if affected:
                result.cve_rows.extend(affected)
            elif rows:
                result.cve_rows.append(next((r for r in rows if r.status == UNKNOWN), rows[0]))
            else:
                result.cve_rows.append(self._not_found(cve))
        for row in result.cve_rows:
            row.in_list = True
        if self.msrc is not None and self.msrc.error:
            result.messages.append(f"{self.msrc.error}。Windows OS の判定は行っていません")
        return result
