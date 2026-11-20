"""通達 × 環境 の判定。

会社公表リストの1件ごとに、すべての環境について
影響あり / 影響なし / 未使用 / 対象外 / 判定不能 のいずれかを必ず決める。
"""
from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date
from typing import Any

from .inventory import normalize_kb
from .matching.names import build_matcher
from .matching.rank import decide_rank
from .matching.versions import version_matches
from .models import (
    AFFECTED,
    AFFECTED_UNCOMPARABLE,
    KIND_CUSTOM,
    KIND_MAVEN,
    NOT_AFFECTED,
    NOT_APPLICABLE,
    NOT_DETECTED,
    UNKNOWN,
    UNUSED,
    Advisory,
    Component,
    EnvInventory,
    TrivyFinding,
    Verdict,
)
from .msrc import MsrcClient, evaluate_build

CAT_TRIVY = "CVE（Trivy）"
CAT_TRIVY_RULE = "CVE（Trivy＋ルール）"
CAT_RULE = "ルール（製品・版）"
CAT_KB = "KB"
CAT_MSRC = "Windows OS（ビルド番号）"
CAT_NEW = "新規検出"
STATUS_NEW = "影響あり（新規検出）"

# 影響ありが無い場合に、どの結果を代表にするか（左ほど優先）
_PRIORITY = [UNKNOWN, NOT_AFFECTED, NOT_DETECTED, NOT_APPLICABLE, UNUSED]


@dataclass
class JudgeResult:
    rows: list[Verdict] = field(default_factory=list)            # 通達 × 環境 × パッケージ
    new_findings: list[Verdict] = field(default_factory=list)    # 通達に無い Trivy 検出
    messages: list[str] = field(default_factory=list)


def _finding_component(finding: TrivyFinding) -> Component:
    group, _, artifact = finding.pkg_name.rpartition(":")
    if group:
        return Component(name=artifact, version=finding.installed_version, kind=KIND_MAVEN, group=group)
    return Component(name=finding.pkg_name, version=finding.installed_version)


class Judge:
    def __init__(
        self,
        envs: list[EnvInventory],
        findings: list[TrivyFinding],
        config: dict[str, Any],
        base_date: date,
        msrc: MsrcClient | None = None,
    ) -> None:
        self.envs = envs
        self.config = config
        self.base_date = base_date
        self.msrc = msrc
        self.findings: dict[tuple[str, str], list[TrivyFinding]] = defaultdict(list)
        self.cvss: dict[str, float] = {}
        for finding in findings:
            self.findings[(finding.env, finding.cve_id)].append(finding)
            if finding.cvss is not None:
                self.cvss[finding.cve_id] = max(self.cvss.get(finding.cve_id, 0.0), finding.cvss)
        self.all_findings = findings

    # ------------------------------------------------------------ 個別の判定

    def _base(self, advisory: Advisory, env: EnvInventory, status: str, category: str, **kwargs) -> Verdict:
        return Verdict(
            status=status, env=env.name, exposure=env.exposure, category=category,
            cve_id=advisory.cve_id, advisory_id=advisory.advisory_id, advisory=advisory,
            **{"package": advisory.product_name, "condition": advisory.affected_version, **kwargs},
        )

    def _judge_cve(self, advisory: Advisory, env: EnvInventory) -> tuple[list[Verdict], bool]:
        """Trivy と Windows OS（MSRC）による判定。2つ目の戻り値は MSRC で結論が出たか。"""
        rows = []
        for finding in self.findings.get((env.name, advisory.cve_id), []):
            condition = advisory.affected_version or (f"修正: {finding.fixed_version}" if finding.fixed_version else "")
            rows.append(self._base(
                advisory, env, AFFECTED, CAT_TRIVY, package=finding.pkg_name,
                version=finding.installed_version, condition=condition, path=finding.path or finding.sbom,
                cvss=finding.cvss,
            ))
        decided = False
        if self.msrc is not None:
            info = self.msrc.lookup(advisory.cve_id)
            if info and info.get("fixes"):
                decided = True
                if info.get("cvss") is not None:
                    self.cvss.setdefault(advisory.cve_id, info["cvss"])
                if env.os_family == "windows":
                    eol = (self.config.get("msrc") or {}).get("eol_builds") or []
                    status, detail = evaluate_build(env.os_build, info, eol)
                    rows.append(self._base(
                        advisory, env, status, CAT_MSRC, package=env.os_name or "Windows",
                        version=env.os_build, condition=detail, path="OS ビルド番号", cvss=info.get("cvss"),
                    ))
                elif not rows:
                    rows.append(self._base(
                        advisory, env, NOT_APPLICABLE, CAT_MSRC, package=advisory.product_name or "Windows",
                        note="Windows OS の脆弱性のため Windows 以外は対象外",
                    ))
        return rows, decided

    def _judge_kb(self, advisory: Advisory, env: EnvInventory) -> list[Verdict]:
        kbs = [kb for kb in (normalize_kb(part) for part in re.split(r"[|,、/\s]+", advisory.product_name)) if kb]
        if env.os_family != "windows":
            return [self._base(advisory, env, NOT_APPLICABLE, CAT_KB, note="Windows 以外の環境")]
        if env.hotfixes is None:
            return [self._base(advisory, env, UNKNOWN, CAT_KB, note="適用済み KB の情報を回収できていません")]
        applied = [kb for kb in kbs if kb in env.hotfixes]
        if applied:
            return [self._base(advisory, env, NOT_AFFECTED, CAT_KB, version=f"適用済み（{applied[0]}）",
                               path="適用済み KB 一覧")]
        return [self._base(advisory, env, AFFECTED, CAT_KB, version="未適用", path="適用済み KB 一覧")]

    def _judge_product(self, advisory: Advisory, env: EnvInventory) -> list[Verdict]:
        matcher = build_matcher(advisory.product_name, self.config.get("aliases") or {})
        components = [c for c in env.components if matcher(c)]
        if any(c.version for c in components):
            # 版が分かった結果があるなら、「存在だけ分かった」個別製品の結果は使わない
            components = [c for c in components if c.version or c.kind != KIND_CUSTOM]
        rows = []
        for component in components:
            common = dict(package=component.name if not component.group else f"{component.group}:{component.name}",
                          version=component.version, path=component.path or component.source)
            if advisory.affected_version:
                matched = version_matches(component.version, advisory.affected_version)
                if matched is True:
                    rows.append(self._base(advisory, env, AFFECTED, CAT_RULE, **common))
                elif matched is False:
                    rows.append(self._base(advisory, env, NOT_AFFECTED, CAT_RULE, **common))
                else:
                    rows.append(self._base(advisory, env, AFFECTED_UNCOMPARABLE, CAT_RULE,
                                           note="バージョンを比較できないため安全側で影響ありと判定", **common))
            elif not advisory.cve_id:
                rows.append(self._base(advisory, env, AFFECTED, CAT_RULE,
                                       note="影響バージョンの記載がないため全バージョンを対象と判定", **common))
            elif component.scannable and env.cve_coverage:
                rows.append(self._base(advisory, env, NOT_AFFECTED, CAT_RULE,
                                       note="製品は存在するが Trivy でこの CVE は未検出", **common))
            else:
                rows.append(self._base(advisory, env, AFFECTED_UNCOMPARABLE, CAT_RULE,
                                       note="製品は存在するが影響バージョンの記載がなく Trivy でも判定できない", **common))
        if rows:
            return rows
        for probe in env.failed_probes:
            if matcher(Component(name=probe.name)):
                return [self._base(advisory, env, UNKNOWN, CAT_RULE,
                                   note=f"製品の版取得に失敗しています（{probe.reason or '理由不明'}）")]
        if not env.has_inventory:
            return [self._base(advisory, env, UNKNOWN, CAT_RULE, note="インベントリを回収できていません")]
        if env.incomplete:
            return [self._base(advisory, env, UNKNOWN, CAT_RULE, note="収集が未完了のため、存在しないと断定できません")]
        if not env.full_collection:
            return [self._base(advisory, env, UNKNOWN, CAT_RULE,
                               note="回収データが一部のみ（SBOM も inventory.json も無い）のため、存在しないと断定できません")]
        return [self._base(advisory, env, UNUSED, CAT_RULE)]

    # ------------------------------------------------------------ まとめ

    def judge_one(self, advisory: Advisory, env: EnvInventory) -> list[Verdict]:
        rows: list[Verdict] = []
        msrc_decided = False
        if advisory.cve_id:
            cve_rows, msrc_decided = self._judge_cve(advisory, env)
            rows.extend(cve_rows)
        if advisory.is_kb:
            rows.extend(self._judge_kb(advisory, env))
        elif advisory.product_name:
            rule_rows = self._judge_product(advisory, env)
            trivy_rows = [r for r in rows if r.category == CAT_TRIVY]
            matcher = build_matcher(advisory.product_name, self.config.get("aliases") or {})
            used: set[int] = set()
            seen: set[tuple] = set()
            for rule_row in rule_rows:
                key = (rule_row.status, rule_row.package, rule_row.version, rule_row.path)
                if key in seen:
                    continue                  # SBOM 内で重複しているコンポーネント
                seen.add(key)
                # Trivy とルールの両方で同じパッケージがヒットした場合は1行にまとめる
                twin = None
                if rule_row.affected:
                    candidates = [t for t in trivy_rows if id(t) not in used and t.version == rule_row.version
                                  and matcher(_finding_component(TrivyFinding(env.name, t.cve_id, t.package, t.version)))]
                    twin = next((t for t in candidates if t.path == rule_row.path), None) or next(
                        (t for t in candidates if not t.path or not rule_row.path), None)
                if twin is None:
                    rows.append(rule_row)
                    continue
                used.add(id(twin))
                twin.category = CAT_TRIVY_RULE
                twin.path = twin.path or rule_row.path
        elif not rows and not msrc_decided:
            if env.cve_coverage:
                rows.append(self._base(advisory, env, NOT_DETECTED, CAT_TRIVY,
                                       note="製品名の記載がないため「未使用」との区別はできません"))
            else:
                rows.append(self._base(advisory, env, UNKNOWN, CAT_TRIVY,
                                       note="Trivy で判定できる SBOM がありません"))

        affected = [r for r in rows if r.affected]
        if affected:
            for row in affected:
                self._finish_affected(row, env)
            return affected
        for status in _PRIORITY:
            chosen = [r for r in rows if r.status == status]
            if chosen:
                for row in chosen:
                    row.note = self._join_note(row.note, row.advisory.note if row.advisory else "")
                return chosen
        return [self._base(advisory, env, UNKNOWN, "", note="判定できる情報がありません")]

    @staticmethod
    def _join_note(*parts: str) -> str:
        return " / ".join(p for p in parts if p)

    def _finish_affected(self, row: Verdict, env: EnvInventory) -> None:
        if row.cvss is None and row.cve_id:
            row.cvss = self.cvss.get(row.cve_id)
        row.rank, row.deadline, row.base_date = decide_rank(
            row.advisory, row.cvss, env.exposure, self.config, self.base_date)
        overdue = "期限超過" if row.deadline < self.base_date else ""
        row.note = self._join_note(overdue, row.note, row.advisory.note if row.advisory else "")

    def run(self, advisories: list[Advisory], only_advisory: bool = False) -> JudgeResult:
        result = JudgeResult()
        for advisory in advisories:
            for env in self.envs:
                result.rows.extend(self.judge_one(advisory, env))
        if self.msrc is not None and self.msrc.error:
            result.messages.append(
                f"{self.msrc.error}。Windows OS のビルド番号による判定は行っていません。")
        if not only_advisory:
            known = {a.cve_id for a in advisories if a.cve_id}
            env_map = {e.name: e for e in self.envs}
            for finding in self.all_findings:
                if finding.cve_id in known:
                    continue
                env = env_map[finding.env]
                row = Verdict(
                    status=STATUS_NEW, env=env.name, exposure=env.exposure, category=CAT_NEW,
                    cve_id=finding.cve_id, package=finding.pkg_name, version=finding.installed_version,
                    condition=f"修正: {finding.fixed_version}" if finding.fixed_version else "",
                    path=finding.path or finding.sbom, cvss=finding.cvss, note=finding.title,
                )
                row.rank, row.deadline, row.base_date = decide_rank(
                    None, row.cvss, env.exposure, self.config, self.base_date)
                result.new_findings.append(row)
        return result
