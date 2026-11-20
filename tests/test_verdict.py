from datetime import date

from vuln_triage.models import (
    AFFECTED,
    AFFECTED_UNCOMPARABLE,
    KIND_CUSTOM,
    KIND_MAVEN,
    KIND_SOFTWARE,
    NOT_AFFECTED,
    NOT_APPLICABLE,
    NOT_DETECTED,
    UNKNOWN,
    UNUSED,
    FailedProbe,
    Finding,
)
from vuln_triage.verdict import CAT_KB, CAT_MSRC, CAT_RULE, CAT_TRIVY, CAT_TRIVY_RULE, STATUS_NEW, Judge

from conftest import TODAY, comp, make_advisory, make_env


class FakeMsrc:
    error = None

    def __init__(self, data):
        self.data = data

    def lookup(self, cve_id):
        return self.data.get(cve_id, {"cve": cve_id, "found": False, "fixes": [], "cvss": None})


def judge(config, envs, findings=(), msrc=None):
    return Judge(list(envs), list(findings), config, TODAY, msrc)


def one(config, advisory, env, findings=(), msrc=None):
    return judge(config, [env], findings, msrc).judge_one(advisory, env)


def test_product_rule_statuses(config):
    advisory = make_advisory(product_name="tomcat", affected_version="9.0.*")
    assert one(config, advisory, make_env(components=[comp("Tomcat", "9.0.83")]))[0].status == AFFECTED
    assert one(config, advisory, make_env(components=[comp("Tomcat", "10.1.0")]))[0].status == NOT_AFFECTED
    assert one(config, advisory, make_env(components=[comp("Tomcat", "")]))[0].status == AFFECTED_UNCOMPARABLE
    assert one(config, advisory, make_env(components=[comp("nginx", "1.0")]))[0].status == UNUSED


def test_affected_row_gets_rank_and_deadline(config):
    advisory = make_advisory(product_name="tomcat", affected_version="9.0.*", published_date=date(2026, 11, 1),
                             company_rank="Rank-A", deadline_days=14, note="メモ")
    row = one(config, advisory, make_env(exposure="internet", components=[comp("Tomcat", "9.0.83", path="/opt/tomcat")]))[0]
    assert (row.rank, row.deadline, row.base_date) == ("Rank-A", date(2026, 11, 15), date(2026, 11, 1))
    assert row.note.startswith("期限超過") and "メモ" in row.note
    assert (row.category, row.package, row.version, row.path) == (CAT_RULE, "Tomcat", "9.0.83", "/opt/tomcat")


def test_unknown_when_nothing_collected(config):
    advisory = make_advisory(product_name="tomcat", affected_version="9.0.*")
    empty = make_env()
    assert one(config, advisory, empty)[0].status == UNKNOWN
    incomplete = make_env(components=[comp("nginx", "1.0")], incomplete=True)
    assert one(config, advisory, incomplete)[0].status == UNKNOWN
    partial = make_env(components=[comp("nginx", "1.0")])
    partial.full_collection = False
    assert one(config, advisory, partial)[0].status == UNKNOWN


def test_failed_probe_is_unknown_not_unused(config):
    env = make_env(components=[comp("nginx", "1.0")])
    env.failed_probes = [FailedProbe("HULFT", "権限不足")]
    row = one(config, make_advisory(product_name="HULFT", affected_version="<8.5.0"), env)[0]
    assert row.status == UNKNOWN and "権限不足" in row.note
    assert one(config, make_advisory(product_name="DataMagic", affected_version="<3"), env)[0].status == UNUSED


def test_versionless_custom_result_is_dropped_when_version_known(config):
    config["aliases"] = {"HULFT": ["HULFT8 for Windows"]}
    env = make_env(os_family="windows", components=[
        comp("HULFT8 for Windows", "8.5.3", kind=KIND_SOFTWARE), comp("HULFT", "", kind=KIND_CUSTOM)])
    rows = one(config, make_advisory(product_name="HULFT", affected_version="<8.5.0"), env)
    assert [r.status for r in rows] == [NOT_AFFECTED]
    only_custom = make_env(components=[comp("HULFT", "", kind=KIND_CUSTOM)])
    assert one(config, make_advisory(product_name="HULFT", affected_version="<8.5.0"), only_custom)[0].status == \
        AFFECTED_UNCOMPARABLE


def test_no_version_condition(config):
    env = make_env(components=[comp("FooSoft", "1.0", kind=KIND_SOFTWARE)])
    assert one(config, make_advisory(product_name="FooSoft"), env)[0].status == AFFECTED
    # CVE あり・版の記載なし・Trivy で判定できない製品 → 安全側
    assert one(config, make_advisory(product_name="FooSoft", cve_id="CVE-2024-1"), env)[0].status == AFFECTED_UNCOMPARABLE
    # 脆弱性データベースで照合したパッケージで未検出 → 影響なし
    jar = comp("log4j-core", "2.17.1", kind=KIND_MAVEN, group="org.apache.logging.log4j", scannable=True, checked=True)
    scanned = make_env(components=[jar])
    assert one(config, make_advisory(product_name="log4j-core", cve_id="CVE-2021-44228"), scanned)[0].status == NOT_AFFECTED


def test_kb(config):
    advisory = make_advisory(product_name="KB5034441", affected_version="missing")
    windows = make_env(os_family="windows", hotfixes={"KB5034127"})
    row = one(config, advisory, windows)[0]
    assert (row.status, row.category, row.version) == (AFFECTED, CAT_KB, "未適用")
    windows.hotfixes.add("KB5034441")
    assert one(config, advisory, windows)[0].status == NOT_AFFECTED
    assert one(config, advisory, make_env(os_family="windows", hotfixes=None))[0].status == UNKNOWN
    assert one(config, advisory, make_env(os_family="linux"))[0].status == NOT_APPLICABLE


def test_kb_alternatives(config):
    advisory = make_advisory(product_name="KB5034441|KB5035845", affected_version="MISSING")
    assert one(config, advisory, make_env(os_family="windows", hotfixes={"KB5035845"}))[0].status == NOT_AFFECTED
    assert one(config, advisory, make_env(os_family="windows", hotfixes={"KB1111111"}))[0].status == AFFECTED


def test_cve_trivy_and_rule_are_merged(config):
    jar = comp("log4j-core", "2.14.1", kind=KIND_MAVEN, group="org.apache.logging.log4j", path="/opt/a.jar", scannable=True)
    env = make_env(exposure="internet", components=[jar], scanned_sboms=1)
    finding = Finding("env1", "CVE-2021-44228", "org.apache.logging.log4j:log4j-core", "2.14.1", "2.15.0",
                           "/opt/a.jar", 10.0)
    advisory = make_advisory(cve_id="CVE-2021-44228", product_name="log4j-core", affected_version=">=2.0,<2.15.0")
    rows = one(config, advisory, env, [finding])
    assert len(rows) == 1
    assert (rows[0].category, rows[0].status, rows[0].rank, rows[0].cvss) == (CAT_TRIVY_RULE, AFFECTED, "Rank-S", 10.0)


def test_cve_rule_hits_without_trivy(config):
    # 商用ソフトの CVE: Trivy は検出しないが、製品名と版で影響あり
    env = make_env(components=[comp("FooSoft", "1.0", kind=KIND_SOFTWARE)], scanned_sboms=1)
    advisory = make_advisory(cve_id="CVE-2024-1", product_name="FooSoft", affected_version="<2.0")
    row = one(config, advisory, env)[0]
    assert (row.status, row.category) == (AFFECTED, CAT_RULE)


def test_cve_only(config):
    advisory = make_advisory(cve_id="CVE-2023-32681")
    scanned = make_env(components=[comp("x", "1")], scanned_sboms=1)
    assert one(config, advisory, scanned)[0].status == NOT_DETECTED
    assert one(config, advisory, make_env(components=[comp("x", "1")]))[0].status == UNKNOWN
    finding = Finding("env1", "CVE-2023-32681", "requests", "2.25.0", "2.31.0", "/site-packages", 6.1)
    row = one(config, advisory, scanned, [finding])[0]
    assert (row.status, row.category, row.condition, row.rank) == (AFFECTED, CAT_TRIVY, "修正: 2.31.0", "Rank-C")


def test_windows_os_by_build_number(config):
    msrc = FakeMsrc({"CVE-2024-21338": {"found": True, "cvss": 7.8, "fixes": [
        {"product": "Windows Server 2019", "kb": "KB5034768", "fixed_build": "10.0.17763.5458"}]}})
    advisory = make_advisory(cve_id="CVE-2024-21338")
    old = make_env(os_family="windows", os_build="10.0.17763.5329", os_name="Windows Server 2019")
    row = one(config, advisory, old, msrc=msrc)[0]
    assert (row.status, row.category, row.rank, row.cvss) == (AFFECTED, CAT_MSRC, "Rank-B", 7.8)
    assert "KB5034768" in row.condition
    patched = make_env(os_family="windows", os_build="10.0.17763.6000")
    assert one(config, advisory, patched, msrc=msrc)[0].status == NOT_AFFECTED
    assert one(config, advisory, make_env(os_family="linux", scanned_sboms=1), msrc=msrc)[0].status == NOT_APPLICABLE
    # Windows OS の CVE でなければ通常の判定
    other = make_advisory(cve_id="CVE-2021-44228")
    assert one(config, other, make_env(os_family="windows", scanned_sboms=1, components=[comp("x", "1")]),
               msrc=msrc)[0].status == NOT_DETECTED


def test_run_covers_every_advisory_and_env(config):
    envs = [make_env("a", components=[comp("nginx", "1.0")]), make_env("b", components=[comp("nginx", "1.30")])]
    advisories = [make_advisory(advisory_id="A1", product_name="nginx", affected_version="<1.25"),
                  make_advisory(advisory_id="A2", product_name="どこにも無い製品", affected_version="<1")]
    result = judge(config, envs).run(advisories)
    assert {(r.advisory_id, r.env, r.status) for r in result.rows} == {
        ("A1", "a", AFFECTED), ("A1", "b", NOT_AFFECTED), ("A2", "a", UNUSED), ("A2", "b", UNUSED)}


def test_new_findings_and_only_advisory(config):
    env = make_env("a", exposure="internet", components=[comp("x", "1")], scanned_sboms=1)
    findings = [Finding("a", "CVE-2024-1", "known", "1", "2", "/p", 9.8),
                Finding("a", "CVE-2024-2", "newpkg", "1", "2", "/q", 9.8)]
    advisories = [make_advisory(cve_id="CVE-2024-1")]
    result = judge(config, [env], findings).run(advisories)
    assert [(r.cve_id, r.status, r.rank) for r in result.new_findings] == [("CVE-2024-2", STATUS_NEW, "Rank-S")]
    assert judge(config, [env], findings).run(advisories, only_advisory=True).new_findings == []


def test_same_jar_in_two_places_keeps_both_rows(config):
    def jar(path):
        return comp("log4j-core", "2.14.1", kind=KIND_MAVEN, group="org.apache.logging.log4j", path=path, scannable=True)

    env = make_env(components=[jar("/a/log4j.jar"), jar("/b/log4j.jar"), jar("/b/log4j.jar")], scanned_sboms=1)
    finding = Finding("env1", "CVE-2021-44228", "org.apache.logging.log4j:log4j-core", "2.14.1", "2.15.0",
                           "/a/log4j.jar", 10.0)
    advisory = make_advisory(cve_id="CVE-2021-44228", product_name="log4j-core", affected_version="<2.15.0")
    rows = one(config, advisory, env, [finding])
    assert sorted((r.path, r.category) for r in rows) == [("/a/log4j.jar", CAT_TRIVY_RULE), ("/b/log4j.jar", CAT_RULE)]
    assert all(r.cvss == 10.0 and r.rank == "Rank-A" for r in rows)


def test_cve_only_with_missing_database(config):
    env = make_env(components=[comp("x", "1", checked=True)])
    env.missing_db = {"Ubuntu": 120}
    row = one(config, make_advisory(cve_id="CVE-2024-1"), env)[0]
    assert row.status == UNKNOWN and "Ubuntu（120 件）" in row.note


def test_finding_matches_by_any_id_and_vendor_severity(config):
    env = make_env(components=[comp("x", "1", checked=True)])
    finding = Finding("env1", "ALAS2-2024-1", "openssl-libs", "1:1.0.2k-24.amzn2.0.4", "1:1.0.2k-24.amzn2.0.10",
                      "", None, "important", ids=("ALAS2-2024-1", "CVE-2024-5535"))
    row = one(config, make_advisory(cve_id="cve-2024-5535"), env, [finding])[0]
    assert row.status == AFFECTED and "ベンダーの深刻度: important" in row.note and row.rank == "Rank-C"
    uncomparable = Finding("env1", "CVE-2024-9", "p", "weird", ids=("CVE-2024-9",), uncomparable=True)
    assert one(config, make_advisory(cve_id="CVE-2024-9"), env, [uncomparable])[0].status == AFFECTED_UNCOMPARABLE


def test_new_findings_skip_known_aliases(config):
    env = make_env("a", components=[comp("x", "1", checked=True)])
    finding = Finding("a", "GHSA-xxxx", "p", "1", ids=("GHSA-xxxx", "CVE-2024-1"))
    result = judge(config, [env], [finding]).run([make_advisory(cve_id="CVE-2024-1")])
    assert result.new_findings == []


def test_multi_cve_advisory_matches_only_its_own_cve(config):
    # 1つの告知（ALAS）に CVE が2つ → CVE ごとの検出。通達の CVE には、その CVE の検出だけを紐づける
    env = make_env(components=[comp("x", "1", checked=True)])
    ids = ("ALAS2023-2024-1", "CVE-2024-4741", "CVE-2024-5535")
    findings = [Finding("env1", "CVE-2024-4741", "openssl-libs", "1:3.0.8-1", ids=ids),
                Finding("env1", "CVE-2024-5535", "openssl-libs", "1:3.0.8-1", ids=ids)]
    rows = one(config, make_advisory(cve_id="CVE-2024-5535"), env, findings)
    assert [(r.status, r.package) for r in rows] == [(AFFECTED, "openssl-libs")]
    result = judge(config, [env], findings).run([make_advisory(cve_id="CVE-2024-5535")])
    assert [f.cve_id for f in result.new_findings] == ["CVE-2024-4741"]
    # ALAS 番号で書かれた通達には、その告知の検出がすべて紐づく
    assert len(one(config, make_advisory(cve_id="ALAS2023-2024-1"), env, findings)) == 2


def test_rule_uses_ecosystem_version_order(config):
    rpm = comp("openssl-libs", "1:1.0.2k-16.amzn2.1.1",
               purl="pkg:rpm/amzn/openssl-libs@1.0.2k-16.amzn2.1.1?epoch=1&distro=amzn-2")
    env = make_env(components=[rpm])
    advisory = make_advisory(product_name="openssl-libs", affected_version="<1:1.0.2k-24.amzn2.0.10")
    assert one(config, advisory, env)[0].status == AFFECTED          # PEP 440 では「影響なし」と誤判定していた
    jar = comp("log4j-core", "2.0-beta9", kind=KIND_MAVEN, group="org.apache.logging.log4j",
               purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.0-beta9")
    advisory = make_advisory(product_name="log4j-core", affected_version=">=2.0-beta9,<2.15.0")
    assert one(config, advisory, make_env(components=[jar]))[0].status == AFFECTED
