from zeijaku_kakunin.judge import Judge
from zeijaku_kakunin.models import AFFECTED, AFFECTED_UNCOMPARABLE, NOT_AFFECTED, UNKNOWN, Finding

from conftest import comp, make_env

WINDOWS_CVE = {"CVE-2024-21338": {"found": True, "cvss": 7.8, "fixes": [
    {"product": "Windows Server 2019", "kb": "KB5034768", "fixed_build": "10.0.17763.5458"}]}}


class FakeMsrc:
    error = None

    def __init__(self, data):
        self.data = data

    def lookup(self, cve_id):
        return self.data.get(cve_id, {"cve": cve_id, "found": False, "fixes": [], "cvss": None})


def checked_env(**kwargs):
    return make_env(components=[comp("x", "1", checked=True)], **kwargs)


def run(config, env, findings=(), cves=None, msrc=None):
    return Judge(env, list(findings), config, msrc).run(cves)


def statuses(result):
    return [(r.cve_id, r.status) for r in result.cve_rows]


def test_without_cve_list_lists_every_finding(config):
    env = checked_env()
    findings = [Finding("env1", "CVE-2024-2", "zlib", "1.2", "1.3", "/b"),
                Finding("env1", "CVE-2024-1", "openssl", "3.0", "3.1", "/a")]
    result = run(config, env, findings)
    assert result.cve_rows == []
    assert [(r.cve_id, r.package, r.fixed, r.in_list) for r in result.vulns] == [
        ("CVE-2024-1", "openssl", "3.1", False), ("CVE-2024-2", "zlib", "1.3", False)]


def test_cve_list_affected_and_not_found(config):
    env = checked_env()
    findings = [Finding("env1", "CVE-2024-1", "openssl", "3.0", "3.1", "/a"),
                Finding("env1", "CVE-2024-2", "zlib", "1.2", "1.3", "/b")]
    result = run(config, env, findings, ["CVE-2024-1", "CVE-2099-0001"])
    assert statuses(result) == [("CVE-2024-1", AFFECTED), ("CVE-2099-0001", NOT_AFFECTED)]
    assert result.cve_rows[0].fixed == "3.1" and result.cve_rows[0].path == "/a"
    # 見つかった脆弱性は一覧に無いものも出し、一覧にあるものに印を付けて先に並べる
    assert [(r.cve_id, r.in_list) for r in result.vulns] == [("CVE-2024-1", True), ("CVE-2024-2", False)]


def test_not_affected_only_when_it_can_be_checked(config):
    """確かめられないときは「影響なし」にしない。"""
    missing = checked_env()
    missing.missing_db = {"Ubuntu": 120}
    row = run(config, missing, cves=["CVE-2024-1"]).cve_rows[0]
    assert row.status == UNKNOWN and "Ubuntu（120 件）" in row.note
    nothing = make_env(components=[comp("x", "1")])          # 照合できたソフトが無い
    assert statuses(run(config, nothing, cves=["CVE-2024-1"])) == [("CVE-2024-1", UNKNOWN)]
    stopped = checked_env(incomplete=True)
    assert statuses(run(config, stopped, cves=["CVE-2024-1"])) == [("CVE-2024-1", UNKNOWN)]


def test_matches_by_any_id_and_uncomparable(config):
    env = checked_env()
    alas = Finding("env1", "ALAS2-2024-1", "openssl-libs", "1:1.0.2k-24", "1:1.0.2k-25", ids=("ALAS2-2024-1", "CVE-2024-5535"))
    weird = Finding("env1", "CVE-2024-9", "p", "weird", ids=("CVE-2024-9",), uncomparable=True)
    result = run(config, env, [alas, weird], ["cve-2024-5535", "CVE-2024-9"])
    assert statuses(result) == [("cve-2024-5535", AFFECTED), ("CVE-2024-9", AFFECTED_UNCOMPARABLE)]


def test_multi_cve_notice_matches_only_its_own_cve(config):
    """1 つの告知（ALAS）に CVE が 2 つ → CVE ごとの検出。一覧の CVE には、その CVE の検出だけを紐づける。"""
    env = checked_env()
    ids = ("ALAS2023-2024-1", "CVE-2024-4741", "CVE-2024-5535")
    findings = [Finding("env1", "CVE-2024-4741", "openssl-libs", "1:3.0.8-1", ids=ids),
                Finding("env1", "CVE-2024-5535", "openssl-libs", "1:3.0.8-1", ids=ids)]
    result = run(config, env, findings, ["CVE-2024-5535"])
    assert [(r.cve_id, r.package) for r in result.cve_rows] == [("CVE-2024-5535", "openssl-libs")]
    assert [(r.cve_id, r.in_list) for r in result.vulns] == [("CVE-2024-5535", True), ("CVE-2024-4741", False)]


def test_same_jar_in_two_places_keeps_both_rows(config):
    env = checked_env()
    findings = [Finding("env1", "CVE-2021-44228", "log4j-core", "2.14.1", "2.15.0", path) for path in ("/a", "/b", "/b")]
    result = run(config, env, findings, ["CVE-2021-44228"])
    assert sorted(r.path for r in result.cve_rows) == ["/a", "/b"]
    assert len(result.vulns) == 2


def test_windows_os_by_build_number(config):
    msrc = FakeMsrc(WINDOWS_CVE)
    old = checked_env(os_family="windows", os_build="10.0.17763.5329", os_name="Windows Server 2019")
    row = run(config, old, cves=["CVE-2024-21338"], msrc=msrc).cve_rows[0]
    assert (row.status, row.package, row.version) == (AFFECTED, "Windows Server 2019", "10.0.17763.5329")
    assert "KB5034768" in row.note
    patched = checked_env(os_family="windows", os_build="10.0.17763.6000")
    assert statuses(run(config, patched, cves=["CVE-2024-21338"], msrc=msrc)) == [("CVE-2024-21338", NOT_AFFECTED)]
    linux = run(config, checked_env(os_family="linux"), cves=["CVE-2024-21338"], msrc=msrc).cve_rows[0]
    assert linux.status == NOT_AFFECTED and "Windows ではありません" in linux.note
    # OS を判別できないサーバーを「Windows 以外＝影響なし」にしない
    unknown = run(config, checked_env(os_family="unknown"), cves=["CVE-2024-21338"], msrc=msrc)
    assert statuses(unknown) == [("CVE-2024-21338", UNKNOWN)]
    # Windows OS の CVE でなければ、ふつうの照合
    other = run(config, checked_env(os_family="windows", os_build="10.0.17763.5329"), cves=["CVE-2021-44228"], msrc=msrc)
    assert statuses(other) == [("CVE-2021-44228", NOT_AFFECTED)]


def test_msrc_error_is_reported(config):
    msrc = FakeMsrc({})
    msrc.error = "Microsoft の公開データに接続できません"
    result = run(config, checked_env(), cves=["CVE-2024-1"], msrc=msrc)
    assert any("接続できません" in m for m in result.messages)
