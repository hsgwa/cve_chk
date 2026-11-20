import gzip
import json
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from click.testing import CliRunner

from vuln_triage.cli import main
from vuln_triage.inventory import load_env_dir
from vuln_triage.models import KIND_MAVEN, Component
from vuln_triage.vulndb import store as store_module
from vuln_triage.vulndb.cvss import cvss3_base_score
from vuln_triage.vulndb.ecosystems import build_query, needed_sources, parse_purl_full
from vuln_triage.vulndb.scanner import evaluate, scan_with_vulndb, stale_sources
from vuln_triage.vulndb.store import DELTA_FILE, VulnDB, parse_modified_ids
from vuln_triage.vulndb.versions import (
    compare,
    compare_dpkg,
    compare_maven,
    compare_rpm,
    compare_rubygems,
    compare_semver,
)

from conftest import make_env


# ------------------------------------------------------------------ バージョン比較

@pytest.mark.parametrize("func, a, b, expected", [
    (compare_dpkg, "1:1.0", "2.0", 1),
    (compare_dpkg, "1.0~rc1", "1.0", -1),
    (compare_dpkg, "3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.9", 1),
    (compare_dpkg, "1.0-1", "1.0-1", 0),
    (compare_dpkg, "1.0+dfsg-1", "1.0-1", 1),
    (compare_rpm, "1.0.2k-24.amzn2.0.4", "1.0.2k-24.amzn2.0.10", -1),
    (compare_rpm, "1:1.0-1", "2.0-1", 1),
    (compare_rpm, "1.0~rc1-1", "1.0-1", -1),
    (compare_rpm, "2.17.1-1.amzn2", "2.17.1-1.amzn2", 0),
    (compare_rpm, "1.0a-1", "1.0-1", 1),
    (compare_maven, "2.14.1", "2.15.0", -1),
    (compare_maven, "2.0-beta9", "2.0", -1),
    (compare_maven, "2.0-rc1", "2.0-beta9", 1),
    (compare_maven, "1.0", "1.0.0", 0),
    (compare_maven, "2.15.1", "2.7", 1),
    (compare_maven, "1.0-SNAPSHOT", "1.0", -1),
    (compare_maven, "1.0-sp1", "1.0", 1),
    (compare_semver, "1.2.3-beta.1", "1.2.3", -1),
    (compare_semver, "v0.17.0", "0.17.0", 0),
    (compare_semver, "1.10.0", "1.9.9", 1),
    (compare_semver, "1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    (compare_rubygems, "1.0.0.pre", "1.0.0", -1),
    (compare_rubygems, "1.10", "1.9", 1),
])
def test_version_schemes(func, a, b, expected):
    assert func(a, b) == expected


def test_compare_falls_back_to_generic():
    assert compare("Go", "1.2", "1.10") == -1
    assert compare("npm", "1.0.0.0", "1.0.0.1") == -1        # semver として読めない → 汎用比較


# ------------------------------------------------------------------ CVSS

@pytest.mark.parametrize("vector, score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:4.0/AV:N/AC:L", None),
    ("AV:N/AC:L/Au:N/C:P/I:P/A:P", None),
    ("CVSS:3.1/AV:X", None),
])
def test_cvss3(vector, score):
    assert cvss3_base_score(vector) == score


# ------------------------------------------------------------------ 範囲の評価

def test_evaluate_ranges():
    log4j = {"ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "2.13.0"}, {"fixed": "2.15.0"}, {"introduced": "2.0-beta9"}, {"fixed": "2.12.2"}]}]}
    assert evaluate("Maven", "2.14.1", log4j) == (True, "2.15.0")
    assert evaluate("Maven", "2.12.2", log4j) == (False, "")
    assert evaluate("Maven", "2.15.0", log4j) == (False, "")
    assert evaluate("Maven", "1.2.17", log4j) == (False, "")
    last = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"last_affected": "1.2.3"}]}]}
    assert evaluate("PyPI", "1.2.3", last)[0] is True and evaluate("PyPI", "1.2.4", last)[0] is False
    unfixed = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}
    assert evaluate("Ubuntu:24.04:LTS", "2.42-4ubuntu2.10", unfixed) == (True, "")
    listed = {"versions": ["1.0.1"], "ranges": [{"type": "GIT", "events": [{"introduced": "abc"}]}]}
    assert evaluate("PyPI", "1.0.1", listed)[0] is True and evaluate("PyPI", "1.0.2", listed)[0] is False
    weird = {"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}
    assert evaluate("PyPI", "not-a-version", weird) == (None, "")


# ------------------------------------------------------------------ エコシステムの対応付け

def env_with(os_id="", version=""):
    return make_env(os_id=os_id, os_version_id=version)


def query(purl, env=None, version=""):
    return build_query(Component(name="x", version=version, purl=purl), env or env_with())


def test_parse_purl_full():
    assert parse_purl_full("pkg:golang/github.com/cli/cli@v2.89.0#v2") == (
        "golang", "github.com/cli", "cli", "v2.89.0", {"#subpath": "v2"})
    assert parse_purl_full("pkg:rpm/amzn/openssl@1.0.2k-24?epoch=1&distro=amzn-2")[4] == {"epoch": "1", "distro": "amzn-2"}


def test_library_queries():
    q = query("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
    assert (q.source, q.ecosystems, q.names, q.version) == ("Maven", ("Maven",), ("org.apache.logging.log4j:log4j-core",), "2.14.1")
    assert query("pkg:pypi/Flask_Login@0.6.3").names == ("flask-login",)
    assert query("pkg:npm/%40scope/pkg@1.0.0").names == ("@scope/pkg",)
    go = query("pkg:golang/github.com/cli/cli@v2.89.0#v2")
    assert go.names == ("github.com/cli/cli/v2",) and go.version == "2.89.0"
    assert query("pkg:golang/stdlib@go1.22.0") is not None
    assert query("pkg:gem/bundler@UNKNOWN") is None                     # 版が不明
    assert query("pkg:github/actions/checkout@v4") is None               # 対象外の種類
    assert query("pkg:maven/a/b", version="") is None


def test_os_package_queries():
    deb = query("pkg:deb/ubuntu/libavcodec60@7:6.1.1-3ubuntu5?arch=amd64&distro=ubuntu-24.04&upstream=ffmpeg")
    assert deb.source == "Ubuntu" and deb.ecosystems == ("Ubuntu:24.04:LTS", "Ubuntu:24.04")
    assert deb.names == ("ffmpeg", "libavcodec60") and deb.version == "7:6.1.1-3ubuntu5"
    rpm = query("pkg:rpm/amzn/openssl-libs@1.0.2k-24.amzn2.0.4?arch=x86_64&epoch=1&distro=amzn-2"
                "&upstream=openssl-1.0.2k-24.amzn2.0.4.src.rpm")
    assert rpm.source == "Amazon Linux:2" and rpm.names == ("openssl-libs", "openssl")
    assert rpm.version == "1:1.0.2k-24.amzn2.0.4"
    assert query("pkg:rpm/amzn/curl@8.0.1-1.amzn2023?distro=amzn-2023").source == "Amazon Linux:2023"
    assert query("pkg:rpm/redhat/curl@7.76.1-26.el9?distro=rhel-9.3").ecosystems == ("Red Hat:enterprise_linux:9:%",)
    assert query("pkg:deb/debian/curl@7.88.1-10?distro=debian-12.4").ecosystems == ("Debian:12",)
    # PURL に OS が無ければ環境の OS 情報を使う
    assert query("pkg:rpm/amzn/curl@8.0.1-1", env_with("amzn", "2023")).source == "Amazon Linux:2023"
    unknown = query("pkg:rpm/centos/curl@7.29.0-59.el7?distro=centos-7")
    assert unknown.ecosystems == () and "centos" in unknown.source


def test_needed_sources(examples, config):
    from vuln_triage.inventory import load_inventories
    from vuln_triage.sbom_builder import assign_purls
    envs = load_inventories(examples / "inventory", {})
    assign_purls(envs)
    sources, unsupported = needed_sources(envs, config)
    assert sources == ["Amazon Linux:2", "Maven", "PyPI", "Ubuntu", "Debian"]   # Debian は CVSS の点数用
    assert unsupported == {}


# ------------------------------------------------------------------ データベース

def osv_zip(path, records):
    with zipfile.ZipFile(path, "w") as archive:
        for record in records:
            archive.writestr(f"{record['id']}.json", json.dumps(record))
    return path


RECORDS = [
    {"id": "GHSA-jfh8-c2jp-5v3q", "aliases": ["CVE-2021-44228"], "summary": "Log4Shell",
     "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
     "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "2.0-beta9"}, {"fixed": "2.15.0"}]}]},
                  {"package": {"ecosystem": "Maven", "name": "org.example:other"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]},
    {"id": "GHSA-old", "withdrawn": "2024-01-01T00:00:00Z",
     "affected": [{"package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                   "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]}]},
    {"id": "RUSTSEC-2026-0001", "affected": [{"package": {"ecosystem": "crates.io", "name": "oldcrate"},
                                              "database_specific": {"informational": "unmaintained"},
                                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]}]},
    {"id": "GHSA-crate", "aliases": ["CVE-2026-0002"], "affected": [{
        "package": {"ecosystem": "crates.io", "name": "oldcrate"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]},
]

UPDATEINFO = b"""<?xml version="1.0"?><updates>
<update type="security"><id>ALAS2-2024-0001</id><title>openssl update</title><issued date="2024-01-01 00:00:00"/>
<severity>important</severity><references><reference type="cve" id="CVE-2024-0727"/></references>
<pkglist><collection><package name="openssl-libs" version="1.0.2k" release="24.amzn2.0.10" epoch="1" arch="x86_64"/>
<package name="openssl-libs" version="1.0.2k" release="24.amzn2.0.10" epoch="1" arch="aarch64"/>
<package name="openssl" version="1.0.2k" release="24.amzn2.0.10" epoch="1" arch="src"/></collection></pkglist></update>
</updates>"""


def test_index_and_lookup(tmp_path):
    db = VulnDB(tmp_path / "db")
    assert not db.exists()
    assert db.import_zip("Maven", osv_zip(tmp_path / "m.zip", RECORDS)) == 3      # 取り下げ済みは除く
    records = list(db.lookup(("Maven",), ("org.apache.logging.log4j:log4j-core",)))
    assert [r["id"] for _, r in records] == ["GHSA-jfh8-c2jp-5v3q"]
    assert db.scores(["cve-2021-44228"]) == {"ghsa": 10.0}
    assert set(db.sources()) == {"Maven"}
    db.close()


def test_amazon_records():
    record = list(VulnDB.amazon_records(UPDATEINFO, "2"))[0]
    assert record["id"] == "ALAS2-2024-0001" and record["aliases"] == ["CVE-2024-0727"]
    assert record["database_specific"]["severity"] == "important"
    assert record["affected"] == [{"package": {"ecosystem": "Amazon Linux:2", "name": "openssl-libs"},
                                   "ranges": [{"type": "ECOSYSTEM",
                                               "events": [{"introduced": "0"}, {"fixed": "1:1.0.2k-24.amzn2.0.10"}]}]}]


def test_update_downloads_osv_and_amazon_with_mirror_fallback(tmp_path):
    maven = osv_zip(tmp_path / "m.zip", RECORDS).read_bytes()
    calls = []

    def fetch(url):
        calls.append(url)
        if url.endswith("/Maven/all.zip"):
            return maven
        if url.endswith("mirror.list"):
            return b"https://cdn.example.invalid/2/core/x86_64/abc/\n"
        if url.startswith("https://cdn.example.invalid/"):
            raise OSError("blocked")
        if url.endswith("repomd.xml"):
            return b'<repomd><data type="updateinfo"><location href="repodata/updateinfo.xml.gz"/></data></repomd>'
        if url.endswith("updateinfo.xml.gz"):
            return gzip.compress(UPDATEINFO)
        raise OSError(f"unexpected {url}")

    config = {"vulndb": {"osv_url": "https://osv.example.invalid",
                         "amazon_mirrors": {"2": "http://mirror.example.invalid/2/core/latest/x86_64/mirror.list"}}}
    db = VulnDB(tmp_path / "db", config, fetch=fetch)
    assert db.update(["Maven", "Amazon Linux:2", "Nope"]) == {"Nope": "unexpected https://osv.example.invalid/Nope/all.zip"}
    assert "http://mirror.example.invalid/2/core/x86_64/abc/repodata/repomd.xml" in calls   # CDN に届かず同じホストへ
    assert set(db.sources()) == {"Maven", "Amazon Linux:2"}
    assert [r["id"] for _, r in db.lookup(("Amazon Linux:2",), ("openssl-libs",))] == ["ALAS2-2024-0001"]


def test_scan_with_vulndb(tmp_path, config):
    db = VulnDB(tmp_path / "db")
    db.import_zip("Maven", osv_zip(tmp_path / "m.zip", RECORDS))
    db.import_zip("crates.io", osv_zip(tmp_path / "c.zip", RECORDS))
    db.connect().execute("UPDATE sources SET updated_at = ?", (
        (datetime.now(timezone.utc) - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%SZ"),))
    db.connect().commit()
    jar = Component(name="log4j-core", version="2.14.1", kind=KIND_MAVEN, purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    path="/opt/log4j.jar", scannable=True)
    other = Component(name="other", version="9.9", purl="pkg:maven/org.example/other@9.9", scannable=True)
    # 同じ記録の別パッケージ（other）の範囲を、修正済みの log4j-core に当てはめないこと
    fixed_jar = Component(name="log4j-core", version="2.16.0", kind=KIND_MAVEN, path="/opt/new/log4j.jar",
                          purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0", scannable=True)
    crate = Component(name="oldcrate", version="1.0.0", purl="pkg:cargo/oldcrate@1.0.0", scannable=True)
    deb = Component(name="openssl", version="3.0.2-0ubuntu1", purl="pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?distro=ubuntu-22.04",
                    scannable=True)
    env = make_env(components=[jar, fixed_jar, other, crate, deb])
    findings = scan_with_vulndb([env], db, config)
    assert sorted((f.pkg_name, f.installed_version, f.cve_id) for f in findings) == [
        ("oldcrate", "1.0.0", "CVE-2026-0002"),                     # 参考情報（保守終了）は除く
        ("org.apache.logging.log4j:log4j-core", "2.14.1", "CVE-2021-44228"),
        ("org.example:other", "9.9", "CVE-2021-44228")]
    log4shell = next(f for f in findings if f.cve_id == "CVE-2021-44228")
    assert (log4shell.cvss, log4shell.fixed_version, log4shell.path, log4shell.sbom) == (10.0, "2.15.0", "/opt/log4j.jar", "Maven")
    assert "GHSA-JFH8-C2JP-5V3Q" in log4shell.all_ids
    assert jar.checked and other.checked and not deb.checked
    assert env.missing_db == {"Ubuntu": 1}
    assert any("Ubuntu の脆弱性データが無い" in w for w in env.warnings)
    assert stale_sources(db, config) == ["Maven（30 日前）", "crates.io（30 日前）"]


def test_example_database(examples, config):
    db = VulnDB(examples / "vulndb", config)
    env = load_env_dir(examples / "inventory" / "batch-emr")
    findings = scan_with_vulndb([env], db, config)
    amazon = [f for f in findings if f.sbom == "Amazon Linux:2"]
    assert amazon and {f.pkg_name for f in amazon} >= {"openssl-libs", "python3"}
    assert any(f.cvss is not None for f in amazon)          # Debian のデータから点数を引ける
    assert not any(f.pkg_name.startswith("log4j-core") for f in findings)   # 2.17.1 は修正済み


def test_db_update_cli(tmp_path, monkeypatch, examples):
    archive = osv_zip(tmp_path / "m.zip", RECORDS)
    runner = CliRunner()
    assert runner.invoke(main, ["db-update", "--db-dir", str(tmp_path / "empty")]).exit_code == 2   # 初回は対象の指定が必要
    result = runner.invoke(main, ["db-update", "--db-dir", str(tmp_path / "db"), "--import", f"Maven={archive}"])
    assert result.exit_code == 0, result.output
    result = runner.invoke(main, ["db-update", "--db-dir", str(tmp_path / "db"), "--list"])
    assert "Maven: 3 件" in result.output

    requested = []

    def fake_fetch(url):
        requested.append(url)
        raise OSError("offline")

    monkeypatch.setattr(store_module, "_fetch", fake_fetch)
    # 引数なし = 取得済みのデータ（Maven）をすべて更新する。失敗しても前の内容は残る
    result = runner.invoke(main, ["db-update", "--db-dir", str(tmp_path / "db")])
    assert result.exit_code == 1 and "前回の内容のまま" in result.output
    assert any(url.endswith("/Maven/all.zip") for url in requested)
    assert "Maven: 3 件" in runner.invoke(main, ["db-update", "--db-dir", str(tmp_path / "db"), "--list"]).output

    requested.clear()
    result = runner.invoke(main, ["db-update", "--db-dir", str(tmp_path / "db2"), "--inventory-dir",
                                  str(examples / "inventory")])
    assert result.exit_code == 1
    assert "Amazon Linux:2、Maven、PyPI、Ubuntu、Debian" in result.output
    assert any("/Maven/all.zip" in url for url in requested)


# ------------------------------------------------------------------ 毎日の差分更新

def test_parse_modified_ids():
    text = ("2026-11-19T21:00:04.802632106Z,GHSA-b\n"
            "2026-11-19T21:00:04.08692612Z,GHSA-a\n"     # 小数部の桁数が違っても正しく比べる
            "2026-11-18T00:00:00Z,GHSA-old\n"
            "2026-11-19T21:00:04.9Z,\n")
    assert parse_modified_ids(text, None) == ("2026-11-19T21:00:04.9Z", ["GHSA-b", "GHSA-a", "GHSA-old"])
    assert parse_modified_ids(text, "2026-11-19T21:00:04.1Z")[1] == ["GHSA-b"]
    assert parse_modified_ids(text, "2026-11-19T21:00:04.9Z")[1] == []


class FakeOSV:
    """OSV.dev の公開データの偽物。all.zip、modified_id.csv、記録単体の JSON を返す。"""

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.records = {}          # id -> (更新日時, 記録)
        self.calls = []
        self.fail = set()

    def put(self, stamp, record):
        self.records[record["id"]] = (stamp, record)

    def __call__(self, url):
        self.calls.append(url)
        name = url.rsplit("/", 1)[-1]
        if name in self.fail:
            raise OSError(f"failed {name}")
        if name == "all.zip":
            return osv_zip(self.tmp_path / "all.zip", [r for _, r in self.records.values()]).read_bytes()
        if name == "modified_id.csv":
            rows = sorted(self.records.values(), key=lambda item: item[0], reverse=True)
            return "".join(f"{stamp},{record['id']}\n" for stamp, record in rows).encode()
        record_id = name[:-len(".json")]
        return json.dumps(self.records[record_id][1]).encode()


def maven_record(record_id, artifact, fixed):
    return {"id": record_id, "aliases": [f"CVE-{record_id[-4:]}"], "affected": [{
        "package": {"ecosystem": "Maven", "name": f"g:{artifact}"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}]}]}


def ids_for(db, artifact):
    return sorted(r["id"] for _, r in db.lookup(("Maven",), (f"g:{artifact}",)))


def test_incremental_update(tmp_path):
    osv = FakeOSV(tmp_path)
    osv.put("2026-11-01T00:00:00Z", maven_record("GHSA-0001", "a", "1.0"))
    osv.put("2026-11-01T00:00:00Z", maven_record("GHSA-0002", "b", "1.0"))
    osv.put("2026-11-01T00:00:00Z", maven_record("GHSA-0003", "c", "1.0"))
    db = VulnDB(tmp_path / "db", {"vulndb": {"osv_url": "https://osv.invalid"}}, fetch=osv)

    assert db.update_osv("Maven") == "全件 3 件"
    info = db.sources()["Maven"]
    assert info["cursor"] == "2026-11-01T00:00:00Z" and info["full_at"]

    # 翌日: 追加 1、変更 1（修正版が変わる）、取り下げ 1
    osv.put("2026-11-02T00:00:00Z", maven_record("GHSA-0004", "d", "2.0"))
    osv.put("2026-11-02T00:00:00Z", maven_record("GHSA-0001", "a", "3.0"))
    osv.put("2026-11-02T00:00:00Z", {**maven_record("GHSA-0002", "b", "1.0"), "withdrawn": "2026-11-02T00:00:00Z"})
    osv.calls.clear()
    assert db.update_osv("Maven") == "差分 3 件"
    assert not any(url.endswith("all.zip") for url in osv.calls)
    assert ids_for(db, "d") == ["GHSA-0004"]
    assert ids_for(db, "b") == []
    changed = next(r for _, r in db.lookup(("Maven",), ("g:a",)))
    assert changed["affected"][0]["ranges"][0]["events"][1] == {"fixed": "3.0"}
    assert db.connect().execute("SELECT count(*) FROM entries WHERE file = ?", (DELTA_FILE,)).fetchone()[0] == 2
    assert db.sources()["Maven"]["cursor"] == "2026-11-02T00:00:00Z"

    # 変更が無ければ何も取らない
    osv.calls.clear()
    assert db.update_osv("Maven") == "変更なし"
    assert [url.rsplit("/", 1)[-1] for url in osv.calls] == ["modified_id.csv"]

    # 全件を取り直すと、差分で取っていた記録は zip の内容に置き換わる
    assert db.update_osv("Maven", force_full=True).startswith("全件")
    assert db.connect().execute("SELECT count(*) FROM entries WHERE file = ?", (DELTA_FILE,)).fetchone()[0] == 0
    assert db.connect().execute("SELECT count(*) FROM records").fetchone()[0] == 0
    assert ids_for(db, "a") == ["GHSA-0001"] and ids_for(db, "b") == [] and ids_for(db, "d") == ["GHSA-0004"]
    db.close()


def test_incremental_failure_keeps_previous_state(tmp_path):
    osv = FakeOSV(tmp_path)
    osv.put("2026-11-01T00:00:00Z", maven_record("GHSA-0001", "a", "1.0"))
    db = VulnDB(tmp_path / "db", {"vulndb": {"osv_url": "https://osv.invalid"}}, fetch=osv)
    db.update_osv("Maven")
    osv.put("2026-11-02T00:00:00Z", maven_record("GHSA-0005", "e", "1.0"))
    osv.put("2026-11-02T00:00:01Z", maven_record("GHSA-0006", "f", "1.0"))
    osv.fail.add("GHSA-0006.json")
    assert set(db.update(["Maven"])) == {"Maven"}
    assert ids_for(db, "e") == []                                  # 途中までの分も反映しない
    assert db.sources()["Maven"]["cursor"] == "2026-11-01T00:00:00Z"
    osv.fail.clear()
    assert db.update_osv("Maven") == "差分 2 件"                    # 次回は取り直せる
    assert ids_for(db, "e") == ["GHSA-0005"] and ids_for(db, "f") == ["GHSA-0006"]


def test_switches_to_full_download(tmp_path):
    osv = FakeOSV(tmp_path)
    osv.put("2026-11-01T00:00:00Z", maven_record("GHSA-0001", "a", "1.0"))
    config = {"vulndb": {"osv_url": "https://osv.invalid", "max_delta_records": 2, "full_refresh_days": 7}}
    db = VulnDB(tmp_path / "db", config, fetch=osv)
    db.update_osv("Maven")
    for number in range(3):                                         # 上限（2 件）を超える変更
        osv.put("2026-11-02T00:00:00Z", maven_record(f"GHSA-100{number}", "x", "1.0"))
    assert db.update_osv("Maven") == "全件 4 件"
    # 最後の全件取得から日数が経っていれば全件
    db.connect().execute("UPDATE sources SET full_at = '2026-01-01T00:00:00Z'")
    osv.put("2026-11-03T00:00:00Z", maven_record("GHSA-2000", "y", "1.0"))
    assert db.update_osv("Maven") == "全件 5 件"
    # 手で取り込んだデータは差分の起点が無いので、次回は全件
    db.import_zip("Maven", osv_zip(tmp_path / "manual.zip", RECORDS))
    assert db.sources()["Maven"]["cursor"] is None
    assert db.update_osv("Maven").startswith("全件")


def test_amazon_skips_unchanged_updateinfo(tmp_path):
    calls = []
    checksum = ["aaa"]

    def fetch(url):
        calls.append(url)
        if url.endswith("mirror.list"):
            return b"http://repo.invalid/2/core/\n"
        if url.endswith("repomd.xml"):
            return (f'<repomd><data type="primary"><checksum type="sha256">fff</checksum>'
                    f'<location href="repodata/primary.xml.gz"/></data>'
                    f'<data type="updateinfo"><checksum type="sha256">{checksum[0]}</checksum>'
                    f'<location href="repodata/updateinfo.xml.gz"/></data></repomd>').encode()
        if url.endswith("updateinfo.xml.gz"):
            return gzip.compress(UPDATEINFO)
        raise OSError(url)

    db = VulnDB(tmp_path / "db", {"vulndb": {"amazon_mirrors": {"2": "http://repo.invalid/mirror.list"}}}, fetch=fetch)
    assert db.update_amazon("2") == "全件 1 件"
    assert db.sources()["Amazon Linux:2"]["checksum"] == "aaa"
    calls.clear()
    assert db.update_amazon("2") == "変更なし"
    assert not any(url.endswith("updateinfo.xml.gz") for url in calls)
    checksum[0] = "bbb"
    assert db.update_amazon("2") == "全件 1 件"


def test_old_database_is_migrated(tmp_path):
    import sqlite3
    path = tmp_path / "db"
    path.mkdir()
    conn = sqlite3.connect(path / "index.sqlite")
    conn.execute("CREATE TABLE sources (source TEXT PRIMARY KEY, file TEXT, url TEXT, updated_at TEXT, records INTEGER)")
    conn.execute("INSERT INTO sources VALUES ('Maven', 'osv/Maven.zip', 'u', '2026-11-01T00:00:00Z', 1)")
    conn.commit()
    conn.close()
    info = VulnDB(path).sources()["Maven"]
    assert info["records"] == 1 and info["cursor"] is None and info["checksum"] is None


def test_python_module_entry():
    import subprocess
    import sys
    result = subprocess.run([sys.executable, "-m", "vuln_triage", "--help"], capture_output=True, text=True)
    assert result.returncode == 0 and "db-update" in result.stdout
