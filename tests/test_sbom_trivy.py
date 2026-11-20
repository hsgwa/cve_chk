import json
import subprocess

import pytest

from vuln_triage import trivy_runner
from vuln_triage.inventory import load_env_dir
from vuln_triage.models import KIND_MAVEN, KIND_NPM, KIND_NUGET, KIND_PYPI, KIND_SOFTWARE, Component
from vuln_triage.sbom_builder import build_sbom, make_purl, write_sboms
from vuln_triage.trivy_runner import (
    TrivyNotFoundError,
    find_trivy,
    parse_results,
    pick_cvss,
    result_file_name,
    scan_environments,
)

from conftest import make_env


def test_make_purl():
    assert make_purl(Component("log4j-core", "2.14.1", KIND_MAVEN, group="org.apache.logging.log4j")) == \
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    assert make_purl(Component("legacy", "1.0", KIND_MAVEN)) == ""            # groupId 不明は作れない
    assert make_purl(Component("Flask_Login", "0.6.3", KIND_PYPI)) == "pkg:pypi/flask-login@0.6.3"
    assert make_purl(Component("@scope/pkg", "1.0.0", KIND_NPM)) == "pkg:npm/%40scope/pkg@1.0.0"
    assert make_purl(Component("Newtonsoft.Json", "12.0.1", KIND_NUGET)) == "pkg:nuget/Newtonsoft.Json@12.0.1"
    assert make_purl(Component("HULFT8", "8.5.3", KIND_SOFTWARE)) == ""
    assert make_purl(Component("requests", "", KIND_PYPI)) == ""


def test_build_sbom_from_windows_inventory(examples, tmp_path):
    env = load_env_dir(examples / "inventory" / "win-app01")
    written = write_sboms([env], tmp_path)
    assert [p.name for p in written] == ["generated_win-app01.cdx.json"]
    sbom = json.loads(written[0].read_text(encoding="utf-8"))
    assert sbom["bomFormat"] == "CycloneDX" and sbom["specVersion"] == "1.5"
    purls = {c["purl"] for c in sbom["components"]}
    assert purls == {"pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:pypi/requests@2.25.0"}
    log4j = next(c for c in sbom["components"] if c["name"] == "log4j-core")
    assert log4j["properties"][0]["value"].endswith("log4j-core-2.14.1.jar")
    assert env.sbom_files == written
    assert next(c for c in env.components if c.name == "requests").scannable


def test_build_sbom_skips_existing_cyclonedx(examples):
    env = load_env_dir(examples / "inventory" / "web-ec2")
    assert build_sbom(env) is None          # syft の SBOM は作り直さない


def test_trivy_not_found(monkeypatch, config):
    monkeypatch.setattr(trivy_runner.shutil, "which", lambda name: None)
    with pytest.raises(TrivyNotFoundError) as error:
        find_trivy(config)
    assert "--scanner osv" in str(error.value) and "trivy.exe" in str(error.value)
    config["trivy"]["path"] = "C:/nowhere/trivy.exe"
    with pytest.raises(TrivyNotFoundError):
        find_trivy(config)


def test_pick_cvss():
    cvss = {"nvd": {"V3Score": 7.5}, "ghsa": {"V3Score": 9.1}, "redhat": {"V2Score": 5.0}}
    assert pick_cvss(cvss, ["nvd"]) == 7.5
    assert pick_cvss(cvss, ["ghsa", "nvd"]) == 9.1
    assert pick_cvss({"ghsa": {"V3Score": 9.1}, "redhat": {"V3Score": 8.0}}, ["nvd"]) == 9.1
    assert pick_cvss({}, ["nvd"]) is None and pick_cvss(None, ["nvd"]) is None


def test_parse_results_resolves_path(tmp_path, config):
    sbom = tmp_path / "x.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [
        {"bom-ref": "ref-1", "name": "log4j-core", "purl": "pkg:maven/g/log4j-core@2.14.1",
         "properties": [{"name": "vuln-triage:path", "value": "D:\\app\\log4j-core-2.14.1.jar"}]}]}), encoding="utf-8")
    data = {"Results": [{"Vulnerabilities": [
        {"VulnerabilityID": "cve-2021-44228", "PkgName": "g:log4j-core", "InstalledVersion": "2.14.1",
         "FixedVersion": "2.15.0", "PkgIdentifier": {"BOMRef": "ref-1"}, "CVSS": {"nvd": {"V3Score": 10.0}}},
        {"VulnerabilityID": "CVE-2000-0001", "PkgName": "other", "PkgPath": "/opt/other.jar"}]},
        {"Target": "empty"}]}
    findings = parse_results(data, "env1", sbom, config)
    assert findings[0].cve_id == "CVE-2021-44228" and findings[0].cvss == 10.0
    assert findings[0].path == "D:\\app\\log4j-core-2.14.1.jar"
    assert findings[1].path == "/opt/other.jar" and findings[1].cvss is None


def test_scan_with_saved_results(examples, config, tmp_path):
    env = load_env_dir(examples / "inventory" / "web-ec2")
    other = make_env("no-result")
    other.sbom_files = [tmp_path / "missing.cdx.json"]
    findings = scan_environments([env, other], config, results_dir=examples / "trivy_fixtures")
    assert any(f.cve_id == "CVE-2021-44228" and f.path == "/opt/app/lib/log4j-core-2.14.1.jar" for f in findings)
    assert env.cve_coverage and not other.cve_coverage
    assert all(c.checked for c in env.components if c.sbom_file == "cdx_syft.json")
    assert any("保存済みの Trivy 結果" in w for w in other.warnings)


def test_scan_runs_trivy_and_saves(monkeypatch, config, tmp_path):
    sbom = tmp_path / "bom.cdx.json"
    sbom.write_text('{"bomFormat": "CycloneDX", "components": []}', encoding="utf-8")
    env = make_env("e1")
    env.sbom_files = [sbom]
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        output = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2024-0001", "PkgName": "p"}]}]}
        return subprocess.CompletedProcess(command, 0, json.dumps(output).encode(), b"")

    monkeypatch.setattr(trivy_runner.shutil, "which", lambda name: "/usr/bin/trivy")
    monkeypatch.setattr(trivy_runner.subprocess, "run", fake_run)
    findings = scan_environments([env], config, save_dir=tmp_path / "saved")
    assert calls[0][:5] == ["/usr/bin/trivy", "sbom", "--format", "json", "--quiet"]
    assert [f.cve_id for f in findings] == ["CVE-2024-0001"]
    assert (tmp_path / "saved" / result_file_name("e1", sbom)).is_file()


def test_trivy_failure_becomes_warning(monkeypatch, config, tmp_path):
    env = make_env("e1")
    env.sbom_files = [tmp_path / "bom.cdx.json"]
    monkeypatch.setattr(trivy_runner.shutil, "which", lambda name: "/usr/bin/trivy")
    monkeypatch.setattr(trivy_runner.subprocess, "run",
                        lambda command, **kw: subprocess.CompletedProcess(command, 1, b"", b"FATAL db error"))
    assert scan_environments([env], config) == []
    assert not env.cve_coverage and any("db error" in w for w in env.warnings)


def test_same_package_in_two_places_gives_two_findings(tmp_path, config):
    purl = "pkg:maven/g/log4j-core@2.14.1"
    sbom = tmp_path / "x.cdx.json"
    sbom.write_text(json.dumps({"bomFormat": "CycloneDX", "components": [
        {"bom-ref": f"{purl}#0", "name": "log4j-core", "purl": purl,
         "properties": [{"name": "vuln-triage:path", "value": "D:\\a\\app.war!/WEB-INF/lib/log4j-core-2.14.1.jar"}]},
        {"bom-ref": f"{purl}#1", "name": "log4j-core", "purl": purl,
         "properties": [{"name": "vuln-triage:path", "value": "D:\\a\\lib\\log4j-core-2.14.1.jar"}]}]}), encoding="utf-8")
    # Trivy は同じ PURL を1件にまとめて報告する
    data = {"Results": [{"Vulnerabilities": [{"VulnerabilityID": "CVE-2021-44228", "PkgName": "g:log4j-core",
                                              "InstalledVersion": "2.14.1",
                                              "PkgIdentifier": {"PURL": purl, "BOMRef": f"{purl}#1"}}]}]}
    findings = parse_results(data, "env1", sbom, config)
    assert sorted(f.path for f in findings) == [
        "D:\\a\\app.war!/WEB-INF/lib/log4j-core-2.14.1.jar", "D:\\a\\lib\\log4j-core-2.14.1.jar"]
