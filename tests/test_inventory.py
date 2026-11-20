import json

from vuln_triage.inventory import (
    detect_format,
    load_env_dir,
    load_env_master,
    load_inventories,
    normalize_kb,
)
from vuln_triage.purl import parse_purl
from vuln_triage.models import KIND_CUSTOM, KIND_EXECUTABLE, KIND_MAVEN, KIND_OS_PACKAGE, KIND_PYPI, KIND_SOFTWARE


def write(path, data, encoding="utf-8"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False), encoding=encoding)


def test_detect_format():
    assert detect_format({"bomFormat": "CycloneDX"}) == "cyclonedx"
    assert detect_format({"Sources": []}) == "winget"
    assert detect_format([{"HotFixID": "KB1234567"}]) == "hotfix"
    assert detect_format({"HotFixID": "KB1234567"}) == "hotfix"        # 1件だと配列にならない
    assert detect_format([{"ProductName": "x", "ProductVersion": "1"}]) == "versioninfo"
    assert detect_format({"schema": "vuln-triage-inventory/1"}) == "inventory"
    assert detect_format({"schema": "vuln-triage-osinfo/1"}) == "osinfo"
    assert detect_format({"foo": 1}) == "unknown"
    assert detect_format([1, 2]) == "unknown"


def test_parse_purl():
    parsed = parse_purl("pkg:maven/org.apache/commons-text@1.9")
    assert (parsed.type, parsed.namespace, parsed.name, parsed.version) == ("maven", "org.apache", "commons-text", "1.9")
    assert parsed.full_name == "org.apache:commons-text"
    deb = parse_purl("pkg:deb/ubuntu/openssl@3.0.2-0ubuntu1?arch=amd64")
    assert (deb.name, deb.version, deb.qualifiers) == ("openssl", "3.0.2-0ubuntu1", {"arch": "amd64"})
    assert parse_purl("pkg:npm/%40scope/pkg@1.0.0").full_name == "@scope/pkg"
    assert parse_purl("pkg:golang/github.com/cli/cli@v2.89.0#v2").full_name == "github.com/cli/cli/v2"
    assert parse_purl("not a purl").type == ""


def test_normalize_kb():
    assert normalize_kb("kb5034441") == "KB5034441"
    assert normalize_kb("5034441") == "KB5034441"
    assert normalize_kb("なし") is None


def test_cyclonedx_14_and_15(tmp_path):
    for spec in ("1.4", "1.5"):
        write(tmp_path / f"e{spec}" / "bom.json", {
            "bomFormat": "CycloneDX", "specVersion": spec,
            "metadata": {"component": {"type": "operating-system", "name": "amzn", "version": "2"}},
            "components": [
                {"type": "library", "name": "log4j-core", "version": "2.14.1", "group": "org.apache.logging.log4j",
                 "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                 "properties": [{"name": "syft:location:0:path", "value": "/opt/app/log4j-core-2.14.1.jar"}],
                 "components": [{"type": "library", "name": "nested", "version": "1.0"}]},
                {"type": "library", "name": "openssl", "version": "1.0.2k", "purl": "pkg:rpm/amzn/openssl@1.0.2k"},
                {"type": "file", "name": "/etc/hosts"},
            ]})
        env = load_env_dir(tmp_path / f"e{spec}")
        names = {c.name: c for c in env.components}
        assert set(names) == {"log4j-core", "nested", "openssl"}
        assert names["log4j-core"].kind == KIND_MAVEN
        assert names["log4j-core"].path == "/opt/app/log4j-core-2.14.1.jar"
        assert names["openssl"].kind == KIND_OS_PACKAGE
        assert env.os_family == "linux" and env.os_name == "amzn 2"
        assert len(env.sbom_files) == 1 and env.full_collection


def test_inspector_style_location_property(tmp_path):
    write(tmp_path / "e" / "bom.json", {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [
        {"type": "library", "name": "requests", "version": "2.25.0", "purl": "pkg:pypi/requests@2.25.0",
         "properties": [{"name": "amazon:inspector:sbom_scanner:path", "value": "/var/task/requests"}]}]})
    env = load_env_dir(tmp_path / "e")
    assert env.components[0].kind == KIND_PYPI
    assert env.components[0].path == "/var/task/requests"


def test_windows_standalone_files_utf16(tmp_path):
    env_dir = tmp_path / "win"
    write(env_dir / "hotfix.json", [{"HotFixID": "KB5034441"}, {"HotFixID": "kb5034127"}], encoding="utf-16")
    write(env_dir / "winget.json", {"Sources": [{"Packages": [
        {"PackageIdentifier": "Oracle.JavaRuntimeEnvironment", "Version": "8.0.3910.13"}]}]})
    write(env_dir / "vi.json", {"ProductName": "Node.js", "FileName": "C:\\node\\node.exe", "ProductVersion": "18.19.0"})
    (env_dir / "broken.json").write_text("{not json", encoding="utf-8")
    write(env_dir / "other.json", {"hello": "world"})
    env = load_env_dir(env_dir)
    assert env.hotfixes == {"KB5034441", "KB5034127"}
    kinds = {c.name: c.kind for c in env.components}
    assert kinds == {"Oracle.JavaRuntimeEnvironment": KIND_SOFTWARE, "Node.js": KIND_EXECUTABLE}
    assert env.os_family == "windows"
    assert not env.full_collection
    assert any("broken.json" in w for w in env.warnings) and any("other.json" in w for w in env.warnings)


def test_example_windows_inventory(examples):
    env = load_env_dir(examples / "inventory" / "win-app01")
    assert env.os_family == "windows" and env.os_build == "10.0.17763.5329"
    assert env.hotfixes == {"KB5034127", "KB5033371"}
    by_name = {c.name: c for c in env.components}
    assert by_name["log4j-core"].group == "org.apache.logging.log4j"
    assert by_name["HULFT8 for Windows"].version == "8.5.3"
    assert by_name["OpenJDK Platform 8"].kind == KIND_EXECUTABLE
    assert by_name["HULFT"].kind == KIND_CUSTOM
    assert env.out_of_scope_running == ["E:\\tools\\agent\\agent.exe"]   # スキャン範囲外で動作中
    assert env.unreadable and not env.incomplete


def test_failed_sections_and_incomplete(tmp_path):
    write(tmp_path / "w" / "inventory.json", {
        "schema": "vuln-triage-inventory/1", "os": {"family": "windows", "build": ""},
        "sections": {
            "hotfixes": {"status": "failed", "reason": "アクセス拒否", "items": []},
            "custom_products": {"status": "ok", "items": [
                {"name": "HULFT", "status": "error", "reason": "権限不足"},
                {"name": "DataMagic", "status": "not_found"}]},
        }})
    env = load_env_dir(tmp_path / "w")
    assert env.hotfixes is None                       # 失敗した KB 情報は「回収なし」
    assert env.sections["hotfixes"].status == "failed"
    assert [p.name for p in env.failed_probes] == ["HULFT"]
    assert env.incomplete                             # completed が無い = 途中で中断


def test_linux_osinfo_with_emr(examples):
    env = load_env_dir(examples / "inventory" / "batch-emr")
    assert env.emr_release == "emr-6.15.0"
    emr = next(c for c in env.components if c.name == "amazon-emr")
    assert emr.version == "6.15.0"
    datamagic = next(c for c in env.components if c.name == "DataMagic")
    assert datamagic.version == "" and datamagic.kind == KIND_CUSTOM


def test_env_master_and_unregistered(examples):
    master = load_env_master(examples / "env_master.csv")
    assert master["web-ec2"]["exposure"] == "internet"
    envs = {e.name: e for e in load_inventories(examples / "inventory", master)}
    assert envs["web-ec2"].exposure == "internet" and envs["web-ec2"].registered
    assert envs["win-legacy"].exposure == "internal" and not envs["win-legacy"].registered
