import json

from zeijaku_kakunin.inventory import (
    detect_format,
    load_env_dir,
    load_inventories,
    load_server,
    normalize_kb,
)
from zeijaku_kakunin.purl import parse_purl
from zeijaku_kakunin.models import KIND_EXECUTABLE, KIND_MAVEN, KIND_OS_PACKAGE, KIND_PYPI, KIND_SOFTWARE


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
    assert "HULFT" not in by_name                   # 個別製品の表の結果（古い回収物）は使わない
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
    assert env.incomplete                             # completed が無い = 途中で中断


def test_linux_osinfo_with_emr(examples):
    env = load_env_dir(examples / "inventory" / "batch-emr")
    assert env.emr_release == "emr-6.15.0"
    names = {c.name for c in env.components}
    assert "amazon-emr" not in names and "DataMagic" not in names   # 製品名で照合しないので部品にしない


def test_load_server_and_inventories(examples, tmp_path):
    """1 台のフォルダはそのまま読む。複数台を並べたフォルダを zk check に渡したら、1 台ずつ指定するよう案内する。"""
    import pytest

    env = load_server(examples / "inventory" / "web-ec2")
    assert env.name == "web-ec2" and env.components
    with pytest.raises(ValueError, match="1 台ずつ"):
        load_server(examples / "inventory")
    (tmp_path / "empty").mkdir()
    with pytest.raises(ValueError, match="回収ファイル"):
        load_server(tmp_path / "empty")
    # zk update などは、1 台のフォルダでも複数台を並べたフォルダでも読める
    assert [e.name for e in load_inventories(examples / "inventory" / "web-ec2")] == ["web-ec2"]
    assert len(load_inventories(examples / "inventory")) == 4


def test_plain_syft_sbom_without_os_info(examples, tmp_path, config):
    """collect_linux.sh を使わず、素の syft の出力（cdx_syft.json）だけを置いた環境も同じように照合できる。"""
    from zeijaku_kakunin.vulndb.scanner import scan_with_vulndb
    from zeijaku_kakunin.vulndb.store import VulnDB

    data = json.loads((examples / "inventory" / "web-ec2" / "cdx_syft.json").read_text(encoding="utf-8"))
    data["metadata"]["timestamp"] = "2026-11-20T01:02:03Z"
    write(tmp_path / "plain" / "sbom.json", data)
    plain = load_env_dir(tmp_path / "plain")
    full = load_env_dir(examples / "inventory" / "web-ec2")
    assert (plain.os_family, plain.os_id, plain.os_version_id) == ("linux", "ubuntu", "22.04")
    assert plain.full_collection and not plain.incomplete
    assert plain.collected_at == "2026-11-20T01:02:03Z"

    db = VulnDB(examples / "vulndb", config)
    keys = lambda env: {(f.cve_id, f.pkg_name, f.installed_version) for f in scan_with_vulndb([env], db, config)}
    try:
        assert keys(plain) == keys(full) and keys(plain)
    finally:
        db.close()


def test_elf_package_notes_duplicating_rpm_db_are_not_scanned(tmp_path):
    """syft が実行ファイルの ELF のパッケージ情報から作る rpm（エポック無し）は、rpm のデータベースに同じものが
    あれば照合しない（Amazon Linux 2023 の実機で openssl の誤検出 92 件）。"""
    note = {"name": "syft:package:foundBy", "value": "elf-binary-package-cataloger"}
    db = {"name": "syft:package:foundBy", "value": "rpm-db-cataloger"}
    write(tmp_path / "e" / "sbom.json", {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "library", "name": "openssl-libs", "version": "1:3.5.8-1.amzn2023.0.4", "properties": [db],
         "purl": "pkg:rpm/amzn/openssl-libs@3.5.8-1.amzn2023.0.4?distro=amzn-2023&epoch=1"
                 "&upstream=openssl-3.5.8-1.amzn2023.0.4.src.rpm"},
        {"type": "library", "name": "tar", "version": "2:1.34-1.amzn2023.0.4", "properties": [db],
         "purl": "pkg:rpm/amzn/tar@1.34-1.amzn2023.0.4?distro=amzn-2023&epoch=2"},
        {"type": "library", "name": "openssl", "version": "3.5.8-1.amzn2023.0.4", "properties": [note],
         "purl": "pkg:rpm/amazon_linux/openssl@3.5.8-1.amzn2023.0.4?distro=amazon_linux-2023"},
        {"type": "library", "name": "tar", "version": "1.34-1.amzn2023.0.4", "properties": [note],
         "purl": "pkg:rpm/amazon_linux/tar@1.34-1.amzn2023.0.4?distro=amazon_linux-2023"},
        {"type": "library", "name": "mytool", "version": "1.0-1.amzn2023", "properties": [note],
         "purl": "pkg:rpm/amazon_linux/mytool@1.0-1.amzn2023?distro=amazon_linux-2023"},
    ]})
    env = load_env_dir(tmp_path / "e")
    scannable = {(c.name, c.found_by.split("-")[0]) for c in env.components if c.scannable}
    assert scannable == {("openssl-libs", "rpm"), ("tar", "rpm"), ("mytool", "elf")}   # rpm DB に無いものは残す


def test_osinfo_warns_when_syft_checksum_was_not_verified(examples, tmp_path):
    base = json.loads((examples / "inventory" / "batch-emr" / "os_info.json").read_text(encoding="utf-8"))
    for checksum, warned in (("ok", False), ("unverified", True), (None, False)):   # None = 古い回収スクリプト
        data = json.loads(json.dumps(base))
        data["syft"]["status"] = "ok"
        if checksum is None:
            data["syft"].pop("checksum", None)
        else:
            data["syft"]["checksum"] = checksum
        write(tmp_path / checksum.__str__() / "os_info.json", data)
        env = load_env_dir(tmp_path / checksum.__str__())
        assert any("チェックサム" in w for w in env.warnings) == warned, (checksum, env.warnings)
