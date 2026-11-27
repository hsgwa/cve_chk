"""scan-file: zip / jar / war / ear / whl と展開したフォルダの中のライブラリを調べる。"""
import csv
import hashlib
import io
import json
import zipfile

from click.testing import CliRunner

from zeijaku_kakunin.archive_scan import scan
from zeijaku_kakunin.cli import main
from zeijaku_kakunin.inventory import load_env_dir


def zip_bytes(files: dict) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in files.items():
            archive.writestr(name, data if isinstance(data, bytes) else data.encode("utf-8"))
    return buffer.getvalue()


def jar(group, artifact, version) -> bytes:
    return zip_bytes({f"META-INF/maven/{group}/{artifact}/pom.properties":
                      f"groupId={group}\nartifactId={artifact}\nversion={version}\n",
                      "META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n"})


LOG4J = jar("org.apache.logging.log4j", "log4j-core", "2.14.1")


def metadata(name, version):
    return f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n\nbody"


def lambda_zip(tmp_path):
    """Python の Lambda（ライブラリを同梱）に、Java のライブラリも入れたもの。"""
    path = tmp_path / "my-function.zip"
    path.write_bytes(zip_bytes({
        "lambda_function.py": "def handler(event, context): pass",
        "requests-2.25.0.dist-info/METADATA": metadata("requests", "2.25.0"),
        "urllib3-1.26.4.dist-info/METADATA": metadata("urllib3", "1.26.4"),
        "lib/log4j-core-2.14.1.jar": LOG4J,
        "package.json": json.dumps({"name": "my-app", "version": "1.0.0"}),       # node_modules の外は数えない
        "node_modules/lodash/package.json": json.dumps({"name": "lodash", "version": "4.17.20"}),
        "node_modules/@scope/pkg/package.json": json.dumps({"name": "@scope/pkg", "version": "2.0.0"}),
        "broken.jar": b"not a zip",
    }))
    return path


def test_lambda_zip(tmp_path):
    result = scan([lambda_zip(tmp_path)])
    assert {(p["name"], p["version"]) for p in result.python} == {("requests", "2.25.0"), ("urllib3", "1.26.4")}
    assert [(j["group"], j["artifact"], j["version"]) for j in result.java] == [
        ("org.apache.logging.log4j", "log4j-core", "2.14.1")]
    assert result.java[0]["path"].endswith("my-function.zip!/lib/log4j-core-2.14.1.jar")
    assert {(n["name"], n["version"]) for n in result.node} == {("lodash", "4.17.20"), ("@scope/pkg", "2.0.0")}
    assert [s["path"].rsplit("!/", 1)[1] for s in result.skipped] == ["broken.jar"]


def test_fat_jar_war_ear_and_wheel(tmp_path):
    boot = tmp_path / "app.jar"
    boot.write_bytes(zip_bytes({"META-INF/maven/com.example/app/pom.properties": "groupId=com.example\nartifactId=app\nversion=1.0\n",
                                "BOOT-INF/lib/log4j-core-2.14.1.jar": LOG4J}))
    war = tmp_path / "web.war"
    war.write_bytes(zip_bytes({"WEB-INF/lib/commons-text-1.9.jar": jar("org.apache.commons", "commons-text", "1.9")}))
    ear = tmp_path / "suite.ear"
    ear.write_bytes(zip_bytes({"web.war": war.read_bytes()}))                    # ear の中の war の中の jar
    wheel = tmp_path / "PyYAML-5.3-cp38-cp38-linux_x86_64.whl"
    wheel.write_bytes(zip_bytes({"PyYAML-5.3.dist-info/METADATA": metadata("PyYAML", "5.3")}))
    result = scan([boot, war, ear, wheel])
    java = {(j["artifact"], j["version"], j["path"].replace(str(tmp_path), "")) for j in result.java}
    sep = str(tmp_path / "x")[len(str(tmp_path)):-1]
    assert ("app", "1.0", f"{sep}app.jar") in java
    assert ("log4j-core", "2.14.1", f"{sep}app.jar!/BOOT-INF/lib/log4j-core-2.14.1.jar") in java
    assert ("commons-text", "1.9", f"{sep}suite.ear!/web.war!/WEB-INF/lib/commons-text-1.9.jar") in java
    assert ("PyYAML", "5.3") in {(p["name"], p["version"]) for p in result.python}


def test_jar_without_pom_uses_manifest_or_file_name_and_keeps_sha1(tmp_path):
    manifest_jar = zip_bytes({"META-INF/MANIFEST.MF": "Implementation-Title: vendor-lib\nImplementation-Version: 3.2\n"})
    plain_jar = zip_bytes({"a/B.class": b"\xca\xfe"})
    path = tmp_path / "bundle.zip"
    path.write_bytes(zip_bytes({"lib/x.jar": manifest_jar, "lib/foo-utils-1.4.2.jar": plain_jar}))
    found = {(j["artifact"], j["version"], j["method"], j["sha1"]) for j in scan([path]).java}
    assert ("vendor-lib", "3.2", "manifest", hashlib.sha1(manifest_jar).hexdigest()) in found
    assert ("foo-utils", "1.4.2", "filename", hashlib.sha1(plain_jar).hexdigest()) in found


def test_dotnet_deps_and_extracted_folder(tmp_path):
    folder = tmp_path / "extracted"
    (folder / "python" / "lib" / "python3.12" / "site-packages" / "jinja2-2.11.2.dist-info").mkdir(parents=True)
    (folder / "python" / "lib" / "python3.12" / "site-packages" / "jinja2-2.11.2.dist-info" / "METADATA").write_text(
        metadata("Jinja2", "2.11.2"), encoding="utf-8")
    (folder / "lib").mkdir()
    (folder / "lib" / "log4j-core-2.14.1.jar").write_bytes(LOG4J)
    (folder / "App.deps.json").write_text(json.dumps({"libraries": {
        "Newtonsoft.Json/12.0.1": {"type": "package"}, "App/1.0.0": {"type": "project"}}}), encoding="utf-8")
    result = scan([folder])
    assert ("Jinja2", "2.11.2") in {(p["name"], p["version"]) for p in result.python}
    assert ("log4j-core", "2.14.1") in {(j["artifact"], j["version"]) for j in result.java}
    assert [(d["name"], d["version"]) for d in result.dotnet] == [("Newtonsoft.Json", "12.0.1")]


def test_scan_archive_command_and_matching(tmp_path, examples):
    """回収物として置き、run でほかの環境と同じように照合される。OS が無いので Windows の KB の通達は対象外。"""
    inventory = tmp_path / "inventory"
    zip_path = lambda_zip(tmp_path)
    layer = tmp_path / "layer.zip"
    layer.write_bytes(zip_bytes({"python/lib/python3.12/site-packages/urllib3-1.26.4.dist-info/METADATA":
                                 metadata("urllib3", "1.26.4")}))
    runner = CliRunner()
    result = runner.invoke(main, ["scan-file", str(zip_path), str(layer), "--inventory-dir", str(inventory),
                                  "--env", "lambda-my-function"])
    assert result.exit_code == 0, result.output
    assert "lambda-my-function: jar 等 1 件、Python 3 件" in result.output
    env = load_env_dir(inventory / "lambda-my-function")
    assert env.os_family == "archive" and env.full_collection and not env.incomplete
    assert env.sections["os"].status == "ok"

    advisory = tmp_path / "advisory.csv"
    advisory.write_text("通達番号,CVE番号,製品名,影響バージョン\nT-1,CVE-2021-44228,log4j-core,\nT-2,,KB5034441,missing\n",
                        encoding="utf-8")
    out = tmp_path / "out"
    result = runner.invoke(main, ["check", "--inventory-dir", str(inventory), "--advisory", str(advisory),
                                  "--db-dir", str(examples / "vulndb"), "--cache-dir", str(examples / "cache"),
                                  "--offline", "--base-date", "2026-11-20", "--out-dir", str(out), "--no-xlsx"])
    assert result.exit_code == 0, result.output
    with (out / "report_detail.csv").open(encoding="utf-8-sig", newline="") as handle:
        rows = {(r["社内通達ID"], r["影響有無"]) for r in csv.DictReader(handle)}
    assert rows == {("T-1", "影響あり"), ("T-2", "対象外")}

    # --env を付けなければ、ファイルごとに別の環境になる
    other = tmp_path / "inv2"
    result = runner.invoke(main, ["scan-file", str(zip_path), str(layer), "--inventory-dir", str(other)])
    assert result.exit_code == 0, result.output
    assert sorted(p.name for p in other.iterdir()) == ["layer", "my-function"]
