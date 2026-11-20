from vuln_triage.matching.names import build_matcher, normalize_name
from vuln_triage.models import KIND_EXECUTABLE, KIND_MAVEN, KIND_SOFTWARE, Component


def test_normalize_name():
    assert normalize_name(" Log4J_Core ") == "log4j-core"
    assert normalize_name("Ｈ Ｕ Ｌ Ｆ Ｔ") == "h-u-l-f-t"


def test_exact_match_ignores_case_and_separators():
    matcher = build_matcher("Log4j Core")
    assert matcher(Component(name="log4j-core"))
    assert not matcher(Component(name="log4j-core-extra"))


def test_group_and_artifact():
    jar = Component(name="log4j-core", group="org.apache.logging.log4j", kind=KIND_MAVEN)
    assert build_matcher("org.apache.logging.log4j:log4j-core")(jar)
    assert build_matcher("log4j-core")(jar)


def test_winget_id_and_executable_file_name():
    assert build_matcher("JavaRuntimeEnvironment")(
        Component(name="Oracle.JavaRuntimeEnvironment", kind=KIND_SOFTWARE))
    exe = Component(name="OpenJDK Platform 8", kind=KIND_EXECUTABLE, path="D:\\jdk\\bin\\java.exe")
    assert build_matcher("java")(exe)
    assert build_matcher("OpenJDK Platform 8")(exe)


def test_alias():
    aliases = {"HULFT": ["HULFT8 for Windows"]}
    assert build_matcher("HULFT", aliases)(Component(name="HULFT8 for Windows"))
    assert build_matcher("hulft8 for windows", aliases)(Component(name="HULFT"))
    assert not build_matcher("HULFT")(Component(name="HULFT8 for Windows"))


def test_wildcard_and_regex():
    assert build_matcher("Apache Tomcat*")(Component(name="Apache Tomcat 9.0 Tomcat9"))
    assert not build_matcher("Apache Tomcat*")(Component(name="Tomcat"))
    assert build_matcher(r"re:^HULFT\d+")(Component(name="hulft8 for Windows"))
    assert not build_matcher(r"re:^HULFT\d+")(Component(name="DataMagic"))
