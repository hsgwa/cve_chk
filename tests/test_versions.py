import pytest

from vuln_triage.matching.versions import normalize_version, version_matches


@pytest.mark.parametrize("installed, spec, expected", [
    ("2.14.1", ">=2.0.0,<2.17.1", True),
    ("2.17.1", ">=2.0.0,<2.17.1", False),
    ("3.0.12", "<=3.0.12", True),
    ("3.0.13", "<=3.0.12", False),
    ("9.0.83", "9.0.*", True),
    ("9.1.0", "9.0.*", False),
    ("9.0.83", "==9.0.*", True),
    ("2.14.1", "2.14.1", True),               # 演算子なしは一致
    ("1:2.3-4ubuntu1", "<2.4", True),         # Debian の epoch とリリース番号
    ("3.4.1-amzn-2", ">=3.4.0,<3.5.0", True), # EMR の接尾辞
    ("2.17.1.Final", "<2.17.1", False),
    ("8u392", "<8u401", True),                # Java の update 表記
    ("1.8.0_392", "<1.8.0_401", True),
    ("10.0.19045.3803", "<10.0.19045.4046", True),
    ("8.0.3920.8", ">=8.0", True),
    ("v1.2.3", "<1.3", True),
    ("２.１４.１", "＜２.１５.０", True),       # 全角
])
def test_version_matches(installed, spec, expected):
    assert version_matches(installed, spec) is expected


@pytest.mark.parametrize("installed, spec", [
    ("", "<1.0"),
    ("unknown", "<1.0"),
    ("1.0", ""),
    ("1.0", "古い版すべて"),
    ("1.0", ">=1.*"),
])
def test_uncomparable_returns_none(installed, spec):
    assert version_matches(installed, spec) is None


def test_normalize_version():
    assert normalize_version("1:2.3-4ubuntu1") == "2.3"
    assert normalize_version("8u392") == "8.392"
    assert normalize_version("abc") is None
