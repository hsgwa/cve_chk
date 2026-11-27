import urllib.error

from zeijaku_kakunin.models import AFFECTED, NOT_AFFECTED, NOT_APPLICABLE, UNKNOWN
from zeijaku_kakunin.msrc import MsrcClient, evaluate_build, extract_cve

DOCUMENT = {
    "ProductTree": {"FullProductName": [
        {"ProductID": "11571", "Value": "Windows Server 2019"},
        {"ProductID": "11929", "Value": "Windows 10 Version 22H2 for x64-based Systems"}]},
    "Vulnerability": [
        {"CVE": "CVE-2024-21338",
         "Remediations": [
             {"Description": {"Value": "5034768"}, "ProductID": ["11571"], "FixedBuild": "10.0.17763.5458", "Type": 2},
             {"Description": {"Value": "5034763"}, "ProductID": ["11929"], "FixedBuild": "10.0.19045.4046", "Type": 2},
             {"Description": {"Value": "Release Notes"}, "ProductID": ["11571"], "Type": 2}],
         "CVSSScoreSets": [{"BaseScore": 7.8, "ProductID": ["11571"]}]},
        {"CVE": "CVE-2024-99999", "Remediations": []}],
}
INFO = extract_cve(DOCUMENT, "CVE-2024-21338")


def test_extract_cve():
    assert INFO["cvss"] == 7.8
    assert INFO["fixes"] == [
        {"product": "Windows Server 2019", "kb": "KB5034768", "fixed_build": "10.0.17763.5458"},
        {"product": "Windows 10 Version 22H2 for x64-based Systems", "kb": "KB5034763", "fixed_build": "10.0.19045.4046"}]


def test_evaluate_build():
    status, detail = evaluate_build("10.0.17763.5329", INFO)
    assert status == AFFECTED and "KB5034768" in detail and "10.0.17763.5458" in detail
    assert evaluate_build("10.0.17763.5458", INFO)[0] == NOT_AFFECTED
    assert evaluate_build("10.0.19045.5000", INFO)[0] == NOT_AFFECTED
    assert evaluate_build("10.0.20348.100", INFO)[0] == NOT_APPLICABLE       # 対象に含まれないビルド系列
    assert evaluate_build("10.0.14393.100", INFO, eol_builds=[14393])[0] == UNKNOWN   # サポート切れ
    assert evaluate_build("", INFO)[0] == UNKNOWN                            # ビルド番号を回収できていない
    assert evaluate_build("10.0.17763.1", {"fixes": []}) is None              # Windows OS の CVE ではない
    assert evaluate_build("10.0.17763.1", None) is None


def test_client_fetches_and_caches(tmp_path, config):
    calls = []

    def fetch(url, timeout):
        calls.append(url)
        if "updates(" in url:
            return {"value": [{"ID": "2024-Feb", "CvrfUrl": "https://example.invalid/cvrf/2024-Feb"}]}
        return DOCUMENT

    client = MsrcClient(tmp_path, config, fetch=fetch)
    assert client.lookup("cve-2024-21338")["fixes"][0]["kb"] == "KB5034768"
    assert client.lookup("CVE-2024-21338")["cvss"] == 7.8
    assert len(calls) == 2                                   # 2回目はキャッシュ
    assert MsrcClient(tmp_path, config, offline=True).lookup("CVE-2024-21338")["found"]


def test_client_unknown_cve_and_errors(tmp_path, config):
    def not_found(url, timeout):
        raise urllib.error.HTTPError(url, 404, "Not Found", None, None)

    client = MsrcClient(tmp_path, config, fetch=not_found)
    assert client.lookup("CVE-2021-44228") == {"cve": "CVE-2021-44228", "found": False, "fixes": [], "cvss": None}
    assert client.error is None

    def broken(url, timeout):
        raise urllib.error.URLError("proxy refused")

    client = MsrcClient(tmp_path / "other", config, fetch=broken)
    assert client.lookup("CVE-2024-0001") is None
    assert "取得できませんでした" in client.error
    assert MsrcClient(tmp_path / "none", config, offline=True).lookup("CVE-2024-0002") is None
