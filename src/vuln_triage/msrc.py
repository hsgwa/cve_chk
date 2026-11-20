"""Windows OS の脆弱性を、Microsoft の公開データ（MSRC Security Update API）で判定する。

CVE ごとに「どのビルド系列が、どのビルド番号（と KB）で修正されたか」を取得し、
回収した OS のビルド番号と比べる。取得結果は CVE 単位でキャッシュする。
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .models import AFFECTED, NOT_AFFECTED, NOT_APPLICABLE, UNKNOWN

API = "https://api.msrc.microsoft.com/cvrf/v3.0"
_BUILD = re.compile(r"^\d+\.\d+\.\d+\.\d+$")


def _get_json(url: str, timeout: int) -> Any:
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "vuln-triage"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8-sig"))


def extract_cve(document: dict, cve_id: str) -> dict:
    """月次の CVRF 文書から、1つの CVE の修正情報だけを取り出す。"""
    products = {
        str(p.get("ProductID")): str(p.get("Value") or "")
        for p in (document.get("ProductTree") or {}).get("FullProductName") or []
    }
    fixes, scores = [], []
    for vuln in document.get("Vulnerability") or []:
        if str(vuln.get("CVE") or "").upper() != cve_id.upper():
            continue
        for remediation in vuln.get("Remediations") or []:
            build = str(remediation.get("FixedBuild") or "").strip()
            if not _BUILD.match(build):
                continue
            kb = str((remediation.get("Description") or {}).get("Value") or "").strip()
            for product_id in remediation.get("ProductID") or []:
                fixes.append({
                    "product": products.get(str(product_id), str(product_id)),
                    "kb": f"KB{kb}" if kb.isdigit() else kb,
                    "fixed_build": build,
                })
        for score in vuln.get("CVSSScoreSets") or []:
            if isinstance(score.get("BaseScore"), (int, float)):
                scores.append(float(score["BaseScore"]))
    return {"cve": cve_id.upper(), "found": True, "fixes": fixes, "cvss": max(scores) if scores else None}


class MsrcClient:
    def __init__(self, cache_dir: str | Path, config: dict[str, Any], offline: bool = False, fetch=_get_json):
        self.cache_dir = Path(cache_dir)
        self.settings = config.get("msrc") or {}
        self.offline = offline
        self.fetch = fetch
        self.error: str | None = None      # 取得に失敗した場合の理由（以後は問い合わせない）
        self._documents: dict[str, dict] = {}

    def lookup(self, cve_id: str) -> dict | None:
        """CVE の修正情報。取得できない場合は None。"""
        cve_id = cve_id.upper()
        cache = self.cache_dir / f"{cve_id}.json"
        if cache.is_file():
            try:
                return json.loads(cache.read_text(encoding="utf-8"))
            except ValueError:
                pass
        if self.offline or self.error:
            return None
        timeout = int(self.settings.get("timeout_sec") or 60)
        try:
            try:
                updates = self.fetch(f"{API}/updates('{cve_id}')", timeout)
            except urllib.error.HTTPError as exc:
                if exc.code != 404:
                    raise
                updates = {"value": []}
            documents = (updates or {}).get("value") or []
            if not documents:
                info = {"cve": cve_id, "found": False, "fixes": [], "cvss": None}
            else:
                # 改訂で複数の月に載ることがあるので、すべての文書の修正情報を合わせる
                info = {"cve": cve_id, "found": True, "fixes": [], "cvss": None}
                for entry in documents:
                    doc_id = str(entry.get("ID") or "")
                    url = entry.get("CvrfUrl") or f"{API}/cvrf/{doc_id}"
                    if doc_id not in self._documents:
                        self._documents[doc_id] = self.fetch(url, timeout)
                    part = extract_cve(self._documents[doc_id], cve_id)
                    info["fixes"].extend(part["fixes"])
                    if part["cvss"] is not None:
                        info["cvss"] = max(info["cvss"] or 0.0, part["cvss"])
        except (urllib.error.URLError, OSError, ValueError, TimeoutError) as exc:
            self.error = f"Microsoft の公開データを取得できませんでした（{exc}）"
            return None
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        cache.write_text(json.dumps(info, ensure_ascii=False, indent=1), encoding="utf-8")
        return info


def _series(build: str) -> tuple[str, int] | None:
    parts = build.split(".")
    if len(parts) != 4 or not all(p.isdigit() for p in parts):
        return None
    return ".".join(parts[:3]), int(parts[3])


def evaluate_build(os_build: str, info: dict | None, eol_builds: list | None = None) -> tuple[str, str] | None:
    """OS ビルドと修正情報から (影響有無, 説明) を返す。Windows OS の CVE でなければ None。"""
    if not info or not info.get("fixes"):
        return None
    host = _series(os_build)
    if host is None:
        return UNKNOWN, "OS のビルド番号を回収できていません"
    series, revision = host
    same = [f for f in info["fixes"] if (_series(f["fixed_build"]) or ("", 0))[0] == series]
    if not same:
        build_number = series.split(".")[-1]
        if any(str(e) in (series, build_number) for e in eol_builds or []):
            return UNKNOWN, f"OS ビルド {series} はサポート切れのため修正情報がありません（要確認）"
        return NOT_APPLICABLE, f"この CVE の対象に OS ビルド {series} は含まれていません"
    fix = min(same, key=lambda f: _series(f["fixed_build"])[1])
    fixed_revision = _series(fix["fixed_build"])[1]
    detail = f"修正ビルド {fix['fixed_build']}（{fix['kb']}）／現在 {os_build}"
    if revision < fixed_revision:
        return AFFECTED, detail
    return NOT_AFFECTED, f"適用済み: {detail}"
