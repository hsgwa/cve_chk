"""Trivy CLI の呼び出しと結果の読み取り。"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .inventory import _component_path, _walk_components, read_text
from .models import EnvInventory, TrivyFinding


class TrivyNotFoundError(RuntimeError):
    def __init__(self) -> None:
        super().__init__(
            "Trivy が見つかりません。\n"
            "  1. https://github.com/aquasecurity/trivy/releases から Windows 用 zip を入手して展開し、\n"
            "     trivy.exe のあるフォルダを PATH に追加するか、config.yaml の trivy.path に場所を書いてください。\n"
            "  2. Trivy を使わずに実行する場合は --skip-trivy を付けてください\n"
            "     （CVE 番号だけの通達は「判定不能」になります）。\n"
            "  3. 保存済みの Trivy 結果を使う場合は --trivy-results-dir を指定してください。")


class TrivyError(RuntimeError):
    pass


def find_trivy(config: dict[str, Any]) -> str:
    configured = (config.get("trivy") or {}).get("path") or ""
    if configured:
        if Path(configured).is_file():
            return str(configured)
        found = shutil.which(configured)
        if found:
            return found
        raise TrivyNotFoundError()
    found = shutil.which("trivy")
    if not found:
        raise TrivyNotFoundError()
    return found


def result_file_name(env: str, sbom: Path) -> str:
    return f"{env}__{sbom.stem}.trivy.json"


def run_trivy(trivy: str, sbom: Path, config: dict[str, Any]) -> dict:
    settings = config.get("trivy") or {}
    command = [trivy, "sbom", "--format", "json", "--quiet", *settings.get("extra_args", []), str(sbom)]
    try:
        completed = subprocess.run(
            command, capture_output=True, timeout=int(settings.get("timeout_sec") or 600), check=False)
    except subprocess.TimeoutExpired as exc:
        raise TrivyError(f"Trivy が時間切れになりました: {sbom}") from exc
    if completed.returncode != 0:
        message = completed.stderr.decode("utf-8", errors="replace").strip().splitlines()[-3:]
        raise TrivyError(f"Trivy がエラー終了しました（{sbom.name}）: {' / '.join(message)}")
    try:
        return json.loads(completed.stdout.decode("utf-8", errors="replace") or "{}")
    except ValueError as exc:
        raise TrivyError(f"Trivy の出力を読めません: {sbom}") from exc


def pick_cvss(cvss: dict | None, priority: list[str]) -> float | None:
    """優先ソース（既定 nvd）の CVSS v3 を使い、無ければ全ソースの最大値。"""
    scores = {}
    for source, values in (cvss or {}).items():
        score = (values or {}).get("V3Score") or (values or {}).get("V40Score")
        if isinstance(score, (int, float)):
            scores[source.lower()] = float(score)
    for source in priority or []:
        if source.lower() in scores:
            return scores[source.lower()]
    return max(scores.values()) if scores else None


def _path_index(sbom: Path) -> dict[str, list[str]]:
    """SBOM 内の bom-ref / PURL からファイルパスを引く表。

    同じパッケージが複数の場所にあっても Trivy は1件にまとめて報告するため、
    PURL からはすべての場所を引けるようにしておく。
    """
    try:
        data = json.loads(read_text(sbom))
    except (ValueError, OSError):
        return {}
    index: dict[str, list[str]] = {}
    for item in _walk_components(data.get("components") or []):
        path = _component_path(item)
        if not path:
            continue
        for key in (item.get("bom-ref"), item.get("purl")):
            if key and path not in index.setdefault(str(key), []):
                index[str(key)].append(path)
    return index


def parse_results(data: dict, env: str, sbom: Path, config: dict[str, Any]) -> list[TrivyFinding]:
    priority = config.get("cvss_source_priority") or ["nvd"]
    paths = _path_index(sbom) if sbom.is_file() else {}
    findings = []
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            identifier = vuln.get("PkgIdentifier") or {}
            if vuln.get("PkgPath"):
                locations = [str(vuln["PkgPath"])]
            else:
                locations = (paths.get(str(identifier.get("PURL") or ""))
                             or paths.get(str(identifier.get("BOMRef") or "")) or [""])
            for location in locations:
                findings.append(TrivyFinding(
                    env=env,
                    cve_id=str(vuln.get("VulnerabilityID") or "").upper(),
                    pkg_name=str(vuln.get("PkgName") or ""),
                    installed_version=str(vuln.get("InstalledVersion") or ""),
                    fixed_version=str(vuln.get("FixedVersion") or ""),
                    path=location,
                    cvss=pick_cvss(vuln.get("CVSS"), priority),
                    severity=str(vuln.get("Severity") or ""),
                    title=str(vuln.get("Title") or ""),
                    sbom=sbom.name,
                ))
    return findings


def scan_environments(
    envs: list[EnvInventory],
    config: dict[str, Any],
    results_dir: str | Path | None = None,
    save_dir: str | Path | None = None,
    log=lambda message: None,
) -> list[TrivyFinding]:
    """各環境の SBOM を Trivy で判定する。results_dir があれば保存済みの結果を使う。"""
    trivy = None if results_dir else find_trivy(config)
    findings: list[TrivyFinding] = []
    for env in envs:
        for sbom in env.sbom_files:
            name = result_file_name(env.name, sbom)
            try:
                if results_dir:
                    saved = Path(results_dir) / name
                    if not saved.is_file():
                        env.warnings.append(f"{sbom.name}: 保存済みの Trivy 結果（{name}）がありません")
                        continue
                    data = json.loads(read_text(saved))
                else:
                    log(f"Trivy: {env.name} / {sbom.name}")
                    data = run_trivy(trivy, sbom, config)
                    if save_dir:
                        Path(save_dir).mkdir(parents=True, exist_ok=True)
                        (Path(save_dir) / name).write_text(
                            json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
            except (TrivyError, ValueError, OSError) as exc:
                env.warnings.append(str(exc))
                continue
            env.scanned_sboms += 1
            findings.extend(parse_results(data, env.name, sbom, config))
    # 同じ jar が複数の SBOM（jbom と自前解析）に出た場合の重複を除く
    unique: dict[tuple, TrivyFinding] = {}
    for finding in findings:
        key = (finding.env, finding.cve_id, finding.pkg_name, finding.installed_version, finding.path)
        unique.setdefault(key, finding)
    return list(unique.values())
