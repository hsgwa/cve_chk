"""Windows の inventory.json から、Trivy に渡す CycloneDX SBOM を作る。

対象は PURL を作れるもの（Java / Python / npm / NuGet）だけ。
インストール済みソフトや exe のバージョン情報は Trivy では判定できないため含めない。
"""
from __future__ import annotations

import json
import re
import uuid
from pathlib import Path
from urllib.parse import quote

from .models import KIND_MAVEN, KIND_NPM, KIND_NUGET, KIND_PYPI, Component, EnvInventory

GENERATED_PREFIX = "generated_"


def make_purl(component: Component) -> str:
    name, version = component.name, component.version
    if not name or not version:
        return ""
    if component.kind == KIND_MAVEN:
        if not component.group:
            return ""
        return f"pkg:maven/{quote(component.group)}/{quote(name)}@{quote(version)}"
    if component.kind == KIND_PYPI:
        normalized = re.sub(r"[-_.]+", "-", name).lower()
        return f"pkg:pypi/{quote(normalized)}@{quote(version)}"
    if component.kind == KIND_NPM:
        return f"pkg:npm/{quote(name, safe='/')}@{quote(version)}".replace("pkg:npm/@", "pkg:npm/%40")
    if component.kind == KIND_NUGET:
        return f"pkg:nuget/{quote(name)}@{quote(version)}"
    return ""


def build_sbom(env: EnvInventory) -> dict | None:
    """inventory.json 由来のコンポーネントから CycloneDX 1.5 を作る。対象が無ければ None。"""
    components = []
    for index, component in enumerate(env.components):
        if component.scannable or component.purl:
            continue                      # 既に CycloneDX として回収済みのもの
        purl = make_purl(component)
        if not purl:
            continue
        component.purl = purl
        component.scannable = True
        entry = {
            "type": "library",
            "bom-ref": f"{purl}#{index}",
            "name": component.name,
            "version": component.version,
            "purl": purl,
        }
        if component.group:
            entry["group"] = component.group
        if component.path:
            entry["properties"] = [{"name": "vuln-triage:path", "value": component.path}]
        components.append(entry)
    if not components:
        return None
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "tools": [{"vendor": "vuln-triage", "name": "sbom_builder"}],
            "component": {"type": "application", "name": env.name, "bom-ref": f"env:{env.name}"},
        },
        "components": components,
    }


def assign_purls(envs: list[EnvInventory]) -> None:
    """inventory.json 由来のコンポーネントに PURL を付ける（OSV で照合できるようにする）。"""
    for env in envs:
        for component in env.components:
            if component.purl:
                continue
            purl = make_purl(component)
            if purl:
                component.purl = purl
                component.scannable = True


def write_sboms(envs: list[EnvInventory], out_dir: str | Path) -> list[Path]:
    """各環境の SBOM を書き出し、env.sbom_files に追加する。"""
    out = Path(out_dir)
    written = []
    for env in envs:
        sbom = build_sbom(env)
        if sbom is None:
            continue
        out.mkdir(parents=True, exist_ok=True)
        path = out / f"{GENERATED_PREFIX}{env.name}.cdx.json"
        path.write_text(json.dumps(sbom, ensure_ascii=False, indent=1), encoding="utf-8")
        for component in env.components:
            if component.scannable and not component.sbom_file:
                component.sbom_file = path.name
        env.sbom_files.append(path)
        written.append(path)
    return written
