"""回収ファイル（<inventory-dir>/<環境名>/*.json）とサーバー一覧の読み込み。

中身を見て次の形式を自動判別する:
- CycloneDX JSON（syft / jbom / Amazon Inspector など）
- collect_win.ps1 の inventory.json
- collect_linux.sh の os_info.json
- 単体の `winget export` / `Get-HotFix` / `VersionInfo` の JSON
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path, PureWindowsPath
from typing import Any

from .purl import parse_purl
from .models import (
    KIND_CUSTOM,
    KIND_EXECUTABLE,
    KIND_MAVEN,
    KIND_NPM,
    KIND_NUGET,
    KIND_OS_PACKAGE,
    KIND_OTHER,
    KIND_PYPI,
    KIND_SOFTWARE,
    Component,
    EnvInventory,
    FailedProbe,
    SectionStatus,
)

INVENTORY_SCHEMA = "vuln-triage-inventory/1"
OSINFO_SCHEMA = "vuln-triage-osinfo/1"

_PURL_KIND = {
    "rpm": KIND_OS_PACKAGE, "deb": KIND_OS_PACKAGE, "apk": KIND_OS_PACKAGE,
    "maven": KIND_MAVEN, "pypi": KIND_PYPI, "npm": KIND_NPM, "nuget": KIND_NUGET,
}
_PATH_PROPERTY = re.compile(r"(^|:)(path|location|filepath)$", re.IGNORECASE)
_KB = re.compile(r"(?:KB)?\s*(\d{6,8})", re.IGNORECASE)


def read_text(path: Path) -> str:
    """BOM を見てエンコーディングを判別する（PowerShell は UTF-16 で出力することがある）。"""
    data = path.read_bytes()
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("cp932", errors="replace")


def normalize_kb(text: str) -> str | None:
    match = _KB.search(str(text or ""))
    return f"KB{match.group(1)}" if match else None


def detect_format(data: Any) -> str:
    if isinstance(data, dict):
        if data.get("bomFormat") == "CycloneDX":
            return "cyclonedx"
        if data.get("schema") == INVENTORY_SCHEMA:
            return "inventory"
        if data.get("schema") == OSINFO_SCHEMA:
            return "osinfo"
        if "Sources" in data:
            return "winget"
        if "SchemaVersion" in data and "Results" in data:
            return "trivy-result"
        data = [data]        # ConvertTo-Json は要素が1件だと配列にしない
    if isinstance(data, list) and data and all(isinstance(item, dict) for item in data):
        keys = set().union(*(item.keys() for item in data))
        if "HotFixID" in keys:
            return "hotfix"
        if "ProductVersion" in keys or ("FileName" in keys and "FileVersion" in keys):
            return "versioninfo"
    return "unknown"


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


# ---------------------------------------------------------------- CycloneDX

def _walk_components(components: list) -> Any:
    for item in components or []:
        if isinstance(item, dict):
            yield item
            yield from _walk_components(item.get("components") or [])


def _component_path(item: dict) -> str:
    paths = []
    for prop in item.get("properties") or []:
        name, value = str(prop.get("name", "")), prop.get("value")
        if value and _PATH_PROPERTY.search(name) and str(value) not in paths:
            paths.append(str(value))
    for occurrence in (item.get("evidence") or {}).get("occurrences") or []:
        location = occurrence.get("location")
        if location and location not in paths:
            paths.append(str(location))
    return "; ".join(paths[:3])


def load_cyclonedx(data: dict, env: EnvInventory, source: str) -> None:
    # 回収日時: os_info.json が無い場合（素の syft の出力だけを置いた場合など）は SBOM の作成日時を使う
    env.collected_at = env.collected_at or str((data.get("metadata") or {}).get("timestamp") or "")
    metadata = (data.get("metadata") or {}).get("component") or {}
    candidates = [metadata, *list(_walk_components(data.get("components") or []))]
    count = 0
    for item in candidates:
        ctype = item.get("type", "")
        if ctype == "operating-system":
            if env.os_family == "unknown":
                env.os_family = "windows" if "windows" in str(item.get("name", "")).lower() else "linux"
            if not env.os_name:
                env.os_name = str(item.get("description") or f"{item.get('name', '')} {item.get('version', '')}").strip()
            env.os_id = env.os_id or str(item.get("name") or "").lower()
            env.os_version_id = env.os_version_id or str(item.get("version") or "")
            continue
        if item is metadata or ctype == "file" or not item.get("name"):
            continue
        purl = item.get("purl", "") or ""
        parsed = parse_purl(purl)
        ptype, namespace, pname, pversion = parsed.type, parsed.namespace, parsed.name, parsed.version
        kind = _PURL_KIND.get(ptype, KIND_OTHER)
        if kind == KIND_OS_PACKAGE and env.os_family == "unknown":
            env.os_family = "linux"
        group = item.get("group") or (namespace if kind == KIND_MAVEN else "")
        # 別名: PURL の名前と、エコシステムでの正式名（Go の v2 モジュールは subpath 付き）
        extra = tuple(n for n in {pname, parsed.full_name if pname else ""} if n)
        if ptype == "golang" and parsed.subpath:
            extra = tuple(n for n in extra if n != pname)   # v1 の名前（github.com/x/y の y）では当てない
        found_by = next((str(p.get("value") or "") for p in item.get("properties") or []
                         if p.get("name") == "syft:package:foundBy"), "")
        env.components.append(Component(
            name=str(item["name"]), version=str(item.get("version") or pversion or ""), kind=kind,
            group=str(group or ""), purl=purl, path=_component_path(item), source=source,
            extra_names=extra, scannable=bool(purl), sbom_file=source, found_by=found_by,
        ))
        count += 1
    section = env.sections.setdefault("sbom", SectionStatus(count=0))
    section.count += count
    _drop_package_note_duplicates(env)


# syft が ELF のパッケージ情報（.note.package）から作る OS パッケージ。Amazon Linux 2023 などの実行ファイルに
# 埋め込まれていて、同じパッケージが rpm / dpkg のデータベースからも取れる。こちらはエポックを持たないため、
# エポック付きの修正版（1:3.0.8 など）と比べると常に古く見え、誤検出になる（実機の Amazon Linux 2023 で確認）。
# データベースから取れた同じパッケージがあれば照合から外す（Grype が所有関係で重複を除くのと同じ扱い）。
PACKAGE_NOTE_CATALOGER = "elf-binary-package-cataloger"


def _strip_epoch(version: str) -> str:
    return version.split(":", 1)[1] if re.match(r"^\d+:", version) else version


def _drop_package_note_duplicates(env: EnvInventory) -> None:
    owned: set[tuple[str, str, str]] = set()
    for component in env.components:
        parsed = parse_purl(component.purl)
        if parsed.type not in ("rpm", "deb", "apk") or component.found_by == PACKAGE_NOTE_CATALOGER:
            continue
        version = _strip_epoch(parsed.version or component.version)
        owned.add((parsed.type, parsed.name.lower(), version))
        source = parsed.qualifiers.get("upstream") or parsed.qualifiers.get("source") or ""
        source = source.split("@", 1)[0]
        match = re.match(r"^(.+)-[^-]+-[^-]+\.src\.rpm$", source)
        if match or source:
            owned.add((parsed.type, (match.group(1) if match else source).lower(), version))
    for component in env.components:
        if component.found_by != PACKAGE_NOTE_CATALOGER or not component.scannable:
            continue
        parsed = parse_purl(component.purl)
        if (parsed.type, parsed.name.lower(), _strip_epoch(parsed.version or component.version)) in owned:
            component.scannable = False


# ------------------------------------------------- Windows 単体コマンド出力

def load_winget(data: dict, env: EnvInventory, source: str) -> None:
    count = 0
    for src in _as_list(data.get("Sources")):
        for package in _as_list((src or {}).get("Packages")):
            identifier = package.get("PackageIdentifier")
            if not identifier:
                continue
            env.components.append(Component(
                name=str(identifier), version=str(package.get("Version") or ""),
                kind=KIND_SOFTWARE, source=source,
            ))
            count += 1
    env.os_family = "windows"
    env.sections["installed_software"] = SectionStatus(count=count)


def _add_hotfixes(items: list, env: EnvInventory) -> int:
    if env.hotfixes is None:
        env.hotfixes = set()
    for item in items:
        value = item.get("HotFixID") or item.get("id") if isinstance(item, dict) else item
        kb = normalize_kb(value)
        if kb:
            env.hotfixes.add(kb)
    return len(env.hotfixes)


def load_hotfix(data: Any, env: EnvInventory, source: str) -> None:
    count = _add_hotfixes(_as_list(data), env)
    env.os_family = "windows"
    env.sections["hotfixes"] = SectionStatus(count=count)


def _executable_component(item: dict, source: str) -> Component | None:
    path = str(item.get("FileName") or item.get("path") or "")
    product = str(item.get("ProductName") or item.get("product_name") or "").strip()
    version = str(item.get("ProductVersion") or item.get("product_version")
                  or item.get("FileVersion") or item.get("file_version") or "").strip()
    stem = PureWindowsPath(path).stem if path else ""
    name = product or stem
    if not name:
        return None
    # "8.0.3920.8, 2024" のような表記は先頭の版だけを使う
    version = version.replace(", ", ".").split(" ")[0] if version else ""
    extra = tuple(n for n in {stem, str(item.get("file_name") or "")} if n)
    return Component(name=name, version=version, kind=KIND_EXECUTABLE, path=path, source=source, extra_names=extra)


def load_versioninfo(data: Any, env: EnvInventory, source: str) -> None:
    count = 0
    for item in _as_list(data):
        component = _executable_component(item, source)
        if component:
            env.components.append(component)
            count += 1
    env.os_family = "windows"
    env.sections["executables"] = SectionStatus(count=count)


# ------------------------------------------------- 収集スクリプトの出力

def _section(data: dict, name: str, env: EnvInventory) -> list:
    """sections[name] の items を返し、成否を env.sections に記録する。"""
    section = (data.get("sections") or {}).get(name)
    if not isinstance(section, dict):
        env.sections.setdefault(name, SectionStatus(status="missing"))
        return []
    items = _as_list(section.get("items"))
    status = str(section.get("status") or "ok")
    env.sections[name] = SectionStatus(status=status, count=len(items), reason=str(section.get("reason") or ""))
    return items


def _load_custom_products(data: dict, env: EnvInventory, source: str) -> None:
    by_name: dict[str, list[dict]] = {}
    for item in _section(data, "custom_products", env):
        if isinstance(item, dict) and item.get("name"):
            by_name.setdefault(str(item["name"]), []).append(item)
    for name, items in by_name.items():
        found = [i for i in items if i.get("status") == "found"]
        errors = [i for i in items if i.get("status") == "error"]
        if found:
            # 版が取れた結果を優先し、同じ製品の「存在だけ分かった」結果は捨てる
            with_version = [i for i in found if i.get("version")]
            seen = set()
            for item in with_version or found[:1]:
                key = (item.get("version"), item.get("source"))
                if key in seen:
                    continue
                seen.add(key)
                env.components.append(Component(
                    name=name, version=str(item.get("version") or ""), kind=KIND_CUSTOM,
                    path=str(item.get("source") or ""), source=f"{source}:custom_products",
                ))
        elif errors:
            env.failed_probes.append(FailedProbe(name=name, reason=str(errors[0].get("reason") or "")))


def _load_common(data: dict, env: EnvInventory, source: str) -> None:
    env.collected_at = str(data.get("collected_at") or env.collected_at)
    if data.get("completed") is not True:
        env.incomplete = True
        env.warnings.append(f"{source}: 収集が完了していません（途中で中断された可能性）")
    _load_custom_products(data, env, source)
    for item in _section(data, "unreadable", env):
        path = item.get("path") if isinstance(item, dict) else item
        if path:
            env.unreadable.append(str(path))


def _under(path: str, roots: list[str]) -> bool:
    lowered = path.lower().replace("/", "\\")
    return any(lowered.startswith(root.lower().replace("/", "\\").rstrip("\\") + "\\") for root in roots if root)


def load_inventory(data: dict, env: EnvInventory, source: str) -> None:
    """collect_win.ps1 の inventory.json。"""
    os_info = data.get("os") or {}
    env.os_family = str(os_info.get("family") or "windows")
    env.os_name = " ".join(str(os_info.get(k) or "") for k in ("product_name", "display_version")).strip()
    env.os_build = str(os_info.get("build") or "")
    if env.os_family == "archive":
        # scan-file で zip / jar などを調べた結果。OS は無い（Windows の KB・OS の通達は「対象外」になる）
        env.sections["os"] = SectionStatus(status="ok", count=0)
    else:
        env.sections["os"] = SectionStatus(status="ok" if env.os_build else "failed", count=1 if env.os_build else 0)
    _load_common(data, env, source)

    hotfix_items = _section(data, "hotfixes", env)
    if env.sections["hotfixes"].status == "ok":
        _add_hotfixes(hotfix_items, env)

    for item in _section(data, "installed_software", env):
        if item.get("name"):
            env.components.append(Component(
                name=str(item["name"]), version=str(item.get("version") or ""), kind=KIND_SOFTWARE,
                path=str(item.get("install_location") or ""), source=f"{source}:installed_software",
            ))
    for item in _section(data, "executables", env):
        component = _executable_component(item, f"{source}:executables")
        if component:
            env.components.append(component)
    for item in _section(data, "java_archives", env):
        artifact = item.get("artifact") or item.get("name")
        if artifact:
            env.components.append(Component(
                name=str(artifact), version=str(item.get("version") or ""), kind=KIND_MAVEN,
                group=str(item.get("group") or ""), path=str(item.get("path") or ""),
                source=f"{source}:java_archives",
                extra_names=(f"sha1:{item['sha1']}",) if item.get("sha1") else (),
            ))
    for section, kind in (("python_packages", KIND_PYPI), ("node_packages", KIND_NPM), ("dotnet_packages", KIND_NUGET)):
        for item in _section(data, section, env):
            if item.get("name"):
                env.components.append(Component(
                    name=str(item["name"]), version=str(item.get("version") or ""), kind=kind,
                    path=str(item.get("path") or ""), source=f"{source}:{section}",
                ))

    roots = [str(r) for r in _as_list(data.get("scan_roots"))]
    system_roots = [r for r in (str(os_info.get("system_root") or ""), "C:\\Windows") if r]
    for item in _section(data, "running", env):
        path = str(item.get("path") if isinstance(item, dict) else item or "")
        if path and not _under(path, roots) and not _under(path, system_roots):
            env.out_of_scope_running.append(path)


def load_osinfo(data: dict, env: EnvInventory, source: str) -> None:
    """collect_linux.sh の os_info.json。"""
    os_info = data.get("os") or {}
    env.os_family = str(os_info.get("family") or "linux")
    env.os_name = str(os_info.get("pretty_name") or f"{os_info.get('id', '')} {os_info.get('version_id', '')}").strip()
    env.os_id = str(os_info.get("id") or env.os_id).lower()
    env.os_version_id = str(os_info.get("version_id") or env.os_version_id)
    env.emr_release = str(data.get("emr_release") or "")
    _load_common(data, env, source)
    syft = data.get("syft") or {}
    status = str(syft.get("status") or "missing")
    env.sections["syft"] = SectionStatus(status=status, reason=str(syft.get("reason") or ""))
    if status != "ok":
        env.warnings.append(f"{source}: syft による SBOM 作成に失敗しています（{syft.get('reason') or status}）")
    elif syft.get("checksum") == "unverified":
        env.warnings.append(f"{source}: 回収に使った syft のチェックサムを確かめていません"
                            "（syft_<版>_checksums.txt を一緒に持ち込むと確かめます）")
    if env.emr_release:
        env.components.append(Component(
            name="amazon-emr", version=env.emr_release.removeprefix("emr-"), kind=KIND_CUSTOM,
            path="EMR リリースラベル", source=f"{source}:emr_release", extra_names=("emr",),
        ))


_LOADERS = {
    "cyclonedx": load_cyclonedx,
    "inventory": load_inventory,
    "osinfo": load_osinfo,
    "winget": load_winget,
    "hotfix": load_hotfix,
    "versioninfo": load_versioninfo,
}


def load_env_dir(path: Path, name: str | None = None) -> EnvInventory:
    env = EnvInventory(name=name or path.name)
    for file in sorted(path.glob("*.json")):
        try:
            data = json.loads(read_text(file))
        except (ValueError, OSError) as exc:
            env.warnings.append(f"{file.name}: JSON として読めません（{exc}）")
            continue
        fmt = detect_format(data)
        if fmt == "trivy-result":
            continue
        if fmt == "unknown":
            env.warnings.append(f"{file.name}: 形式を判別できないため読み飛ばしました")
            continue
        _LOADERS[fmt](data, env, file.name)
        env.files.append(f"{file.name}（{fmt}）")
        if fmt == "cyclonedx":
            env.sbom_files.append(file)
        if fmt in ("cyclonedx", "inventory"):
            env.full_collection = True
    if not env.files:
        env.warnings.append("読み込める回収ファイルがありません")
    return env


def load_env_master(path: str | Path | None) -> dict[str, dict[str, str]]:
    if not path:
        return {}
    text = read_text(Path(path))
    master = {}
    for row in csv.DictReader(text.splitlines()):
        name = (row.get("env_name") or "").strip()
        if not name:
            continue
        exposure = (row.get("exposure") or "").strip().lower()
        master[name] = {
            "exposure": exposure if exposure in ("internet", "internal") else "internal",
            "system_name": (row.get("system_name") or "").strip(),
        }
    return master


def load_inventories(inventory_dir: str | Path, env_master: dict[str, dict[str, str]]) -> list[EnvInventory]:
    root = Path(inventory_dir)
    if not root.is_dir():
        raise FileNotFoundError(f"インベントリのフォルダがありません: {root}")
    envs = []
    for path in sorted(p for p in root.iterdir() if p.is_dir()):
        env = load_env_dir(path)
        info = env_master.get(env.name)
        if info:
            env.exposure, env.system_name, env.registered = info["exposure"], info["system_name"], True
        else:
            env.warnings.append("env_master に未登録のため internal（社内限定）として扱いました")
        envs.append(env)
    # env_master にあるのに回収フォルダが無い環境も、レポートから消さずに「判定不能」として出す
    # （回収し忘れたホストに気づけるようにする）
    found = {env.name for env in envs}
    for name, info in env_master.items():
        if name in found:
            continue
        env = EnvInventory(name=name, exposure=info["exposure"], system_name=info["system_name"], registered=True)
        env.not_collected = True
        env.warnings.append(f"env_master に登録済みですが、回収フォルダ（{root / name}）がありません")
        envs.append(env)
    return sorted(envs, key=lambda e: e.name)
