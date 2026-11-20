"""コンポーネント（PURL）から、OSV.dev のエコシステム名とパッケージ名を決める。"""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import unquote

from ..models import Component, EnvInventory

# PURL の種類 → OSV のエコシステム（ライブラリ）
LIBRARY_ECOSYSTEMS = {
    "maven": "Maven", "pypi": "PyPI", "npm": "npm", "nuget": "NuGet", "golang": "Go",
    "cargo": "crates.io", "gem": "RubyGems", "composer": "Packagist", "hex": "Hex", "pub": "Pub",
}

# カーネルのヘッダファイルだけを含むパッケージ（ソースパッケージが linux のため、そのままだと
# カーネル本体の脆弱性がすべて当てはまってしまう。Trivy・Grype と同じく照合しない）
KERNEL_HEADER_PACKAGES = {"linux-libc-dev"}

# 照合の単位となるデータの名前（OSV のダウンロード用 zip の名前、または Amazon Linux の版）
AMAZON_PREFIX = "Amazon Linux:"


@dataclass(frozen=True)
class Query:
    source: str                      # 必要なデータ（例: "Maven"、"Ubuntu"、"Amazon Linux:2"）
    ecosystems: tuple[str, ...]      # 照合する OSV のエコシステム名（完全一致、末尾 % は前方一致）
    names: tuple[str, ...]           # 照合するパッケージ名（正規化済み）
    version: str
    display: str                     # 表示用のパッケージ名


def normalize_package(ecosystem: str, name: str) -> str:
    name = name.strip()
    if ecosystem.split(":", 1)[0] == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def parse_purl_full(purl: str) -> tuple[str, str, str, str, dict[str, str]]:
    """PURL を (type, namespace, name, version, qualifiers) に分ける。"""
    if not purl or not purl.startswith("pkg:"):
        return "", "", "", "", {}
    body, _, subpath = purl[4:].partition("#")
    body, _, query = body.partition("?")
    qualifiers = {}
    for pair in query.split("&") if query else []:
        key, _, value = pair.partition("=")
        qualifiers[key.lower()] = unquote(value)
    ptype, _, rest = body.partition("/")
    if "@" in rest:
        rest, _, version = rest.rpartition("@")
    else:
        version = ""
    namespace, _, name = rest.rpartition("/")
    if subpath:
        qualifiers["#subpath"] = unquote(subpath).strip("/")
    return ptype.lower(), unquote(namespace), unquote(name), unquote(version), qualifiers


def _distro(qualifiers: dict[str, str], env: EnvInventory) -> tuple[str, str]:
    """(OS の ID, 版) を返す。PURL に無ければ環境の OS 情報を使う。"""
    distro = qualifiers.get("distro", "")
    match = re.match(r"^([a-z]+)-(.+)$", distro)
    if match:
        return match.group(1), match.group(2)
    return env.os_id, env.os_version_id


def _source_name(value: str) -> str:
    """deb の upstream（`openssl` / `openssl@3.0.2`）や rpm の source rpm 名からソースパッケージ名を取る。"""
    value = value.split("@", 1)[0]
    match = re.match(r"^(.+)-[^-]+-[^-]+\.src\.rpm$", value)
    return match.group(1) if match else value


def build_query(component: Component, env: EnvInventory) -> Query | None:
    ptype, namespace, name, version, qualifiers = parse_purl_full(component.purl)
    if not ptype or not name:
        return None
    version = version or component.version
    if not version or not re.search(r"\d", version):
        return None                   # 版が不明（UNKNOWN など）のものは照合できない

    if ptype in LIBRARY_ECOSYSTEMS:
        ecosystem = LIBRARY_ECOSYSTEMS[ptype]
        if ptype == "maven":
            full = f"{namespace}:{name}" if namespace else name
        elif ptype in ("npm", "golang", "composer") and namespace:
            full = f"{namespace}/{name}"
        else:
            full = name
        if ptype == "golang":
            # Go の v2 以降のモジュールは pkg:golang/github.com/x/y@v2.1.0#v2 のように書かれる
            if qualifiers.get("#subpath"):
                full = f"{full}/{qualifiers['#subpath']}"
            version = version.removeprefix("v")
        return Query(ecosystem, (ecosystem,), (normalize_package(ecosystem, full),), version, full)

    if ptype == "deb" and name in KERNEL_HEADER_PACKAGES:
        return None                   # カーネルのヘッダだけのパッケージにカーネル本体の脆弱性は当てはまらない
    if ptype in ("deb", "rpm", "apk"):
        distro_id, distro_version = _distro(qualifiers, env)
        names = [name]
        upstream = qualifiers.get("upstream") or qualifiers.get("source", "")
        if upstream:
            source = _source_name(upstream)
            if source and source != name:
                names.insert(0, source) if ptype == "deb" else names.append(source)
        if ptype == "rpm" and qualifiers.get("epoch") and ":" not in version and qualifiers["epoch"] != "0":
            version = f"{qualifiers['epoch']}:{version}"
        major = distro_version.split(".", 1)[0]
        if distro_id == "ubuntu":
            # 修正版が Ubuntu Pro（ESM）でしか出ていないものは Pro 用の情報にしか載らないので、両方を見る
            source, ecosystems = "Ubuntu", [f"Ubuntu:{distro_version}:LTS", f"Ubuntu:{distro_version}",
                                            f"Ubuntu:Pro:{distro_version}:LTS"]
        elif distro_id == "debian":
            source, ecosystems = "Debian", [f"Debian:{major}"]
        elif distro_id == "amzn":
            release = "2023" if distro_version.startswith("2023") else major
            source = ecosystem = f"{AMAZON_PREFIX}{release}"
            ecosystems = [ecosystem]
        elif distro_id in ("rhel", "redhat"):
            source, ecosystems = "Red Hat", [f"Red Hat:enterprise_linux:{major}:%"]
        elif distro_id == "rocky":
            source, ecosystems = "Rocky Linux", [f"Rocky Linux:{major}"]
        elif distro_id in ("almalinux", "alma"):
            source, ecosystems = "AlmaLinux", [f"AlmaLinux:{major}"]
        elif distro_id == "alpine":
            minor = ".".join(distro_version.split(".")[:2])
            source, ecosystems = "Alpine", [f"Alpine:v{minor}"]
        else:
            return Query(f"未対応の OS（{distro_id or '不明'}）", (), (), version, name)
        names = tuple(dict.fromkeys(normalize_package(source, n) for n in names))
        return Query(source, tuple(ecosystems), names, version, name)
    return None


def needed_sources(envs: list[EnvInventory], config: dict | None = None) -> tuple[list[str], dict[str, int]]:
    """回収データの照合に必要な脆弱性データの名前と、照合できない OS の一覧（{名前: 件数}）。"""
    settings = (config or {}).get("vulndb") or {}
    needed: dict[str, int] = {}
    unsupported: dict[str, int] = {}
    has_os_packages = False
    for env in envs:
        for component in env.components:
            if not component.purl:
                continue
            query = build_query(component, env)
            if query is None:
                continue
            if not query.ecosystems:
                unsupported[query.source] = unsupported.get(query.source, 0) + 1
                continue
            needed[query.source] = needed.get(query.source, 0) + 1
            if query.source not in LIBRARY_ECOSYSTEMS.values():
                has_os_packages = True
    sources = sorted(needed)
    if has_os_packages:
        # Amazon Linux のデータには CVSS が無いので、点数を引くためのデータも取る
        for extra in settings.get("score_sources") or []:
            if extra not in sources:
                sources.append(extra)
    return sources, unsupported
