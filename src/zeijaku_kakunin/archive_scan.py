"""zip / jar / war / ear / whl（と、展開したフォルダ）の中にあるライブラリを調べる。

Lambda のデプロイ用 zip やレイヤー、アプリケーションの war や fat jar など、サーバーに入っていない成果物を
管理 PC で直接調べるためのもの。syft も展開も使わず、zip をメモリ上で読む（ディスクに書き出さない）。

見つけるもの:
  - Maven: META-INF/maven/<group>/<artifact>/pom.properties（入れ子の jar / war / ear もたどる）。
    pom.properties の無い jar は MANIFEST、だめならファイル名から推定し、SHA-1 を記録する（--resolve-hashes 用）
  - Python: *.dist-info/METADATA、*.egg-info/PKG-INFO
  - npm: node_modules/<name>/package.json、node_modules/@<scope>/<name>/package.json
  - .NET: *.deps.json の libraries（type が package のもの）

結果は collect_win.ps1 と同じ形式の inventory.json（OS は family = "archive"）として書き出す。
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterator

ARCHIVE_SUFFIXES = (".zip", ".jar", ".war", ".ear", ".whl")
NESTED_SUFFIXES = (".jar", ".war", ".ear", ".zip", ".whl")
MAX_DEPTH = 4                          # 入れ子をたどる深さ
MAX_NESTED_BYTES = 512 * 1024 * 1024   # 入れ子の 1 つの大きさの上限（これより大きいものは読まずに記録する）
MAX_TEXT_BYTES = 4 * 1024 * 1024       # METADATA や package.json などとして読む大きさの上限

_POM = re.compile(r"(^|/)META-INF/maven/[^/]+/[^/]+/pom\.properties$")
_DIST_INFO = re.compile(r"(^|/)[^/]+\.(dist-info/METADATA|egg-info/PKG-INFO)$")
_NODE_PACKAGE = re.compile(r"(^|/)node_modules/(@[^/]+/)?[^/]+/package\.json$")
_DEPS_JSON = re.compile(r"(^|/)[^/]+\.deps\.json$")


class ArchiveScan:
    """見つけたものを collect_win.ps1 の inventory.json の各項目の形で集める。"""

    def __init__(self) -> None:
        self.java: list[dict] = []
        self.python: list[dict] = []
        self.node: list[dict] = []
        self.dotnet: list[dict] = []
        self.skipped: list[dict] = []     # 読めなかったもの（壊れた zip、大きすぎるもの）
        self.files = 0

    # ------------------------------------------------------------ 中身の 1 件ごと

    def _text(self, data: bytes) -> str:
        return data.decode("utf-8", errors="replace")

    def _add_python(self, data: bytes, path: str) -> None:
        name = version = ""
        for line in self._text(data).splitlines()[:80]:
            if not line.strip():
                break
            if line.startswith("Name:") and not name:
                name = line.split(":", 1)[1].strip()
            elif line.startswith("Version:") and not version:
                version = line.split(":", 1)[1].strip()
        if name and version:
            self.python.append({"name": name, "version": version, "path": path})

    def _add_node(self, data: bytes, path: str) -> None:
        try:
            package = json.loads(self._text(data))
        except ValueError:
            return
        if isinstance(package, dict) and package.get("name") and package.get("version"):
            self.node.append({"name": str(package["name"]), "version": str(package["version"]), "path": path})

    def _add_dotnet(self, data: bytes, path: str) -> None:
        try:
            deps = json.loads(self._text(data).lstrip("﻿"))
        except ValueError:
            return
        for key, value in ((deps or {}).get("libraries") or {}).items():
            if not isinstance(value, dict) or value.get("type") != "package" or "/" not in key:
                continue
            name, version = key.split("/", 1)
            self.dotnet.append({"name": name, "version": version, "path": path})

    def _add_pom(self, data: bytes, path: str) -> int:
        props = {}
        for line in self._text(data).splitlines():
            match = re.match(r"^\s*([A-Za-z]+)\s*=\s*(.*?)\s*$", line)
            if match:
                props[match.group(1)] = match.group(2)
        if props.get("artifactId") and props.get("version"):
            self.java.append({"group": props.get("groupId", ""), "artifact": props["artifactId"],
                              "version": props["version"], "path": path, "method": "pom.properties"})
            return 1
        return 0

    # ------------------------------------------------------------ zip

    def scan_zip(self, archive: zipfile.ZipFile, display: str, depth: int, raw: bytes | None = None) -> None:
        """zip を 1 つ調べる。display は表示用の場所（入れ子は outer.zip!/lib/inner.jar）。"""
        found_pom = nested = 0
        manifest = ""
        for info in archive.infolist():
            if info.is_dir():
                continue
            name = info.filename
            lower = name.lower()
            inner = f"{display}!/{name}"
            self.files += 1
            try:
                if _POM.search(name) and info.file_size <= MAX_TEXT_BYTES:
                    found_pom += self._add_pom(archive.read(info), display)
                elif name.upper() == "META-INF/MANIFEST.MF" and info.file_size <= MAX_TEXT_BYTES:
                    manifest = self._text(archive.read(info))
                elif _DIST_INFO.search(name) and info.file_size <= MAX_TEXT_BYTES:
                    self._add_python(archive.read(info), inner)
                elif _NODE_PACKAGE.search(name) and info.file_size <= MAX_TEXT_BYTES:
                    self._add_node(archive.read(info), inner)
                elif _DEPS_JSON.search(name) and info.file_size <= MAX_TEXT_BYTES:
                    self._add_dotnet(archive.read(info), inner)
                elif lower.endswith(NESTED_SUFFIXES):
                    if depth >= MAX_DEPTH:
                        self.skipped.append({"path": inner, "reason": f"入れ子が深すぎる（{MAX_DEPTH} 段まで）"})
                    elif info.file_size > MAX_NESTED_BYTES:
                        self.skipped.append({"path": inner, "reason": f"大きすぎる（{info.file_size} バイト）"})
                    else:
                        self.scan_bytes(archive.read(info), inner, depth + 1, PurePosixPath(name).name)
                        nested += 1
            except (zipfile.BadZipFile, OSError, RuntimeError, EOFError, ValueError) as exc:
                self.skipped.append({"path": inner, "reason": f"読めない（{exc}）"})
        is_java = display.lower().endswith((".jar", ".war", ".ear"))
        if is_java and found_pom == 0 and nested == 0:
            self._add_unknown_jar(display, manifest, raw)

    def _add_unknown_jar(self, display: str, manifest: str, raw: bytes | None) -> None:
        """pom.properties の無い jar: MANIFEST、だめならファイル名から推定する（collect_win.ps1 と同じ規則）。"""
        title = version = method = ""
        joined = re.sub(r"\r?\n ", "", manifest)
        for pattern, field in ((r"(?m)^Bundle-SymbolicName:\s*([^;\r\n]+)", "title"),
                               (r"(?m)^Bundle-Version:\s*(\S+)", "version"),
                               (r"(?m)^Implementation-Title:\s*(.+?)\s*$", "title"),
                               (r"(?m)^Implementation-Version:\s*(\S+)", "version")):
            match = re.search(pattern, joined)
            if match and not (title if field == "title" else version):
                if field == "title":
                    title = match.group(1).strip()
                else:
                    version = match.group(1).strip()
        if title:
            method = "manifest"
        leaf = re.split(r"[!/\\]", display)[-1]
        match = re.match(r"^(.+?)-(\d[\w.\-]*?)\.(jar|war|ear)$", leaf, re.IGNORECASE)
        if match and (not title or not version):
            title, version, method = match.group(1), match.group(2), "filename"
        sha1 = hashlib.sha1(raw).hexdigest() if raw is not None else ""
        self.java.append({"group": "", "artifact": title or Path(leaf).stem, "version": version,
                          "path": display, "method": method or "unknown", "sha1": sha1})

    def scan_bytes(self, data: bytes, display: str, depth: int, name: str) -> None:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                self.scan_zip(archive, display, depth, data)
        except zipfile.BadZipFile as exc:
            self.skipped.append({"path": display, "reason": f"zip として読めない（{exc}）"})

    # ------------------------------------------------------------ ファイル・フォルダ

    def scan_path(self, path: Path) -> None:
        if path.is_dir():
            for file in sorted(p for p in path.rglob("*") if p.is_file()):
                self._scan_loose(file)
        else:
            self._scan_loose(path)

    def _scan_loose(self, file: Path) -> None:
        """フォルダの中の 1 ファイル（展開済みの Lambda など）。"""
        posix = file.as_posix()
        self.files += 1
        try:
            if file.suffix.lower() in ARCHIVE_SUFFIXES:
                data = file.read_bytes()
                self.files -= 1                       # 中身で数える
                self.scan_bytes(data, str(file), 1, file.name)
            elif _DIST_INFO.search(posix):
                self._add_python(file.read_bytes()[:MAX_TEXT_BYTES], str(file))
            elif _NODE_PACKAGE.search(posix):
                self._add_node(file.read_bytes()[:MAX_TEXT_BYTES], str(file))
            elif _DEPS_JSON.search(posix):
                self._add_dotnet(file.read_bytes()[:MAX_TEXT_BYTES], str(file))
            elif _POM.search(posix):
                self._add_pom(file.read_bytes()[:MAX_TEXT_BYTES], str(file))
        except OSError as exc:
            self.skipped.append({"path": str(file), "reason": f"読めない（{exc}）"})

    # ------------------------------------------------------------ 出力

    def inventory(self, name: str, targets: list[str]) -> dict:
        def section(items: list[dict]) -> dict:
            unique = list({json.dumps(i, sort_keys=True): i for i in items}.values())
            return {"status": "ok", "items": unique}

        return {
            "schema": "vuln-triage-inventory/1",
            "collector_version": "archive-1",
            "host": name,
            "collected_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "os": {"family": "archive", "product_name": "アーカイブ（" + "、".join(Path(t).name for t in targets) + "）"},
            "scan_roots": targets,
            "sections": {
                "java_archives": section(self.java),
                "python_packages": section(self.python),
                "node_packages": section(self.node),
                "dotnet_packages": section(self.dotnet),
                "unreadable": {"status": "ok", "items": self.skipped},
            },
            "completed": True,
        }


def env_name_for(path: Path) -> str:
    """ファイル名から環境名を作る（Windows のフォルダ名に使えない文字は _ にする）。"""
    stem = path.name if path.is_dir() else path.stem
    return re.sub(r'[<>:"/\\|?*\s]+', "_", stem).strip("._") or "archive"


def scan(paths: list[Path]) -> ArchiveScan:
    result = ArchiveScan()
    for path in paths:
        result.scan_path(path)
    return result


def iter_targets(paths: list[Path], env: str | None) -> Iterator[tuple[str, list[Path]]]:
    """(環境名, 調べるもの) の組。--env があれば全部を 1 つの環境に、無ければ 1 つずつ別の環境にする。"""
    if env:
        yield env, paths
    else:
        for path in paths:
            yield env_name_for(path), [path]
