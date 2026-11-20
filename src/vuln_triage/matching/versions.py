"""バージョン条件の比較。

PEP 440 として解釈できない版（Debian の epoch、`8u392`、`3.4.1-amzn-2` など）は
数字部分を取り出して比較を試み、それでも比較できなければ None（比較不能）を返す。
"""
from __future__ import annotations

import re
import unicodedata

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

_CLAUSE = re.compile(r"^\s*(~=|===|==|!=|<=|>=|<|>)?\s*(.+?)\s*$")
_LEADING_NUMERIC = re.compile(r"^\d+(?:\.\d+)*")
_JAVA_UPDATE = re.compile(r"^(\d+)u(\d+)")
_UNDERSCORE_UPDATE = re.compile(r"^(\d+(?:\.\d+)*)_(\d+)")


def normalize_version(text: str) -> str | None:
    """版の文字列を PEP 440 で読める形にする。読めなければ None。"""
    if text is None:
        return None
    value = unicodedata.normalize("NFKC", str(text)).strip()
    if not value:
        return None
    try:
        Version(value)
        return value
    except InvalidVersion:
        pass
    value = value.lstrip("vV")
    value = re.sub(r"^\d+:", "", value)                 # Debian / RPM の epoch
    match = _JAVA_UPDATE.match(value)                   # 8u392 -> 8.392
    if match:
        return f"{match.group(1)}.{match.group(2)}"
    match = _UNDERSCORE_UPDATE.match(value)             # 1.8.0_392 -> 1.8.0.392
    if match:
        return f"{match.group(1)}.{match.group(2)}"
    match = _LEADING_NUMERIC.match(value)               # 2.3-4ubuntu1 / 3.4.1-amzn-2 / 2.17.1.Final
    if match:
        return match.group(0)
    return None


def parse_version(text: str) -> Version | None:
    normalized = normalize_version(text)
    if normalized is None:
        return None
    try:
        return Version(normalized)
    except InvalidVersion:
        return None


def _normalize_spec(spec: str) -> SpecifierSet | None:
    text = unicodedata.normalize("NFKC", spec).strip()
    clauses = []
    for raw in re.split(r"[,、]", text):
        raw = raw.strip()
        if not raw:
            continue
        match = _CLAUSE.match(raw)
        if not match:
            return None
        operator, version = match.group(1), match.group(2)
        wildcard = version.endswith(".*")
        if wildcard:
            version = version[:-2]
        normalized = normalize_version(version)
        if normalized is None:
            return None
        if wildcard:
            if operator not in (None, "==", "!="):
                return None
            normalized += ".*"
        clauses.append(f"{operator or '=='}{normalized}")
    if not clauses:
        return None
    try:
        return SpecifierSet(",".join(clauses))
    except InvalidSpecifier:
        return None


def version_matches(installed: str, spec: str) -> bool | None:
    """installed が条件 spec に当てはまれば True、外れれば False、比較できなければ None。"""
    specifier = _normalize_spec(spec or "")
    version = parse_version(installed)
    if specifier is None or version is None:
        return None
    return specifier.contains(version, prereleases=True)
