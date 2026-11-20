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


def _ecosystem_clause(installed: str, operator: str, version: str, ecosystem: str) -> bool:
    from ..vulndb.versions import compare

    if version.endswith(".*"):
        prefix = version[:-2]
        same = installed == prefix or installed.startswith(prefix + ".") or installed.startswith(prefix + "-")
        if operator in ("", "==", "==="):
            return same
        if operator == "!=":
            return not same
        raise ValueError(operator)
    result = compare(ecosystem, installed, version)
    return {
        "": result == 0, "==": result == 0, "===": result == 0, "!=": result != 0,
        "<": result < 0, "<=": result <= 0, ">": result > 0, ">=": result >= 0,
        "~=": result >= 0,
    }[operator]


def version_matches_in(installed: str, spec: str, ecosystem: str | None) -> bool | None:
    """エコシステム（Maven、Amazon Linux など）の比較規則で版条件を判定する。

    RPM の `1:1.0.2k-24.amzn2.0.10` や Debian の `3.0.2-0ubuntu1.10`、Maven の `2.0-beta9` は
    PEP 440 として正しく比べられないため、エコシステムが分かる場合はこちらを使う。
    """
    if not ecosystem or ecosystem.split(":", 1)[0] == "PyPI":
        return version_matches(installed, spec)
    text = unicodedata.normalize("NFKC", spec or "").strip()
    installed = unicodedata.normalize("NFKC", installed or "").strip()
    if not text or not installed:
        return None
    try:
        for raw in re.split(r"[,、]", text):
            raw = raw.strip()
            if not raw:
                continue
            match = _CLAUSE.match(raw)
            if not match:
                return None
            if not _ecosystem_clause(installed, match.group(1) or "", match.group(2), ecosystem):
                return False
        return True
    except (ValueError, KeyError):
        return version_matches(installed, spec)
