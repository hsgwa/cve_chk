"""エコシステムごとのバージョン比較。

OSV.dev の影響範囲（introduced / fixed など）を評価するために使う。
どれも「a < b なら負、a == b なら 0、a > b なら正」を返す比較関数。
"""
from __future__ import annotations

import re
from functools import cmp_to_key
from typing import Callable

from packaging.version import InvalidVersion, Version

Compare = Callable[[str, str], int]


class UncomparableVersion(ValueError):
    pass


def _sign(value: int) -> int:
    return (value > 0) - (value < 0)


# ---------------------------------------------------------------- Debian (dpkg)

def _dpkg_order(char: str) -> int:
    if char == "~":
        return -1
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _dpkg_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _dpkg_order(a[i]) if i < len(a) else 0
            bc = _dpkg_order(b[j]) if j < len(b) else 0
            if ac != bc:
                return _sign(ac - bc)
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not diff:
                diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if diff:
            return _sign(diff)
    return 0


def _split_dpkg(version: str) -> tuple[int, str, str]:
    version = version.strip()
    epoch = 0
    if ":" in version:
        head, version = version.split(":", 1)
        if not head.isdigit():
            raise UncomparableVersion(head)
        epoch = int(head)
    upstream, _, revision = version.rpartition("-") if "-" in version else (version, "", "")
    return epoch, upstream, revision


def compare_dpkg(a: str, b: str) -> int:
    ea, ua, ra = _split_dpkg(a)
    eb, ub, rb = _split_dpkg(b)
    if ea != eb:
        return _sign(ea - eb)
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


# ---------------------------------------------------------------- RPM

_RPM_SEGMENT = re.compile(r"(\d+|[a-zA-Z]+|~|\^)")


def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    sa, sb = _RPM_SEGMENT.findall(a), _RPM_SEGMENT.findall(b)
    while sa or sb:
        if (sa and sa[0] == "~") or (sb and sb[0] == "~"):
            if not (sa and sa[0] == "~"):
                return 1
            if not (sb and sb[0] == "~"):
                return -1
            sa.pop(0)
            sb.pop(0)
            continue
        if (sa and sa[0] == "^") or (sb and sb[0] == "^"):
            if not sa:
                return -1
            if not sb:
                return 1
            if sa[0] != "^":
                return 1
            if sb[0] != "^":
                return -1
            sa.pop(0)
            sb.pop(0)
            continue
        if not sa or not sb:
            break
        x, y = sa.pop(0), sb.pop(0)
        if x.isdigit() and y.isdigit():
            x, y = x.lstrip("0") or "0", y.lstrip("0") or "0"
            if len(x) != len(y):
                return _sign(len(x) - len(y))
            if x != y:
                return 1 if x > y else -1
        elif x.isdigit():
            return 1
        elif y.isdigit():
            return -1
        elif x != y:
            return 1 if x > y else -1
    if not sa and not sb:
        return 0
    return 1 if sa else -1


def _split_rpm(version: str) -> tuple[int, str, str]:
    version = version.strip()
    epoch = 0
    if ":" in version:
        head, version = version.split(":", 1)
        epoch = int(head) if head.isdigit() else 0
    ver, _, rel = version.partition("-")
    return epoch, ver, rel


def compare_rpm(a: str, b: str) -> int:
    ea, va, ra = _split_rpm(a)
    eb, vb, rb = _split_rpm(b)
    if ea != eb:
        return _sign(ea - eb)
    result = _rpmvercmp(va, vb)
    if result or not ra or not rb:
        return result
    return _rpmvercmp(ra, rb)


# ---------------------------------------------------------------- PyPI

def compare_pypi(a: str, b: str) -> int:
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion as exc:
        raise UncomparableVersion(str(exc)) from exc
    return (va > vb) - (va < vb)


# ---------------------------------------------------------------- semver（npm / Go / crates.io など）

_SEMVER = re.compile(r"^v?(\d+(?:\.\d+)*)(?:-([0-9A-Za-z.\-]+))?(?:\+[0-9A-Za-z.\-]+)?$")


def _prerelease_cmp(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return 1
    if not b:
        return -1
    pa, pb = a.split("."), b.split(".")
    for x, y in zip(pa, pb):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return _sign(int(x) - int(y))
        if x.isdigit():
            return -1
        if y.isdigit():
            return 1
        return 1 if x > y else -1
    return _sign(len(pa) - len(pb))


def compare_semver(a: str, b: str) -> int:
    ma, mb = _SEMVER.match(a.strip()), _SEMVER.match(b.strip())
    if not ma or not mb:
        raise UncomparableVersion(f"{a} / {b}")
    na = [int(x) for x in ma.group(1).split(".")]
    nb = [int(x) for x in mb.group(1).split(".")]
    width = max(len(na), len(nb), 3)
    na += [0] * (width - len(na))
    nb += [0] * (width - len(nb))
    if na != nb:
        return 1 if na > nb else -1
    return _prerelease_cmp(ma.group(2) or "", mb.group(2) or "")


# ---------------------------------------------------------------- Maven（ComparableVersion の簡易実装）

_MAVEN_QUALIFIERS = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "milestone": 2, "m": 2, "rc": 3, "cr": 3,
                     "snapshot": 4, "": 5, "ga": 5, "final": 5, "release": 5, "sp": 6}


def _maven_tokens(version: str) -> list:
    tokens: list = []
    for part in re.split(r"[.\-]", version.lower()):
        for piece in re.findall(r"\d+|[a-z]+", part):
            if piece.isdigit():
                tokens.append((0, int(piece), ""))
            else:
                rank = _MAVEN_QUALIFIERS.get(piece)
                tokens.append((1, rank if rank is not None else 7, piece if rank is None else ""))
    while tokens and tokens[-1] in ((0, 0, ""), (1, 5, "")):
        tokens.pop()
    return tokens


def _maven_item_cmp(x, y) -> int:
    if x is None:
        x = (1, 5, "")        # 何も無い = 正式版
    if y is None:
        y = (1, 5, "")
    if x[0] != y[0]:
        # Maven の ComparableVersion と同じく、同じ位置どうしなら数字の方が常に大きい
        # （例 696.698.v9b42 > 696.v52535。以前は未知の英字を数字より大きく扱っていた）
        return 1 if x[0] == 0 else -1
    if x[1] != y[1]:
        return _sign(x[1] - y[1])
    return (x[2] > y[2]) - (x[2] < y[2])


def compare_maven(a: str, b: str) -> int:
    ta, tb = _maven_tokens(a), _maven_tokens(b)
    for index in range(max(len(ta), len(tb))):
        x = ta[index] if index < len(ta) else None
        y = tb[index] if index < len(tb) else None
        if x is None and y is not None and y[0] == 0:
            x = (0, 0, "")
        if y is None and x is not None and x[0] == 0:
            y = (0, 0, "")
        result = _maven_item_cmp(x, y)
        if result:
            return result
    return 0


# ---------------------------------------------------------------- RubyGems

def compare_rubygems(a: str, b: str) -> int:
    def segments(version: str) -> list:
        result = []
        for piece in re.findall(r"\d+|[a-zA-Z]+", version):
            result.append((1, int(piece), "") if piece.isdigit() else (0, 0, piece))
        while result and result[-1] == (1, 0, ""):
            result.pop()
        return result

    sa, sb = segments(a), segments(b)
    for index in range(max(len(sa), len(sb))):
        x = sa[index] if index < len(sa) else (1, 0, "")
        y = sb[index] if index < len(sb) else (1, 0, "")
        if x != y:
            return 1 if x > y else -1
    return 0


# ---------------------------------------------------------------- Alpine（apk）

_APK = re.compile(r"^(\d+(?:\.\d+)*)([a-z]?\d*)((?:_(?:alpha|beta|pre|rc|cvs|svn|git|hg|p)\d*)*)(?:~[0-9a-f]+)?(?:-r(\d+))?$")
_APK_SUFFIX = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}


def _apk_key(version: str) -> tuple:
    match = _APK.match(version.strip())
    if not match:
        raise UncomparableVersion(version)
    numbers = [int(x) for x in match.group(1).split(".")]
    # 英字の後の数字（openssh の 9.6p1 など）は英字と数字の組として比べる
    letter = re.match(r"([a-z]?)(\d*)", match.group(2))
    letter_key = (letter.group(1), int(letter.group(2) or 0))
    suffixes = [(_APK_SUFFIX[name], int(num or 0))
                for name, num in re.findall(r"_(alpha|beta|pre|rc|cvs|svn|git|hg|p)(\d*)", match.group(3))]
    return numbers, letter_key, suffixes, int(match.group(4) or 0)


def compare_apk(a: str, b: str) -> int:
    """Alpine の版（例 `1.1.1b-r1`、`2.0_rc1-r0`）の比較。-rN はリビジョン、末尾の英字は小さな改版。"""
    na, la, sa, ra = _apk_key(a)
    nb, lb, sb, rb = _apk_key(b)
    width = max(len(na), len(nb))
    na, nb = na + [0] * (width - len(na)), nb + [0] * (width - len(nb))
    if na != nb:
        return 1 if na > nb else -1
    if la != lb:
        return 1 if la > lb else -1
    for index in range(max(len(sa), len(sb))):
        x = sa[index] if index < len(sa) else (0, 0)
        y = sb[index] if index < len(sb) else (0, 0)
        if x != y:
            return 1 if x > y else -1
    return _sign(ra - rb)


# ---------------------------------------------------------------- 汎用

def compare_generic(a: str, b: str) -> int:
    def tokens(version: str) -> list:
        return [(1, int(t), "") if t.isdigit() else (0, 0, t.lower()) for t in re.findall(r"\d+|[a-zA-Z]+", version)]

    ta, tb = tokens(a), tokens(b)
    if not any(t[0] for t in ta) or not any(t[0] for t in tb):
        raise UncomparableVersion(f"{a} / {b}")      # 数字を含まない版は比較しない
    for index in range(max(len(ta), len(tb))):
        x = ta[index] if index < len(ta) else (1, 0, "")
        y = tb[index] if index < len(tb) else (1, 0, "")
        if x != y:
            return 1 if x > y else -1
    return 0


SCHEMES: dict[str, Compare] = {
    "dpkg": compare_dpkg,
    "rpm": compare_rpm,
    "pypi": compare_pypi,
    "semver": compare_semver,
    "maven": compare_maven,
    "rubygems": compare_rubygems,
    "apk": compare_apk,
    "generic": compare_generic,
}


def scheme_for(ecosystem: str) -> str:
    base = ecosystem.split(":", 1)[0]
    if base in ("Debian", "Ubuntu"):
        return "dpkg"
    if base in ("Red Hat", "Rocky Linux", "AlmaLinux", "Amazon Linux", "SUSE", "openSUSE", "Mageia", "openEuler"):
        return "rpm"
    if base == "PyPI":
        return "pypi"
    if base in ("npm", "Go", "crates.io", "Hex", "Pub", "NuGet", "SwiftURL"):
        return "semver"
    if base == "Maven":
        return "maven"
    if base == "RubyGems":
        return "rubygems"
    if base == "Alpine":
        return "apk"
    if base == "Packagist":
        return "semver"
    return "generic"


def compare(ecosystem: str, a: str, b: str) -> int:
    """エコシステムに合った比較。専用の比較で読めなければ汎用の比較を試す。"""
    scheme = scheme_for(ecosystem)
    try:
        return SCHEMES[scheme](a, b)
    except (UncomparableVersion, ValueError):
        if scheme == "generic":
            raise
        return compare_generic(a, b)


def sort_key(ecosystem: str):
    return cmp_to_key(lambda a, b: compare(ecosystem, a, b))
