"""PURL（Package URL）の読み取り。ツール内で PURL を読むのはこの関数だけにする。

以前は読み取り関数が2つあり、片方が subpath（Go の `#v2` など）と qualifier を捨てていたため、
同じパッケージが場所によって別の名前になる不具合があった。
"""
from __future__ import annotations

from typing import NamedTuple
from urllib.parse import unquote


class Purl(NamedTuple):
    type: str
    namespace: str
    name: str
    version: str
    qualifiers: dict
    subpath: str

    @property
    def full_name(self) -> str:
        """エコシステムでの正式なパッケージ名（Maven は group:artifact、Go は v2 以降の subpath 付き）。"""
        if self.type == "maven" and self.namespace:
            return f"{self.namespace}:{self.name}"
        if self.type in ("npm", "golang", "composer") and self.namespace:
            full = f"{self.namespace}/{self.name}"
        else:
            full = self.name
        if self.type == "golang" and self.subpath:
            full = f"{full}/{self.subpath}"
        return full


EMPTY = Purl("", "", "", "", {}, "")


def parse_purl(purl: str) -> Purl:
    if not purl or not purl.startswith("pkg:"):
        return EMPTY
    body, _, subpath = purl[4:].partition("#")
    body, _, query = body.partition("?")
    qualifiers = {}
    for pair in query.split("&") if query else []:
        key, _, value = pair.partition("=")
        if key:
            qualifiers[key.lower()] = unquote(value)
    ptype, _, rest = body.partition("/")
    if "@" in rest:
        rest, _, version = rest.rpartition("@")
    else:
        version = ""
    namespace, _, name = rest.rpartition("/")
    return Purl(ptype.lower(), unquote(namespace), unquote(name), unquote(version), qualifiers,
                unquote(subpath).strip("/"))
