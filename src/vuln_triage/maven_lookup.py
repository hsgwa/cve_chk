"""jar の SHA-1 から Maven の座標（groupId / artifactId / version）を調べる（任意機能）。

pom.properties を持たず groupId が分からない jar は Trivy に渡せないため、
Maven Central のハッシュ検索で特定する。送信するのはハッシュ値だけ。
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from .models import KIND_MAVEN, EnvInventory

SEARCH = "https://search.maven.org/solrsearch/select"


def _search(sha1: str, timeout: int = 30) -> dict | None:
    query = urllib.parse.urlencode({"q": f'1:"{sha1}"', "rows": 1, "wt": "json"})
    request = urllib.request.Request(f"{SEARCH}?{query}", headers={"User-Agent": "vuln-triage"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        docs = json.loads(response.read().decode("utf-8"))["response"]["docs"]
    if not docs:
        return None
    return {"group": docs[0].get("g", ""), "artifact": docs[0].get("a", ""), "version": docs[0].get("v", "")}


def resolve_hashes(envs: list[EnvInventory], cache_file: str | Path, search=_search) -> tuple[int, str | None]:
    """groupId の無い jar を SHA-1 で特定する。(特定できた件数, エラー) を返す。"""
    cache_path = Path(cache_file)
    cache: dict[str, dict | None] = {}
    if cache_path.is_file():
        try:
            cache = json.loads(cache_path.read_text(encoding="utf-8"))
        except ValueError:
            cache = {}
    resolved, error = 0, None
    for env in envs:
        for component in env.components:
            if component.kind != KIND_MAVEN or component.group or component.scannable:
                continue
            sha1 = next((n[5:] for n in component.extra_names if n.startswith("sha1:")), "")
            if not sha1:
                continue
            if sha1 not in cache and error is None:
                try:
                    cache[sha1] = search(sha1)
                except (urllib.error.URLError, OSError, ValueError, KeyError, TimeoutError) as exc:
                    error = f"Maven Central に問い合わせできませんでした（{exc}）"
            found = cache.get(sha1)
            if found and found.get("group"):
                component.group = found["group"]
                component.name = found["artifact"] or component.name
                component.version = found["version"] or component.version
                resolved += 1
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(cache, ensure_ascii=False, indent=1), encoding="utf-8")
    return resolved, error
