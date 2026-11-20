"""製品名とコンポーネント名の照合。"""
from __future__ import annotations

import fnmatch
import re
import unicodedata
from pathlib import PureWindowsPath
from typing import Callable

from ..models import Component


def normalize_name(text: str) -> str:
    value = unicodedata.normalize("NFKC", str(text or "")).strip().lower()
    return re.sub(r"[_.\s]+", "-", value)


def candidate_names(component: Component) -> set[str]:
    """コンポーネントが持ちうる呼び名（正規化済み）。"""
    raw: set[str] = {component.name, *component.extra_names}
    if component.group:
        raw.add(f"{component.group}:{component.name}")
        raw.add(f"{component.group}/{component.name}")
    if component.kind == "software" and "." in component.name and " " not in component.name:
        raw.add(component.name.rsplit(".", 1)[-1])          # winget ID の末尾
    if component.kind == "executable" and component.path:
        raw.add(PureWindowsPath(component.path).stem)
    return {normalize_name(name) for name in raw if name}


def build_matcher(product_name: str, aliases: dict[str, list[str]] | None = None) -> Callable[[Component], bool]:
    """通達の製品名から、コンポーネントが該当するかを返す関数を作る。

    - `re:` で始まれば正規表現（大文字小文字を無視、元の名前に対して検索）
    - `*` や `?` を含めばワイルドカード
    - それ以外は正規化した完全一致（別名辞書も使う）
    """
    text = unicodedata.normalize("NFKC", product_name or "").strip()
    if text.lower().startswith("re:"):
        pattern = re.compile(text[3:].strip(), re.IGNORECASE)

        def match_regex(component: Component) -> bool:
            names = {component.name, *component.extra_names}
            if component.group:
                names.add(f"{component.group}:{component.name}")
            return any(pattern.search(name) for name in names if name)

        return match_regex

    targets = {normalize_name(text)}
    for canonical, others in (aliases or {}).items():
        group = {normalize_name(canonical), *(normalize_name(o) for o in others or [])}
        if targets & group:
            targets |= group

    if any(ch in text for ch in "*?"):
        def match_glob(component: Component) -> bool:
            names = candidate_names(component)
            return any(fnmatch.fnmatchcase(name, target) for name in names for target in targets)

        return match_glob

    return lambda component: bool(candidate_names(component) & targets)
