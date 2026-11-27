"""CVSS v3.x のベクトル文字列から基本値（Base Score）を計算する。

OSV.dev のデータは点数ではなくベクトル文字列（例 `CVSS:3.1/AV:N/AC:L/...`）で
CVSS を持っていることが多いため、社内ランクの判定に使えるよう点数に直す。
CVSS v4 と v2 のベクトルは扱わない（None を返す）。
"""
from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    """CVSS v3.1 仕様の切り上げ（小数第1位）。"""
    integer = int(round(value * 100000))
    if integer % 10000 == 0:
        return integer / 100000.0
    return (math.floor(integer / 10000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    if not vector or not vector.upper().startswith("CVSS:3."):
        return None
    metrics = {}
    for part in vector.split("/")[1:]:
        key, _, value = part.partition(":")
        metrics[key.upper()] = value.upper()
    try:
        scope_changed = metrics["S"] == "C"
        if metrics["S"] not in ("U", "C"):
            return None
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))
