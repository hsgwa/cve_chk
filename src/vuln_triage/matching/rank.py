"""社内ランクと対応期限の計算。"""
from __future__ import annotations

from datetime import date, timedelta
from typing import Any

from ..models import Advisory


def rank_from_matrix(cvss: float | None, exposure: str, config: dict[str, Any]) -> tuple[str, int]:
    """CVSS と公開区分からランクと日数を決める。"""
    exposure = exposure if exposure in ("internet", "internal") else "internal"
    if cvss is not None:
        for row in sorted(config["rank_matrix"], key=lambda r: r["min_cvss"], reverse=True):
            if cvss >= row["min_cvss"]:
                cell = row[exposure]
                return cell["rank"], int(cell["days"])
    default = config["default_rank"]
    return default["rank"], int(default["days"])


def decide_rank(
    advisory: Advisory | None,
    cvss: float | None,
    exposure: str,
    config: dict[str, Any],
    base_date: date,
) -> tuple[str, date, date]:
    """(ランク, 対応期限, 基準日) を返す。通達に記載があればそれを優先する。"""
    rank, days = rank_from_matrix(cvss, exposure, config)
    start = base_date
    if advisory is not None:
        if advisory.company_rank:
            rank = advisory.company_rank
            # 通達がランクだけ指定している場合、日数はそのランクの既定値を使う
            for row in config["rank_matrix"]:
                for cell in (row["internet"], row["internal"]):
                    if cell["rank"] == rank:
                        days = int(cell["days"])
            if config["default_rank"]["rank"] == rank:
                days = int(config["default_rank"]["days"])
        if advisory.deadline_days is not None:
            days = advisory.deadline_days
        if advisory.published_date is not None:
            start = advisory.published_date
    return rank, start + timedelta(days=days), start


def rank_sort_key(rank: str, config: dict[str, Any]) -> int:
    order = config.get("rank_order", [])
    return order.index(rank) if rank in order else len(order)
