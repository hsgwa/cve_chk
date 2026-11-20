"""設定ファイル（config.yaml）の読み込み。未指定の項目は既定値を使う。"""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "rank_matrix": [
        {"min_cvss": 9.0, "internet": {"rank": "Rank-S", "days": 3}, "internal": {"rank": "Rank-A", "days": 14}},
        {"min_cvss": 7.0, "internet": {"rank": "Rank-A", "days": 14}, "internal": {"rank": "Rank-B", "days": 30}},
        {"min_cvss": 4.0, "internet": {"rank": "Rank-B", "days": 30}, "internal": {"rank": "Rank-C", "days": 90}},
    ],
    "default_rank": {"rank": "Rank-C", "days": 90},
    "rank_order": ["Rank-S", "Rank-A", "Rank-B", "Rank-C"],
    "cvss_source_priority": ["nvd"],
    "aliases": {},
    "stale_days": 90,
    "scanner": "osv",
    "vulndb": {
        "dir": "vulndb",
        "osv_url": "https://osv-vulnerabilities.storage.googleapis.com",
        "max_age_days": 1,
        "full_refresh_days": 7,
        "max_delta_records": 3000,
        "ubuntu_pro": False,
        "score_sources": ["Debian"],
        "amazon_mirrors": {},
    },
    "trivy": {"path": "", "timeout_sec": 600, "extra_args": []},
    "msrc": {"enabled": True, "timeout_sec": 60, "eol_builds": []},
    "advisory_input": {
        "sheet": "",
        "header_row": 1,
        "fill_merged": False,
        "columns": {
            "advisory_id": ["advisory_id", "通達番号", "通達ID", "社内通達ID", "管理番号", "No", "No."],
            "cve_id": ["cve_id", "CVE番号", "CVE", "CVE-ID", "CVE_ID"],
            "product_name": ["product_name", "製品名", "対象製品", "製品・パッケージ名", "ソフトウェア名"],
            "affected_version": ["affected_version", "影響バージョン", "対象バージョン", "影響を受けるバージョン"],
            "published_date": ["published_date", "公表日", "通達日", "公開日"],
            "company_rank": ["company_rank", "社内ランク", "ランク"],
            "deadline_days": ["deadline_days", "対応期限(日)", "対応期限（日）", "対応期限日数", "期限日数"],
            "note": ["note", "備考"],
        },
    },
}


def _merge(base: dict, override: dict) -> dict:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict) and key not in ("aliases", "amazon_mirrors"):
            _merge(base[key], value)
        elif value is not None:
            base[key] = value
    return base


def load_config(path: str | Path | None) -> dict[str, Any]:
    config = copy.deepcopy(DEFAULT_CONFIG)
    if path:
        with open(path, encoding="utf-8-sig") as fh:
            loaded = yaml.safe_load(fh) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"設定ファイルの形式が正しくありません: {path}")
        _merge(config, loaded)
    return config
