"""設定ファイル（config.yaml）の読み込み。未指定の項目は既定値を使う。"""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "cvss_source_priority": ["nvd"],
    "stale_days": 90,
    "xlsx_max_rows": 100000,
    "scanner": "osv",
    "vulndb": {
        "dir": "vulndb",
        "osv_url": "https://osv-vulnerabilities.storage.googleapis.com",
        "max_age_days": 1,
        "full_refresh_days": 7,
        "max_delta_records": 3000,
        "score_sources": [],           # CVSS を引くために一緒に取るデータ（レポートには CVSS を出さないので既定は無し）
        "amazon_mirrors": {},
        "amazon_extras": "all",
    },
    "trivy": {"path": "", "timeout_sec": 600, "extra_args": []},
    "msrc": {"enabled": True, "timeout_sec": 60, "eol_builds": []},
}


def _merge(base: dict, override: dict) -> dict:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict) and key != "amazon_mirrors":
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
