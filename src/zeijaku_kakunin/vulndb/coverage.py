"""脆弱性データに含まれる「系統」（エコシステム名）の分類。

Ubuntu Pro や Amazon Linux 2 の extras のように、修正情報が通常とは別の系統にしか無いものを見落とした
不具合があった。同じ種類の見落としを防ぐため、取得したデータに現れる系統をすべて、
「照合に使う」か「理由があって使わない」に分類する。どちらにも当てはまらない系統が現れたら
（データ提供元が新しい系統を足したら）update が警告を出す。
"""
from __future__ import annotations

import re

# 照合に使う系統（ecosystems.build_query が問い合わせるもの）
USED = [
    (r"^Ubuntu:\d+\.\d+(:LTS)?$", "Ubuntu の通常の情報"),
    (r"^Ubuntu:Pro:\d+\.\d+(:LTS)?$", "Ubuntu Pro（ESM）。通常の情報が無いときに使う"),
    (r"^Debian:\d+(\.\d+)?$", "Debian の通常の情報"),
    (r"^Red Hat:enterprise_linux:\d+::[a-z0-9_-]+$", "RHEL（9 まで）の通常の情報"),
    (r"^Red Hat:enterprise_linux:\d+\.\d+$", "RHEL（10 から）のマイナー版ごとの通常の情報"),
    (r"^Rocky Linux:\d+(\.\d+)?$", "Rocky Linux"),
    (r"^AlmaLinux:\d+(\.\d+)?$", "AlmaLinux"),
    (r"^Alpine:v\d+\.\d+$", "Alpine"),
    (r"^Amazon Linux:(2|2023)$", "Amazon Linux（2 は core と extras の全トピック）"),
    (r"^(Maven|PyPI|npm|NuGet|Go|crates\.io|RubyGems|Packagist|Hex|Pub)$", "ライブラリ"),
]

# 理由があって使わない系統
EXCLUDED = [
    (r"^Ubuntu:Pro:FIPS(-updates|-preview)?:\d+\.\d+:LTS$", "FIPS 認証版のカーネル・暗号ライブラリ用（FIPS 版を使うホストだけ）"),
    (r"^Ubuntu:Pro:Realtime:\d+\.\d+:LTS$", "リアルタイムカーネル用（Real-time Ubuntu を使うホストだけ）"),
    (r"^Ubuntu:Nvidia-BlueField:\d+\.\d+:LTS$", "NVIDIA BlueField 向け"),
    (r"^Red Hat:(rhel_(eus|e4s|aus|tus|els)[^:]*|enterprise_linux_eus):", "RHEL の延長サポート系統（EUS など）。通常の RHEL は enterprise_linux の情報で判定"),
    (r"^Red Hat:enterprise_linux_nvidia:", "NVIDIA 向けの RHEL"),
    (r"^Red Hat:enterprise_linux:2\.1::", "RHEL 2.1（2009 年にサポート終了）"),
    (r"^Red Hat:(?!enterprise_linux:)[a-z0-9_.-]+:",
     "RHEL の追加製品（OpenShift、JBoss、Satellite など。別契約のリポジトリ）。RHEL を対象にする場合、"
     "これらの製品のパッケージは見落とす（対象外として docs/ROLLOUT.md に記載）"),
    (r"^Red Hat:enterprise_linux:\d+::(realtime|nfv|sap|sap_hana|highavailability|resilientstorage)$",
     "通常の情報（問い合わせには含まれる。リアルタイムカーネルなど特定用途のパッケージ名でだけ当たる）"),
    (r"^(GitHub Actions|SwiftURL|Hackage|GHC|CRAN|Julia|opam|Bitnami|OSS-Fuzz|Linux|GIT|UVI|GSD|VSCode|Root|"
     r"Chainguard|Wolfi|MinimOS|Echo|CleanStart|Docker Hardened Images|BellSoft Hardened Containers|Alpaquita|"
     r"Azure Linux|Mageia|openEuler|openSUSE|SUSE|TuxCare|Red Hat Lightwell)(:|$)",
     "回収データの PURL の種類・OS に対応が無い（照合しない）"),
]


def classify(ecosystem: str) -> tuple[str, str]:
    """("used" | "excluded" | "unknown", 理由)。"""
    for pattern, reason in USED:
        if re.search(pattern, ecosystem):
            return "used", reason
    for pattern, reason in EXCLUDED:
        if re.search(pattern, ecosystem):
            return "excluded", reason
    return "unknown", "分類されていない系統（データ提供元が新しく追加した可能性。見落としにつながらないか確認が必要）"


def unknown_ecosystems(ecosystems) -> list[str]:
    return sorted({e for e in ecosystems if classify(e)[0] == "unknown"})
