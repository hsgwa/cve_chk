"""ツール全体で使うデータ構造。"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# 影響有無の値
AFFECTED = "影響あり"
AFFECTED_UNCOMPARABLE = "影響あり（比較不能）"
NOT_AFFECTED = "影響なし"
NOT_APPLICABLE = "対象外"        # Windows OS の判定で、この OS の版が CVE の対象に無い（レポートでは影響なしにする）
UNKNOWN = "判定不能"

# コンポーネントの種類。Trivy に渡せるのは PURL を作れるものだけ。
KIND_OS_PACKAGE = "os-package"
KIND_MAVEN = "maven"
KIND_PYPI = "pypi"
KIND_NPM = "npm"
KIND_NUGET = "nuget"
KIND_SOFTWARE = "software"      # インストール済みソフト（レジストリ、winget）
KIND_EXECUTABLE = "executable"  # exe/dll のバージョン情報
KIND_OTHER = "other"


@dataclass
class Component:
    """環境に存在するソフトウェア1件。"""

    name: str
    version: str = ""
    kind: str = KIND_OTHER
    group: str = ""
    purl: str = ""
    path: str = ""
    source: str = ""                      # 取得元（ファイル名やセクション名）
    extra_names: tuple[str, ...] = ()     # 照合に使う別の呼び名
    scannable: bool = False               # 脆弱性データベースで判定できる形（PURL）を持つか
    sbom_file: str = ""                   # 含まれている CycloneDX のファイル名
    checked: bool = False                 # 脆弱性データベースで実際に判定したか
    found_by: str = ""                    # SBOM を作ったツールの検出方法（syft:package:foundBy）


@dataclass
class SectionStatus:
    """収集スクリプトの1項目の結果。"""

    status: str = "ok"     # ok / failed / skipped / missing
    count: int = 0
    reason: str = ""


@dataclass
class EnvInventory:
    """1環境（1ホスト）ぶんの回収結果。"""

    name: str
    os_family: str = "unknown"            # windows / linux / unknown
    os_name: str = ""
    os_id: str = ""                       # ubuntu / amzn / rhel など
    os_version_id: str = ""               # 22.04 / 2 / 2023 など
    os_build: str = ""                    # Windows: 10.0.19045.3803
    emr_release: str = ""
    collected_at: str = ""
    components: list[Component] = field(default_factory=list)
    hotfixes: set[str] | None = None      # None = KB 情報を回収できていない
    sections: dict[str, SectionStatus] = field(default_factory=dict)
    sbom_files: list[Path] = field(default_factory=list)   # Trivy に渡す CycloneDX
    scanned_sboms: int = 0                # Trivy が正常に判定できた SBOM の数
    files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    out_of_scope_running: list[str] = field(default_factory=list)
    incomplete: bool = False
    missing_db: dict[str, int] = field(default_factory=dict)   # データベースが無く判定できなかったエコシステムと件数
    full_collection: bool = False         # SBOM か収集スクリプトの inventory.json があるか

    @property
    def has_inventory(self) -> bool:
        return bool(self.components)

    @property
    def cve_coverage(self) -> bool:
        """脆弱性データベースによる CVE 判定が、少なくとも一部でもできたか。"""
        return self.scanned_sboms > 0 or any(c.checked for c in self.components)


@dataclass
class Finding:
    """脆弱性データベース（OSV / Amazon Linux / Trivy）が検出した1件。"""

    env: str
    cve_id: str                           # CVE 番号（無ければ GHSA などの ID）
    pkg_name: str
    installed_version: str = ""
    fixed_version: str = ""
    path: str = ""
    cvss: float | None = None
    severity: str = ""
    title: str = ""
    sbom: str = ""                        # 取得元（SBOM ファイル名やデータベース名）
    ids: tuple[str, ...] = ()             # CVE・GHSA・ALAS など、この脆弱性のすべての ID
    uncomparable: bool = False            # バージョンを比較できず、安全側で検出扱いにしたもの

    @property
    def all_ids(self) -> set[str]:
        return {i.upper() for i in (self.cve_id, *self.ids) if i}

    @property
    def match_ids(self) -> set[str]:
        """通達の CVE 番号と突き合わせる ID。

        1つの告知（ALAS など）に複数の CVE が載っている場合は CVE ごとに1件にしているので、
        ほかの CVE では突き合わせない（GHSA や ALAS などの CVE 以外の ID は使う）。
        """
        primary = self.cve_id.upper()
        if not primary.startswith("CVE-"):
            return self.all_ids
        return {primary} | {i for i in self.all_ids if not i.startswith("CVE-")}


TrivyFinding = Finding   # 旧名
