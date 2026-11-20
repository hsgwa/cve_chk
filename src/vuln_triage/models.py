"""ツール全体で使うデータ構造。"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

# 影響有無の値
AFFECTED = "影響あり"
AFFECTED_UNCOMPARABLE = "影響あり（比較不能）"
NOT_AFFECTED = "影響なし"
NOT_DETECTED = "影響なし（CVE未検出）"
UNUSED = "未使用"
NOT_APPLICABLE = "対象外"
UNKNOWN = "判定不能"

AFFECTED_STATUSES = (AFFECTED, AFFECTED_UNCOMPARABLE)
NOT_AFFECTED_STATUSES = (NOT_AFFECTED, NOT_DETECTED)

# コンポーネントの種類。Trivy に渡せるのは PURL を作れるものだけ。
KIND_OS_PACKAGE = "os-package"
KIND_MAVEN = "maven"
KIND_PYPI = "pypi"
KIND_NPM = "npm"
KIND_NUGET = "nuget"
KIND_SOFTWARE = "software"      # インストール済みソフト（レジストリ、winget）
KIND_EXECUTABLE = "executable"  # exe/dll のバージョン情報
KIND_CUSTOM = "custom"          # 個別製品の版取得
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
    scannable: bool = False               # Trivy が判定できる SBOM に含まれるか


@dataclass
class SectionStatus:
    """収集スクリプトの1項目の結果。"""

    status: str = "ok"     # ok / failed / skipped / missing
    count: int = 0
    reason: str = ""


@dataclass
class FailedProbe:
    """個別製品の版取得で、エラーになったもの。"""

    name: str
    reason: str = ""


@dataclass
class EnvInventory:
    """1環境（1ホスト）ぶんの回収結果。"""

    name: str
    exposure: str = "internal"
    system_name: str = ""
    registered: bool = False
    os_family: str = "unknown"            # windows / linux / unknown
    os_name: str = ""
    os_build: str = ""                    # Windows: 10.0.19045.3803
    emr_release: str = ""
    collected_at: str = ""
    components: list[Component] = field(default_factory=list)
    hotfixes: set[str] | None = None      # None = KB 情報を回収できていない
    sections: dict[str, SectionStatus] = field(default_factory=dict)
    failed_probes: list[FailedProbe] = field(default_factory=list)
    sbom_files: list[Path] = field(default_factory=list)   # Trivy に渡す CycloneDX
    scanned_sboms: int = 0                # Trivy が正常に判定できた SBOM の数
    files: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unreadable: list[str] = field(default_factory=list)
    out_of_scope_running: list[str] = field(default_factory=list)
    incomplete: bool = False
    full_collection: bool = False         # SBOM か収集スクリプトの inventory.json があるか

    @property
    def has_inventory(self) -> bool:
        return bool(self.components)

    @property
    def cve_coverage(self) -> bool:
        """Trivy による CVE 判定が、少なくとも1つの SBOM に対してできたか。"""
        return self.scanned_sboms > 0


@dataclass
class Advisory:
    """会社公表リストの1行（1セルに複数 CVE がある場合は CVE ごとに1件）。"""

    advisory_id: str
    cve_id: str = ""
    product_name: str = ""
    affected_version: str = ""
    published_date: date | None = None
    company_rank: str = ""
    deadline_days: int | None = None
    note: str = ""
    row: int = 0

    @property
    def is_kb(self) -> bool:
        return self.affected_version.strip().lower() == "missing"

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.advisory_id, self.cve_id, self.product_name)


@dataclass
class TrivyFinding:
    env: str
    cve_id: str
    pkg_name: str
    installed_version: str = ""
    fixed_version: str = ""
    path: str = ""
    cvss: float | None = None
    severity: str = ""
    title: str = ""
    sbom: str = ""


@dataclass
class Verdict:
    """通達 × 環境（× パッケージ）の判定結果1行。"""

    status: str
    env: str = ""
    exposure: str = ""
    category: str = ""        # 判定区分
    cve_id: str = ""
    advisory_id: str = ""
    package: str = ""
    version: str = ""
    condition: str = ""       # 影響条件 / 修正バージョン
    path: str = ""
    cvss: float | None = None
    rank: str = ""
    deadline: date | None = None
    base_date: date | None = None
    note: str = ""
    advisory: Advisory | None = None

    @property
    def affected(self) -> bool:
        return self.status in AFFECTED_STATUSES
