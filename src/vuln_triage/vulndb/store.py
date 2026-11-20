"""手元の脆弱性データベースの作成（ダウンロード）と検索。

- OSV.dev がエコシステムごとに公開している all.zip をそのまま保存し、
  パッケージ名から記録を引くための索引を SQLite（Python 標準）に作る。
- Amazon Linux は OSV.dev に無いため、公式リポジトリの updateinfo.xml を
  OSV と同じ形式の zip に変換して同じ仕組みで扱う。
"""
from __future__ import annotations

import bz2
import gzip
import json
import lzma
import re
import shutil
import sqlite3
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from .cvss import cvss3_base_score
from .ecosystems import AMAZON_PREFIX, normalize_package

DEFAULT_OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com"
DEFAULT_AMAZON_MIRRORS = {
    "2": "http://amazonlinux.default.amazonaws.com/2/core/latest/x86_64/mirror.list",
    "2023": "https://al2023-repos-us-east-1-de612dc2.s3.dualstack.us-east-1.amazonaws.com/core/mirrors/latest/x86_64/mirror.list",
}
INDEX_FILE = "index.sqlite"
_CVE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    source TEXT PRIMARY KEY, file TEXT, url TEXT, updated_at TEXT, records INTEGER);
CREATE TABLE IF NOT EXISTS entries (
    ecosystem TEXT, name TEXT, record_id TEXT, file TEXT, member TEXT,
    UNIQUE (ecosystem, name, record_id));
CREATE INDEX IF NOT EXISTS entries_lookup ON entries (name, ecosystem);
CREATE TABLE IF NOT EXISTS scores (
    vuln_id TEXT, source TEXT, score REAL, UNIQUE (vuln_id, source));
"""


class VulnDBError(RuntimeError):
    pass


def _fetch(url: str, timeout: int = 600) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "vuln-triage"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def _download(url: str, dest: Path, fetch: Callable[[str], bytes]) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    temp = dest.with_suffix(dest.suffix + ".part")
    temp.write_bytes(fetch(url))
    temp.replace(dest)


def _decompress(data: bytes) -> bytes:
    for opener in (gzip.decompress, lzma.decompress, bz2.decompress):
        try:
            return opener(data)
        except (OSError, lzma.LZMAError, ValueError, EOFError):
            continue
    return data


def record_ids(record: dict) -> list[str]:
    ids = [str(record.get("id") or "")]
    for key in ("aliases", "upstream"):
        ids.extend(str(i) for i in record.get(key) or [])
    return [i for i in dict.fromkeys(ids) if i]


def record_scores(record: dict) -> list[tuple[str, str, float]]:
    """(脆弱性 ID, ソース名, CVSS v3 の点数) の一覧。ソース名は記録 ID の接頭辞（ghsa, ubuntu など）。"""
    record_id = str(record.get("id") or "")
    source = record_id.split("-", 1)[0].lower() or "osv"
    scores = []
    for severity in record.get("severity") or []:
        if not isinstance(severity, dict) or severity.get("type") != "CVSS_V3":
            continue
        score = cvss3_base_score(str(severity.get("score") or ""))
        if score is None:
            continue
        for vuln_id in record_ids(record):
            scores.append((vuln_id.upper(), source, score))
    return scores


class VulnDB:
    def __init__(self, db_dir: str | Path, config: dict[str, Any] | None = None,
                 fetch: Callable[[str], bytes] | None = None, log: Callable[[str], None] = lambda m: None):
        self.dir = Path(db_dir)
        self.settings = (config or {}).get("vulndb") or {}
        self.fetch = fetch or (lambda url: _fetch(url))
        self.log = log
        self._conn: sqlite3.Connection | None = None
        self._zips: dict[str, zipfile.ZipFile] = {}
        # 読んだ記録の一時保管（同じソースパッケージの照合で使い回す）。メモリを使いすぎないよう件数を絞る
        self._records: OrderedDict[tuple[str, str], dict | None] = OrderedDict()
        self._cache_size = 256

    # ------------------------------------------------------------ 共通

    @property
    def index_path(self) -> Path:
        return self.dir / INDEX_FILE

    def exists(self) -> bool:
        return self.index_path.is_file()

    def connect(self) -> sqlite3.Connection:
        if self._conn is None:
            self.dir.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(self.index_path)
            self._conn.executescript(_SCHEMA)
        return self._conn

    def close(self) -> None:
        for archive in self._zips.values():
            archive.close()
        self._zips.clear()
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def sources(self) -> dict[str, dict[str, Any]]:
        if not self.exists():
            return {}
        rows = self.connect().execute("SELECT source, file, url, updated_at, records FROM sources")
        return {r[0]: {"file": r[1], "url": r[2], "updated_at": r[3], "records": r[4]} for r in rows}

    # ------------------------------------------------------------ 作成

    def _index_zip(self, source: str, relative: str, url: str) -> int:
        conn = self.connect()
        conn.execute("DELETE FROM entries WHERE file = ?", (relative,))
        count = 0
        with zipfile.ZipFile(self.dir / relative) as archive:
            batch, scores = [], []
            for member in archive.namelist():
                if not member.endswith(".json"):
                    continue
                try:
                    record = json.loads(archive.read(member))
                except ValueError:
                    continue
                if record.get("withdrawn"):
                    continue
                record_id = str(record.get("id") or member)
                for affected in record.get("affected") or []:
                    package = affected.get("package") or {}
                    ecosystem, name = package.get("ecosystem"), package.get("name")
                    if ecosystem and name:
                        batch.append((ecosystem, normalize_package(ecosystem, name), record_id, relative, member))
                scores.extend(record_scores(record))
                count += 1
                if len(batch) > 20000:
                    conn.executemany("INSERT OR IGNORE INTO entries VALUES (?, ?, ?, ?, ?)", batch)
                    batch.clear()
            conn.executemany("INSERT OR IGNORE INTO entries VALUES (?, ?, ?, ?, ?)", batch)
            conn.executemany("INSERT OR REPLACE INTO scores VALUES (?, ?, ?)", scores)
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        conn.execute("INSERT OR REPLACE INTO sources VALUES (?, ?, ?, ?, ?)", (source, relative, url, now, count))
        conn.commit()
        return count

    def update_osv(self, ecosystem: str) -> int:
        base = self.settings.get("osv_url") or DEFAULT_OSV_URL
        url = f"{base.rstrip('/')}/{urllib.parse.quote(ecosystem)}/all.zip"
        relative = f"osv/{ecosystem}.zip"
        self.log(f"ダウンロード中: {ecosystem}（{url}）")
        _download(url, self.dir / relative, self.fetch)
        count = self._index_zip(ecosystem, relative, url)
        self.log(f"  {ecosystem}: {count} 件")
        return count

    def _amazon_repo(self, release: str) -> tuple[str, bytes]:
        mirrors = {**DEFAULT_AMAZON_MIRRORS, **(self.settings.get("amazon_mirrors") or {})}
        if release not in mirrors:
            raise VulnDBError(f"Amazon Linux {release} のリポジトリ URL が設定されていません（vulndb.amazon_mirrors）")
        mirror_list = mirrors[release]
        bases = [line.strip() for line in self.fetch(mirror_list).decode("utf-8").splitlines() if line.strip()]
        # ミラー一覧と同じホストにも同じパスがある（CDN に届かない環境向け）
        list_host = urllib.parse.urlsplit(mirror_list)
        for base in list(bases):
            parts = urllib.parse.urlsplit(base)
            alternative = urllib.parse.urlunsplit((list_host.scheme, list_host.netloc, parts.path, "", ""))
            if alternative not in bases:
                bases.append(alternative)
        errors = []
        for base in bases:
            base = base.rstrip("/") + "/"
            try:
                repomd = self.fetch(base + "repodata/repomd.xml").decode("utf-8")
                match = re.search(r'type="updateinfo".*?href="([^"]+)"', repomd, re.S)
                if not match:
                    raise VulnDBError("repomd.xml に updateinfo がありません")
                url = base + match.group(1)
                return url, _decompress(self.fetch(url))
            except Exception as exc:          # 次のミラーを試す
                errors.append(f"{base}: {exc}")
        raise VulnDBError("Amazon Linux のリポジトリに接続できません: " + " / ".join(errors))

    @staticmethod
    def amazon_records(xml_text: bytes, release: str) -> Iterable[dict]:
        """updateinfo.xml を OSV 形式の記録に変換する。"""
        ecosystem = f"{AMAZON_PREFIX}{release}"
        root = ET.fromstring(xml_text)
        for update in root.iter("update"):
            advisory_id = (update.findtext("id") or "").strip()
            if not advisory_id:
                continue
            fixed: dict[str, str] = {}
            for package in update.iter("package"):
                name = package.get("name")
                if not name or package.get("arch") == "src":
                    continue
                epoch = package.get("epoch") or "0"
                version = f"{package.get('version')}-{package.get('release')}"
                fixed[name] = version if epoch == "0" else f"{epoch}:{version}"
            cves = [r.get("id") for r in update.iter("reference") if r.get("type") == "cve" and r.get("id")]
            yield {
                "id": advisory_id,
                "aliases": list(dict.fromkeys(cves)),
                "summary": (update.findtext("title") or "").strip(),
                "published": (update.find("issued").get("date") if update.find("issued") is not None else ""),
                "database_specific": {"severity": (update.findtext("severity") or "").strip().lower()},
                "affected": [
                    {"package": {"ecosystem": ecosystem, "name": name},
                     "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": version}]}]}
                    for name, version in sorted(fixed.items())
                ],
            }

    def update_amazon(self, release: str) -> int:
        source = f"{AMAZON_PREFIX}{release}"
        self.log(f"ダウンロード中: {source}（公式リポジトリの updateinfo）")
        url, xml_text = self._amazon_repo(release)
        relative = f"amazon/amazon-linux-{release}.zip"
        target = self.dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_suffix(".zip.part")
        with zipfile.ZipFile(temp, "w", zipfile.ZIP_DEFLATED) as archive:
            for record in self.amazon_records(xml_text, release):
                archive.writestr(f"{record['id']}.json", json.dumps(record, ensure_ascii=False))
        temp.replace(target)
        count = self._index_zip(source, relative, url)
        self.log(f"  {source}: {count} 件")
        return count

    def update(self, sources: Iterable[str]) -> dict[str, str]:
        """データを取得する。戻り値は {データ名: エラー内容}（成功したものは含まない）。"""
        errors = {}
        for source in sources:
            try:
                if source.startswith(AMAZON_PREFIX):
                    self.update_amazon(source[len(AMAZON_PREFIX):])
                else:
                    self.update_osv(source)
            except Exception as exc:
                errors[source] = str(exc)
                self.log(f"  失敗: {source}: {exc}")
        return errors

    def import_zip(self, source: str, path: str | Path, url: str = "") -> int:
        """手元にある OSV 形式の zip を取り込む（ネットに出られない場合や試験用）。"""
        relative = f"osv/{source}.zip" if not source.startswith(AMAZON_PREFIX) else \
            f"amazon/amazon-linux-{source[len(AMAZON_PREFIX):]}.zip"
        target = self.dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if Path(path).resolve() != target.resolve():
            shutil.copyfile(path, target)
        return self._index_zip(source, relative, url or str(path))

    # ------------------------------------------------------------ 検索

    def lookup(self, ecosystems: tuple[str, ...], names: tuple[str, ...]) -> Iterator[tuple[str, dict]]:
        """(エコシステム, 記録) を1件ずつ返す（大量の記録を一度にメモリへ載せない）。"""
        conn = self.connect()
        seen: set[str] = set()
        for name in names:
            for ecosystem in ecosystems:
                operator = "LIKE" if ecosystem.endswith("%") else "="
                rows = conn.execute(
                    f"SELECT ecosystem, record_id, file, member FROM entries WHERE name = ? AND ecosystem {operator} ?",
                    (name, ecosystem)).fetchall()
                for row_ecosystem, record_id, file, member in rows:
                    if record_id in seen:
                        continue
                    seen.add(record_id)
                    record = self._read(file, member)
                    if record is not None:
                        yield row_ecosystem, record

    def _read(self, file: str, member: str) -> dict | None:
        key = (file, member)
        if key in self._records:
            self._records.move_to_end(key)
            return self._records[key]
        if True:
            archive = self._zips.get(file)
            if archive is None:
                path = self.dir / file
                if not path.is_file():
                    raise VulnDBError(f"データベースのファイルがありません: {path}（db-update をやり直してください）")
                archive = self._zips[file] = zipfile.ZipFile(path)
            try:
                record = json.loads(archive.read(member))
            except (KeyError, ValueError):
                record = None
            self._records[key] = record
            if len(self._records) > self._cache_size:
                self._records.popitem(last=False)
        return record

    def scores(self, vuln_ids: Iterable[str]) -> dict[str, float]:
        """{ソース名: CVSS v3 の点数}。同じソースに複数あれば最大値。"""
        conn = self.connect()
        result: dict[str, float] = {}
        for vuln_id in vuln_ids:
            for source, score in conn.execute("SELECT source, score FROM scores WHERE vuln_id = ?", (vuln_id.upper(),)):
                result[source] = max(result.get(source, 0.0), score)
        return result
