"""手元の脆弱性データベースの作成（ダウンロード）と検索。

- OSV.dev がエコシステムごとに公開している all.zip をそのまま保存し、
  パッケージ名から記録を引くための索引を SQLite（Python 標準）に作る。
- Amazon Linux は OSV.dev に無いため、公式リポジトリの updateinfo.xml を
  OSV と同じ形式の zip に変換して同じ仕組みで扱う。
- 2 回目以降の更新は差分で行う。OSV.dev が公開している modified_id.csv（更新日時と記録 ID の一覧）で
  前回より新しい記録だけを1件ずつ取り直し、SQLite に保存する。一定日数ごとに全件を取り直す。
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
import zlib
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from .cvss import cvss3_base_score
from .ecosystems import AMAZON_PREFIX, normalize_package

DEFAULT_OSV_URL = "https://osv-vulnerabilities.storage.googleapis.com"
DEFAULT_AMAZON_MIRRORS = {
    "2": "http://amazonlinux.default.amazonaws.com/2/core/latest/x86_64/mirror.list",
    "2023": "https://al2023-repos-us-east-1-de612dc2.s3.dualstack.us-east-1.amazonaws.com/core/mirrors/latest/x86_64/mirror.list",
}
# Amazon Linux 2 の extras（kernel-5.10 などのトピック）。修正情報は core と別の updateinfo にある
DEFAULT_AL2_EXTRAS_BASE = "http://amazonlinux.default.amazonaws.com/2"
EXTRAS_PREFIX = f"{AMAZON_PREFIX}2:extras:"
INDEX_FILE = "index.sqlite"
_CVE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

DELTA_FILE = "#delta"     # 差分更新で取った記録（records テーブルに保存）を表す entries.file の値

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
    source TEXT PRIMARY KEY, file TEXT, url TEXT, updated_at TEXT, records INTEGER);
CREATE TABLE IF NOT EXISTS records (record_id TEXT PRIMARY KEY, data TEXT);
CREATE TABLE IF NOT EXISTS entries (
    ecosystem TEXT, name TEXT, record_id TEXT, file TEXT, member TEXT,
    UNIQUE (ecosystem, name, record_id));
CREATE INDEX IF NOT EXISTS entries_lookup ON entries (name, ecosystem);
CREATE TABLE IF NOT EXISTS scores (
    vuln_id TEXT, source TEXT, score REAL, UNIQUE (vuln_id, source));
CREATE TABLE IF NOT EXISTS slim (record_id TEXT PRIMARY KEY, data BLOB);
"""

# 大きな記録（Ubuntu のカーネルの CVE は 1 件 0.5 MB 前後。カーネルの系統ごとに 277 項目が並ぶ）は、
# 照合に使う項目だけを残した縮小版を zlib で圧縮して索引に入れる。照合ではまずこちらを読む
# （1 環境の照合が 5 分以上かかり、その 6 割が JSON の読み込みだった）。
SLIM_MIN_BYTES = 64 * 1024


def slim_record(record: dict) -> dict:
    """照合に使う項目だけを残した記録。

    - 記録: id、aliases、upstream、summary、database_specific の severity / informational / topic
    - affected の各項目: package、ranges、database_specific の informational。
      versions（影響のある版の列挙）は、ECOSYSTEM / SEMVER の範囲が無い項目だけ残す（範囲があれば判定に足りる）
    - 捨てるもの: details、references、ecosystem_specific（バイナリパッケージの一覧）など
    """
    out = {k: record[k] for k in ("id", "aliases", "upstream", "summary") if k in record}
    specific = record.get("database_specific") or {}
    out["database_specific"] = {k: specific[k] for k in ("severity", "informational", "topic") if k in specific}
    affected_items = []
    for affected in record.get("affected") or []:
        item = {k: affected[k] for k in ("package", "ranges") if k in affected}
        if not any((r or {}).get("type") in ("ECOSYSTEM", "SEMVER") for r in affected.get("ranges") or []):
            if affected.get("versions"):
                item["versions"] = affected["versions"]
        informational = (affected.get("database_specific") or {}).get("informational")
        if informational:
            item["database_specific"] = {"informational": informational}
        affected_items.append(item)
    out["affected"] = affected_items
    return out


def _slim_blob(record: dict) -> bytes:
    return zlib.compress(json.dumps(slim_record(record), ensure_ascii=False, separators=(",", ":")).encode("utf-8"))


# 後から足した sources の列（古い DB は開いたときに追加する）
_SOURCE_COLUMNS = {"cursor": "TEXT", "full_at": "TEXT", "checksum": "TEXT"}


class VulnDBError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(text: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None


def _time_key(text: str) -> tuple[str, int]:
    """modified_id.csv の日時（小数部の桁数がまちまち）を正しく比べるためのキー。"""
    text = text.strip().rstrip("Z")
    base, _, fraction = text.partition(".")
    return base, int((fraction + "000000000")[:9] or 0)


def parse_modified_ids(text: str, since: str | None) -> tuple[str, list[str]]:
    """modified_id.csv から (最新の日時, since より新しい記録 ID の一覧) を返す。"""
    latest = ""
    ids: list[str] = []
    since_key = _time_key(since) if since else None
    for line in text.splitlines():
        stamp, _, record_id = line.strip().partition(",")
        if not stamp:
            continue
        key = _time_key(stamp)
        if not latest or key > _time_key(latest):
            latest = stamp
        if record_id and (since_key is None or key > since_key):
            ids.append(record_id.strip())
    return latest, list(dict.fromkeys(ids))


def _fetch(url: str, timeout: int = 600) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "zeijaku-kakunin"})
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
        # 読んだ記録の一時保管（同じソースパッケージの照合で使い回す）。メモリを使いすぎないよう件数を絞る（Ubuntu のカーネルの記録は 1 件 0.5 MB 前後）
        self._records: OrderedDict[tuple[str, str], dict | None] = OrderedDict()
        self._cache_size = 256
        self._slim_cache: OrderedDict[str, dict] = OrderedDict()   # 縮小版は 1 件 50 KB 前後なので多めに持つ
        self._has_slim: bool | None = None

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
            columns = {row[1] for row in self._conn.execute("PRAGMA table_info(sources)")}
            for name, kind in _SOURCE_COLUMNS.items():
                if name not in columns:
                    self._conn.execute(f"ALTER TABLE sources ADD COLUMN {name} {kind}")
            self._conn.commit()
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
        rows = self.connect().execute(
            "SELECT source, file, url, updated_at, records, cursor, full_at, checksum FROM sources")
        return {r[0]: {"file": r[1], "url": r[2], "updated_at": r[3], "records": r[4],
                       "cursor": r[5], "full_at": r[6], "checksum": r[7]} for r in rows}

    def _save_source(self, source: str, **values: Any) -> None:
        conn = self.connect()
        conn.execute("INSERT OR IGNORE INTO sources (source) VALUES (?)", (source,))
        for key, value in values.items():
            conn.execute(f"UPDATE sources SET {key} = ? WHERE source = ?", (value, source))

    # ------------------------------------------------------------ 作成

    def _index_zip(self, source: str, relative: str, url: str, **extra: Any) -> int:
        conn = self.connect()
        conn.execute("DELETE FROM entries WHERE file = ?", (relative,))
        count = 0
        record_ids_in_zip: list[str] = []
        with zipfile.ZipFile(self.dir / relative) as archive:
            batch, scores, slims = [], [], []
            big_ids: set[str] = set()
            for member in archive.namelist():
                if not member.endswith(".json"):
                    continue
                raw = archive.read(member)
                try:
                    record = json.loads(raw)
                except ValueError:
                    continue
                if record.get("withdrawn"):
                    continue
                record_id = str(record.get("id") or member)
                record_ids_in_zip.append(record_id)
                for affected in record.get("affected") or []:
                    package = affected.get("package") or {}
                    ecosystem, name = package.get("ecosystem"), package.get("name")
                    if ecosystem and name:
                        batch.append((ecosystem, normalize_package(ecosystem, name), record_id, relative, member))
                scores.extend(record_scores(record))
                if len(raw) >= SLIM_MIN_BYTES:
                    slims.append((record_id, _slim_blob(record)))
                    big_ids.add(record_id)
                count += 1
                if len(slims) > 2000:
                    conn.executemany("INSERT OR REPLACE INTO slim VALUES (?, ?)", slims)
                    slims.clear()
                if len(batch) > 20000:
                    conn.executemany("INSERT OR REPLACE INTO entries VALUES (?, ?, ?, ?, ?)", batch)
                    batch.clear()
            conn.executemany("INSERT OR REPLACE INTO entries VALUES (?, ?, ?, ?, ?)", batch)
            conn.executemany("INSERT OR REPLACE INTO scores VALUES (?, ?, ?)", scores)
        # 全件を取り直したので、差分で取っていた同じ記録は不要（zip の方が新しい）
        for start in range(0, len(record_ids_in_zip), 500):
            chunk = record_ids_in_zip[start:start + 500]
            marks = ",".join("?" * len(chunk))
            conn.execute(f"DELETE FROM entries WHERE file = ? AND record_id IN ({marks})", (DELTA_FILE, *chunk))
            conn.execute(f"DELETE FROM records WHERE record_id IN ({marks})", chunk)
        # 縮小版: この zip の記録の古い縮小版を消してから入れ直す（小さくなった記録の縮小版を残さない）
        small = [rid for rid in record_ids_in_zip if rid not in big_ids]
        for start in range(0, len(small), 500):
            chunk = small[start:start + 500]
            conn.execute(f"DELETE FROM slim WHERE record_id IN ({','.join('?' * len(chunk))})", chunk)
        conn.executemany("INSERT OR REPLACE INTO slim VALUES (?, ?)", slims)
        now = _now()
        self._save_source(source, file=relative, url=url, updated_at=now, records=count, full_at=now, **extra)
        conn.commit()
        return count

    @staticmethod
    def _relative_file(source: str) -> str:
        """データの保存先（vulndb/ からの相対パス）。Windows で使えない文字（: など）は含めない。"""
        if source.startswith(EXTRAS_PREFIX):
            name = f"amazon-linux-2-extras-{source[len(EXTRAS_PREFIX):]}"
        elif source.startswith(AMAZON_PREFIX):
            name = f"amazon-linux-{source[len(AMAZON_PREFIX):]}"
        else:
            return "osv/" + re.sub(r'[<>:"/\\|?*]', "_", source) + ".zip"
        return "amazon/" + re.sub(r'[<>:"/\\|?*]', "_", name) + ".zip"

    def _osv_url(self, ecosystem: str, name: str) -> str:
        base = self.settings.get("osv_url") or DEFAULT_OSV_URL
        return f"{base.rstrip('/')}/{urllib.parse.quote(ecosystem)}/{urllib.parse.quote(name)}"

    def _apply_records(self, records: list[dict]) -> None:
        """差分で取った記録を入れ直す（同じ ID の古い索引はファイルを問わず消す）。"""
        conn = self.connect()
        for record in records:
            record_id = str(record.get("id") or "")
            if not record_id:
                continue
            conn.execute("DELETE FROM entries WHERE record_id = ?", (record_id,))
            conn.execute("DELETE FROM slim WHERE record_id = ?", (record_id,))
            self._slim_cache.pop(record_id, None)
            if record.get("withdrawn"):
                conn.execute("DELETE FROM records WHERE record_id = ?", (record_id,))
                continue
            data = json.dumps(record, ensure_ascii=False)
            conn.execute("INSERT OR REPLACE INTO records VALUES (?, ?)", (record_id, data))
            if len(data.encode("utf-8")) >= SLIM_MIN_BYTES:
                conn.execute("INSERT OR REPLACE INTO slim VALUES (?, ?)", (record_id, _slim_blob(record)))
            rows = []
            for affected in record.get("affected") or []:
                package = affected.get("package") or {}
                ecosystem, name = package.get("ecosystem"), package.get("name")
                if ecosystem and name:
                    rows.append((ecosystem, normalize_package(ecosystem, name), record_id, DELTA_FILE, record_id))
            conn.executemany("INSERT OR REPLACE INTO entries VALUES (?, ?, ?, ?, ?)", rows)
            conn.executemany("INSERT OR REPLACE INTO scores VALUES (?, ?, ?)", record_scores(record))
            self._records.pop((DELTA_FILE, record_id), None)

    def _needs_full(self, info: dict[str, Any] | None, force_full: bool) -> bool:
        if force_full or not info or not info.get("cursor") or not info.get("full_at"):
            return True
        if not (self.dir / str(info.get("file") or "")).is_file():
            return True
        full_at = _parse_time(info["full_at"])
        days = int(self.settings.get("full_refresh_days") or 7)
        return full_at is None or datetime.now(timezone.utc) - full_at >= timedelta(days=days)

    def update_osv(self, ecosystem: str, force_full: bool = False) -> str:
        """OSV.dev のデータを更新する。戻り値は結果の説明（「全件 n 件」「差分 n 件」など）。"""
        info = self.sources().get(ecosystem)
        csv_url = self._osv_url(ecosystem, "modified_id.csv")
        if not self._needs_full(info, force_full):
            latest, changed = parse_modified_ids(self.fetch(csv_url).decode("utf-8"), info["cursor"])
            limit = int(self.settings.get("max_delta_records") or 3000)
            if not changed:
                self._save_source(ecosystem, updated_at=_now())
                self.connect().commit()
                return "変更なし"
            if len(changed) <= limit:
                self.log(f"差分を取得中: {ecosystem}（{len(changed)} 件）")
                # すべて取れてから反映する（途中で失敗したら前回の内容のまま）
                records = [json.loads(self.fetch(self._osv_url(ecosystem, f"{rid}.json"))) for rid in changed]
                self._apply_records(records)
                self._save_source(ecosystem, updated_at=_now(), cursor=latest)
                self.connect().commit()
                return f"差分 {len(changed)} 件"
            self.log(f"  変更が {len(changed)} 件と多いため、全件を取り直します")

        # 全件: 先に一覧の最新日時を取っておき、次回はそれより新しいものを差分で取る
        try:
            cursor, _ = parse_modified_ids(self.fetch(csv_url).decode("utf-8"), None)
        except Exception as exc:          # 一覧が無くても全件は取れる（次回も全件になる）
            self.log(f"  変更一覧を取得できません（次回も全件を取得します）: {exc}")
            cursor = None
        url = self._osv_url(ecosystem, "all.zip")
        relative = self._relative_file(ecosystem)
        self.log(f"ダウンロード中: {ecosystem}（{url}）")
        _download(url, self.dir / relative, self.fetch)
        self._close_zip(relative)
        count = self._index_zip(ecosystem, relative, url, cursor=cursor)
        return f"全件 {count} 件"

    def _close_zip(self, relative: str) -> None:
        archive = self._zips.pop(relative, None)
        if archive is not None:
            archive.close()
        for key in [k for k in self._records if k[0] == relative]:
            self._records.pop(key, None)

    def _mirror_list(self, release: str) -> str:
        if release.startswith("2:extras:"):
            base = self.settings.get("al2_extras_base") or DEFAULT_AL2_EXTRAS_BASE
            topic = release[len("2:extras:"):]
            return f"{base.rstrip('/')}/extras/{urllib.parse.quote(topic)}/latest/x86_64/mirror.list"
        mirrors = {**DEFAULT_AMAZON_MIRRORS, **(self.settings.get("amazon_mirrors") or {})}
        if release not in mirrors:
            raise VulnDBError(f"Amazon Linux {release} のリポジトリ URL が設定されていません（vulndb.amazon_mirrors）")
        return mirrors[release]

    def al2_extras_topics(self) -> list[str]:
        """取得する Amazon Linux 2 の extras トピック（config の vulndb.amazon_extras。既定は全トピック）。"""
        setting = self.settings.get("amazon_extras", "all")
        if isinstance(setting, list):
            return [str(t) for t in setting]
        if str(setting).lower() in ("", "none", "false", "off"):
            return []
        base = self.settings.get("al2_extras_base") or DEFAULT_AL2_EXTRAS_BASE
        catalog = json.loads(self.fetch(f"{base.rstrip('/')}/extras-catalog-x86_64-v2.json").decode("utf-8"))
        return sorted({str(t["n"]) for t in catalog.get("topics") or [] if t.get("n")})

    def _amazon_repo(self, release: str) -> tuple[str, str]:
        """(updateinfo の URL, チェックサム) を返す。"""
        mirror_list = self._mirror_list(release)
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
                match = re.search(r'<data type="updateinfo">(.*?)</data>', repomd, re.S)
                href = re.search(r'href="([^"]+)"', match.group(1)) if match else None
                if not href:
                    # リポジトリには届いたが、セキュリティ情報を持たない（extras の一部のトピック）
                    return "", ""
                checksum = re.search(r"<checksum[^>]*>\s*([0-9a-fA-F]+)\s*</checksum>", match.group(1))
                return base + href.group(1), checksum.group(1).lower() if checksum else ""
            except Exception as exc:          # 次のミラーを試す
                errors.append(f"{base}: {exc}")
        raise VulnDBError("Amazon Linux のリポジトリに接続できません: " + " / ".join(errors))

    @staticmethod
    def stream_floor(fixed: str) -> str:
        """修正版の系統の下限（エポック:メジャー.マイナー）。例 `5.10.35-31.135.amzn2` → `5.10`。"""
        epoch, _, version = fixed.rpartition(":") if ":" in fixed else ("", "", fixed)
        match = re.match(r"(\d+)(?:\.(\d+))?", version)
        if not match:
            return "0"
        floor = match.group(1) + (f".{match.group(2)}" if match.group(2) else "")
        return f"{epoch}:{floor}" if epoch and epoch != "0" else floor

    @staticmethod
    def amazon_records(xml_text: bytes, release: str, topic: str = "") -> list[dict]:
        """updateinfo.xml を OSV 形式の記録に変換する。

        extras のトピック（kernel-5.10、nginx1 など）の記録には、影響範囲の下限を付ける。下限は
        「そのトピックでのそのパッケージの最も古い修正版」の系統（エポック:メジャー.マイナー）。
        - kernel-5.10 → 5.10。kernel 4.14 や 5.15 のホストには当たらない。
        - nginx1 のようにトピックの中で版が上がる（1.20 → 1.22）ものは 1.20。1.20 のホストに 1.22 系の修正も当たる。
        告知ごとに下限を付けると、後者を見落とす（実データで確認した不具合）。エコシステムは core と同じ。
        """
        from .versions import compare_rpm

        ecosystem = f"{AMAZON_PREFIX}{release}"
        root = ET.fromstring(xml_text)
        updates = []
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
            updates.append((update, advisory_id, fixed))

        floors: dict[str, str] = {}
        if topic:
            oldest: dict[str, str] = {}
            for _, _, fixed in updates:
                for name, version in fixed.items():
                    if name not in oldest or compare_rpm(version, oldest[name]) < 0:
                        oldest[name] = version
            floors = {name: VulnDB.stream_floor(version) for name, version in oldest.items()}

        records = []
        for update, advisory_id, fixed in updates:
            cves = [r.get("id") for r in update.iter("reference") if r.get("type") == "cve" and r.get("id")]
            issued = update.find("issued")
            record = {
                "id": advisory_id,
                "aliases": list(dict.fromkeys(cves)),
                "summary": (update.findtext("title") or "").strip(),
                "published": issued.get("date") if issued is not None else "",
                "database_specific": {"severity": (update.findtext("severity") or "").strip().lower(),
                                      **({"topic": topic} if topic else {})},
                "affected": [
                    {"package": {"ecosystem": ecosystem, "name": name},
                     "ranges": [{"type": "ECOSYSTEM", "events": [
                         {"introduced": floors.get(name, "0")}, {"fixed": version}]}]}
                    for name, version in sorted(fixed.items())
                ],
            }
            records.append(record)
        return records

    def update_amazon(self, release: str, force_full: bool = False) -> str:
        source = f"{AMAZON_PREFIX}{release}"
        topic = release[len("2:extras:"):] if release.startswith("2:extras:") else ""
        relative = self._relative_file(source)
        info = self.sources().get(source) or {}
        url, checksum = self._amazon_repo(release)
        if not url:
            self._save_source(source, file=None, url="", updated_at=_now(), records=0, full_at=_now(), checksum="")
            self.connect().commit()
            return "脆弱性情報なし"
        if (not force_full and checksum and checksum == info.get("checksum")
                and (self.dir / relative).is_file()):
            self._save_source(source, updated_at=_now())
            self.connect().commit()
            return "変更なし"
        self.log(f"ダウンロード中: {source}（公式リポジトリの updateinfo）")
        xml_text = _decompress(self.fetch(url))
        target = self.dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_suffix(".zip.part")
        with zipfile.ZipFile(temp, "w", zipfile.ZIP_DEFLATED) as archive:
            for record in self.amazon_records(xml_text, "2" if topic else release, topic):
                archive.writestr(f"{record['id']}.json", json.dumps(record, ensure_ascii=False))
        self._close_zip(relative)
        temp.replace(target)
        count = self._index_zip(source, relative, url, checksum=checksum)
        return f"全件 {count} 件"

    def update(self, sources: Iterable[str], force_full: bool = False) -> dict[str, str]:
        """データを更新する。戻り値は {データ名: エラー内容}（成功したものは含まない）。"""
        errors = {}
        sources = list(dict.fromkeys(sources))
        if f"{AMAZON_PREFIX}2" in sources:
            # Amazon Linux 2 は core に加えて extras のトピック（kernel-5.10 など）も取る
            try:
                for topic in self.al2_extras_topics():
                    name = f"{EXTRAS_PREFIX}{topic}"
                    if name not in sources:
                        sources.append(name)
            except Exception as exc:
                errors[f"{AMAZON_PREFIX}2 extras"] = f"トピックの一覧を取得できません: {exc}"
                self.log(f"  失敗: Amazon Linux 2 extras の一覧: {exc}")
        for source in sources:
            try:
                if source.startswith(AMAZON_PREFIX):
                    result = self.update_amazon(source[len(AMAZON_PREFIX):], force_full)
                    if source.startswith(EXTRAS_PREFIX) and result in ("変更なし", "脆弱性情報なし"):
                        continue          # 70 以上あるので変更なしは表示しない
                else:
                    result = self.update_osv(source, force_full)
                self.log(f"  {source}: {result}")
            except Exception as exc:
                self.connect().rollback()
                errors[source] = str(exc)
                self.log(f"  失敗: {source}: {exc}")
        return errors

    def unknown_ecosystems(self) -> list[str]:
        """取得済みのデータに含まれる、分類されていない系統（coverage.py）。"""
        from .coverage import unknown_ecosystems

        if not self.exists():
            return []
        rows = self.connect().execute("SELECT DISTINCT ecosystem FROM entries")
        return unknown_ecosystems(row[0] for row in rows)

    def import_zip(self, source: str, path: str | Path, url: str = "") -> int:
        """手元にある OSV 形式の zip を取り込む（ネットに出られない場合や試験用）。"""
        relative = self._relative_file(source)
        target = self.dir / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        self._close_zip(relative)
        if Path(path).resolve() != target.resolve():
            shutil.copyfile(path, target)
        # 手で取り込んだデータは差分の起点が分からないので、次回の更新は全件になる
        return self._index_zip(source, relative, url or str(path), cursor=None)

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
                    record = self._read_slim(record_id)
                    if record is None:
                        record = self._read(file, member)
                    if record is not None:
                        yield row_ecosystem, record

    def ensure_slim(self) -> int:
        """縮小版が無い索引（0.2.0 より前に作ったもの）に、手元のデータから縮小版を作る。作った件数を返す。

        zip を取り直さずに済むよう、保存済みの zip と差分の記録から作る。64 KB 未満の記録は読まない。
        差分で新しくなった記録は、zip の古い版ではなく差分の版から作る。
        """
        conn = self.connect()
        if conn.execute("SELECT 1 FROM slim LIMIT 1").fetchone() is not None:
            return 0
        delta_ids = {row[0] for row in conn.execute("SELECT record_id FROM records")}
        made = 0
        for (file,) in conn.execute("SELECT DISTINCT file FROM sources WHERE file IS NOT NULL").fetchall():
            path = self.dir / str(file)
            if not path.is_file():
                continue
            with zipfile.ZipFile(path) as archive:
                rows = []
                for info in archive.infolist():
                    if info.file_size < SLIM_MIN_BYTES or not info.filename.endswith(".json"):
                        continue
                    try:
                        record = json.loads(archive.read(info))
                    except ValueError:
                        continue
                    record_id = str(record.get("id") or info.filename)
                    if record.get("withdrawn") or record_id in delta_ids:
                        continue
                    rows.append((record_id, _slim_blob(record)))
                    if len(rows) >= 2000:
                        conn.executemany("INSERT OR REPLACE INTO slim VALUES (?, ?)", rows)
                        made += len(rows)
                        rows.clear()
                conn.executemany("INSERT OR REPLACE INTO slim VALUES (?, ?)", rows)
                made += len(rows)
        for record_id, data in conn.execute("SELECT record_id, data FROM records").fetchall():
            if len(data.encode("utf-8")) >= SLIM_MIN_BYTES:
                conn.execute("INSERT OR REPLACE INTO slim VALUES (?, ?)", (record_id, _slim_blob(json.loads(data))))
                made += 1
        conn.commit()
        self._has_slim = None
        return made

    def _read_slim(self, record_id: str) -> dict | None:
        """大きな記録の縮小版（無ければ None。古い索引には縮小版が無いので、そのときは元の記録を読む）。"""
        if record_id in self._slim_cache:
            self._slim_cache.move_to_end(record_id)
            return self._slim_cache[record_id]
        if self._has_slim is None:
            self._has_slim = self.connect().execute("SELECT 1 FROM slim LIMIT 1").fetchone() is not None
        if not self._has_slim:
            return None
        row = self.connect().execute("SELECT data FROM slim WHERE record_id = ?", (record_id,)).fetchone()
        if row is None:
            return None
        record = json.loads(zlib.decompress(row[0]))
        self._slim_cache[record_id] = record
        if len(self._slim_cache) > 512:
            self._slim_cache.popitem(last=False)
        return record

    def _read(self, file: str, member: str) -> dict | None:
        key = (file, member)
        if key in self._records:
            self._records.move_to_end(key)
            return self._records[key]
        if file == DELTA_FILE:
            row = self.connect().execute("SELECT data FROM records WHERE record_id = ?", (member,)).fetchone()
            record = json.loads(row[0]) if row else None
            self._records[key] = record
            if len(self._records) > self._cache_size:
                self._records.popitem(last=False)
            return record
        if True:
            archive = self._zips.get(file)
            if archive is None:
                path = self.dir / file
                if not path.is_file():
                    raise VulnDBError(f"データベースのファイルがありません: {path}（update をやり直してください）")
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
