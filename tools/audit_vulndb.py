"""実データで、これまでの不具合と同じ種類の不具合が無いことを確かめる監査。

使い方:
    python tools/audit_vulndb.py --db-dir vulndb [--db-dir 別の DB ...] [--inventory-dir inventory]

検査（docs/DEFECTS.md の不具合の種類に対応）:
  A. 系統の網羅性     … データに現れる系統をすべて「使う／理由つきで使わない」に分類できるか
                         （Ubuntu Pro、Amazon Linux 2 extras の見落としと同じ種類）
  B. extras の網羅性  … Amazon Linux 2 の extras のトピックがすべて取得済みか
  C. 版の比較規則     … データ中の版を、そのエコシステムの比較規則で読めるか。影響範囲の順序が正しいか
                         （RPM を PEP 440 で比べた、数字の無い版を比べた、と同じ種類）
  D. 照合結果の不変条件（--inventory-dir のとき）
       D1 検出のもとの記録に、そのパッケージ名・系統が載っているか（別パッケージの範囲の誤適用）
       D2 検出 1 件に CVE は 1 つか（複数 CVE の告知の紐づけ誤り）
       D3 ヘッダだけのパッケージに検出が無いか（linux-libc-dev と同じ種類）
       D4 すべてのパッケージが「照合した／理由つきで照合しなかった」のどちらかに入っているか（黙って抜けない）
       D5 Go の v2 以降のモジュール名に subpath が付いているか（#v2 の読み落とし）
問題が 1 つでもあれば終了コード 1。
"""
from __future__ import annotations

import argparse
import json
import random
import sqlite3
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vuln_triage.config import load_config  # noqa: E402
from vuln_triage.inventory import load_inventories  # noqa: E402
from vuln_triage.purl import parse_purl  # noqa: E402
from vuln_triage.sbom_builder import assign_purls  # noqa: E402
from vuln_triage.vulndb.coverage import classify  # noqa: E402
from vuln_triage.vulndb.ecosystems import build_query, is_kernel_header_package, normalize_package, skip_reason  # noqa: E402
from vuln_triage.vulndb.scanner import scan_with_vulndb  # noqa: E402
from vuln_triage.vulndb.store import EXTRAS_PREFIX, VulnDB  # noqa: E402
from vuln_triage.vulndb.versions import SCHEMES, UncomparableVersion, compare, scheme_for  # noqa: E402

problems: list[str] = []


def problem(message: str) -> None:
    problems.append(message)
    print("  NG: " + message)


def audit_ecosystems(db: VulnDB) -> None:
    print("A. 系統の網羅性")
    rows = db.connect().execute("SELECT ecosystem, count(*) FROM entries GROUP BY ecosystem").fetchall()
    by_class: dict[str, list] = defaultdict(list)
    for ecosystem, count in rows:
        state, reason = classify(ecosystem)
        by_class[state].append((ecosystem, count, reason))
    print(f"  系統 {len(rows)} 種: 使う {len(by_class['used'])}、理由つきで使わない {len(by_class['excluded'])}、"
          f"分類なし {len(by_class['unknown'])}")
    reasons = Counter(reason for _, _, reason in by_class["excluded"])
    for reason, count in reasons.most_common():
        print(f"    使わない: {count} 種 … {reason}")
    for ecosystem, count, _ in sorted(by_class["unknown"], key=lambda x: -x[1]):
        problem(f"分類されていない系統 {ecosystem}（{count} 件）")


def audit_extras(db: VulnDB) -> None:
    sources = db.sources()
    if "Amazon Linux:2" not in sources:
        return
    print("B. Amazon Linux 2 の extras の網羅性")
    try:
        topics = db.al2_extras_topics()
    except Exception as exc:          # noqa: BLE001
        problem(f"extras のトピック一覧を取得できない: {exc}")
        return
    have = {name[len(EXTRAS_PREFIX):] for name in sources if name.startswith(EXTRAS_PREFIX)}
    missing = sorted(set(topics) - have)
    print(f"  トピック {len(topics)} 件中 {len(set(topics) & have)} 件を取得済み")
    for topic in missing:
        problem(f"extras のトピック {topic} が未取得")


def audit_versions(db: VulnDB, per_ecosystem: int = 3000) -> None:
    print("C. 版の比較規則")
    conn = db.connect()
    ecosystems = [row[0] for row in conn.execute("SELECT DISTINCT ecosystem FROM entries")
                  if classify(row[0])[0] == "used"]
    rng = random.Random(0)
    for ecosystem in sorted(ecosystems):
        rows = conn.execute("SELECT file, member FROM entries WHERE ecosystem = ?", (ecosystem,)).fetchall()
        rows = rng.sample(rows, min(per_ecosystem, len(rows)))
        scheme = SCHEMES[scheme_for(ecosystem)]
        values = fallback = disorder = 0
        examples = []
        for file, member in rows:
            record = db._read(file, member)
            for affected in (record or {}).get("affected") or []:
                if (affected.get("package") or {}).get("ecosystem") != ecosystem:
                    continue
                for range_ in affected.get("ranges") or []:
                    if range_.get("type") not in ("ECOSYSTEM", "SEMVER"):
                        continue
                    previous = None
                    for event in range_.get("events") or []:
                        for kind, value in event.items():
                            if kind == "limit" or value in (None, "0"):
                                continue
                            values += 1
                            try:
                                scheme(str(value), str(value))
                            except (UncomparableVersion, ValueError):
                                fallback += 1
                                if len(examples) < 3:
                                    examples.append(str(value))
                            if kind == "introduced":
                                previous = str(value)
                            elif previous is not None:
                                try:
                                    if compare(ecosystem, previous, str(value)) > 0:
                                        disorder += 1
                                except (UncomparableVersion, ValueError):
                                    pass
                                previous = None
        rate = fallback / values if values else 0
        note = f"（例 {', '.join(examples)}）" if examples else ""
        print(f"  {ecosystem:28s} 版 {values:6d} 個: 規則で読めない {fallback}（{rate:.2%}）{note}、"
              f"下限 > 修正版の範囲 {disorder}")
        if rate > 0.01:
            problem(f"{ecosystem}: 比較規則で読めない版が {rate:.1%}（汎用比較に頼っている）")
        if disorder:
            problem(f"{ecosystem}: 下限が修正版より大きい範囲が {disorder} 件（比較規則の誤りの疑い）")


def audit_scan(dbs: list[VulnDB], inventory_dir: str, config: dict) -> None:
    print("D. 照合結果の不変条件")
    envs = load_inventories(inventory_dir, {})
    assign_purls(envs)
    for env in envs:
        db = next((d for d in dbs if d.sources()), dbs[0])
        findings = []
        for d in dbs:
            for component in env.components:
                component.checked = False
            findings = scan_with_vulndb([env], d, config) or findings
            if any(c.checked for c in env.components):
                db = d
                break
        print(f"  環境 {env.name}: 検出 {len(findings)} 件（DB {db.dir}）")
        components = {c.path or c.name: c for c in env.components}
        # D1: 記録にパッケージ名・系統が載っているか
        bad = 0
        index = defaultdict(list)
        for component in env.components:
            query = build_query(component, env) if component.purl else None
            if query and query.ecosystems:
                index[query.display].append(query)
        for finding in findings:
            queries = index.get(finding.pkg_name) or []
            ok = False
            for query in queries:
                for _, record in db.lookup(query.ecosystems, query.names):
                    if finding.cve_id.upper() in {i.upper() for i in [record.get("id"), *(record.get("aliases") or []),
                                                                      *(record.get("upstream") or [])]}:
                        names = {normalize_package(a["package"]["ecosystem"], a["package"]["name"])
                                 for a in record.get("affected") or []}
                        ok = ok or bool(set(query.names) & names)
                if ok:
                    break
            if not ok:
                bad += 1
                if bad <= 3:
                    problem(f"D1 {env.name}: {finding.pkg_name} {finding.cve_id} の記録にそのパッケージが無い")
        print(f"    D1 記録に載っていないパッケージへの検出: {bad} 件")
        # D2
        multi = [f for f in findings if f.cve_id.startswith("CVE-") and
                 len([i for i in f.match_ids if i.startswith("CVE-")]) != 1]
        print(f"    D2 通達との突き合わせに CVE が複数使われる検出: {len(multi)} 件")
        for f in multi[:3]:
            problem(f"D2 {env.name}: {f.pkg_name} {f.cve_id} の突き合わせ ID {sorted(f.match_ids)}")
        # D3
        headers = [c for c in env.components if c.purl and is_kernel_header_package(parse_purl(c.purl).type, c.name)]
        header_hits = [f for f in findings if f.pkg_name in {c.name for c in headers}]
        print(f"    D3 ヘッダだけのパッケージ {len(headers)} 件への検出: {len(header_hits)} 件")
        if header_hits:
            problem(f"D3 {env.name}: ヘッダのパッケージに検出 {len(header_hits)} 件")
        # D4
        total = checked = skipped = missing = 0
        silent = Counter()
        for component in env.components:
            if not component.scannable or not component.purl:
                continue
            total += 1
            query = build_query(component, env)
            if component.checked:
                checked += 1
            elif query is None:
                if skip_reason(component):
                    skipped += 1
                else:
                    silent[parse_purl(component.purl).type] += 1
            else:
                missing += 1
        print(f"    D4 パッケージ {total} 件 = 照合 {checked} + 理由つきで照合せず {skipped} + データ無し {missing}"
              f" + 理由なしで抜けた {sum(silent.values())}")
        if sum(silent.values()):
            problem(f"D4 {env.name}: 理由なしで照合から抜けたパッケージ {dict(silent)}")
        # D5
        go = [c for c in env.components if c.purl.startswith("pkg:golang/") and parse_purl(c.purl).subpath
              and build_query(c, env) is not None]          # 版が不明で理由つきで外したものは D4 で数える
        wrong = [c for c in go if not (build_query(c, env) and build_query(c, env).display.endswith("/" + parse_purl(c.purl).subpath))]
        print(f"    D5 Go の v2 以降のモジュール {len(go)} 件のうち、名前に subpath が無いもの: {len(wrong)} 件")
        if wrong:
            problem(f"D5 {env.name}: subpath の無い Go モジュール名 {[c.purl for c in wrong[:3]]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--db-dir", action="append", required=True)
    parser.add_argument("--inventory-dir")
    parser.add_argument("--config")
    args = parser.parse_args()
    config = load_config(args.config)
    dbs = [VulnDB(d, config) for d in args.db_dir]
    for db in dbs:
        print(f"==== {db.dir}")
        audit_ecosystems(db)
        audit_extras(db)
        audit_versions(db)
    if args.inventory_dir:
        print("====")
        audit_scan(dbs, args.inventory_dir, config)
    print("====")
    print(f"問題 {len(problems)} 件" if problems else "問題なし")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
