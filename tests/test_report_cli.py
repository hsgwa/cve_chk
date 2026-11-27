import csv

from click.testing import CliRunner
from openpyxl import load_workbook

from zeijaku_kakunin.cli import main
from zeijaku_kakunin.judge import Result, Row
from zeijaku_kakunin.maven_lookup import resolve_hashes
from zeijaku_kakunin.models import KIND_MAVEN
from zeijaku_kakunin.report import tables

from conftest import comp, make_env


def read_rows(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def check(examples, tmp_path, server="web-ec2", *extra, cve_list=True, db=True):
    args = ["check", str(examples / "inventory" / server), "--cache-dir", str(examples / "cache"), "--offline",
            "--base-date", "2026-11-20", "--out-dir", str(tmp_path / "out"), *extra]
    if cve_list:
        args += ["--cve-list", str(examples / "cve_list.xlsx")]
    if db:
        args += ["--db-dir", str(examples / "vulndb")]
    return CliRunner().invoke(main, args)


def test_check_with_cve_list(examples, tmp_path):
    result = check(examples, tmp_path)
    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    assert (out / "report_cve.csv").read_bytes().startswith(b"\xef\xbb\xbf")     # Excel で開ける BOM 付き
    cves = {r["CVE"]: r for r in read_rows(out / "report_cve.csv")}
    assert list(cves) == ["CVE-2021-44228", "CVE-2022-42889", "CVE-2023-32681", "CVE-2024-21338", "CVE-2099-0001"]
    log4j = cves["CVE-2021-44228"]
    assert (log4j["影響有無"], log4j["ソフトウェア"], log4j["現在のバージョン"], log4j["修正バージョン"]) == (
        "影響あり", "org.apache.logging.log4j:log4j-core", "2.14.1", "2.15.0")
    assert cves["CVE-2099-0001"]["影響有無"] == "影響なし"
    assert "Windows ではありません" in cves["CVE-2024-21338"]["備考"]

    updates = {r["ソフトウェア"]: r for r in read_rows(out / "report_updates.csv")}
    log4j = updates["org.apache.logging.log4j:log4j-core"]
    assert log4j["この版以上に更新"] == "2.25.4" and log4j["うち CVE の一覧にあるもの（件）"] == "1"
    assert list(updates)[0] in ("org.apache.logging.log4j:log4j-core", "org.apache.commons:commons-text")  # 一覧の CVE を含むものが先

    vulns = read_rows(out / "report_vulns.csv")
    assert {r["CVE の一覧にある"] for r in vulns} == {"○", ""} and len(vulns) > 10

    sheets = load_workbook(out / "report.xlsx", read_only=True).sheetnames
    assert sheets == ["サマリ", "CVE の判定", "要更新ソフト", "脆弱性の一覧", "収集状況"]
    assert "CVE の一覧 5 件: 影響あり 2 件、影響なし 3 件、判定不能 0 件" in result.output


def test_check_without_cve_list(examples, tmp_path):
    """CVE の一覧が無くても、見つかった脆弱性とソフトの更新先を出す。"""
    result = check(examples, tmp_path, "win-app01", cve_list=False)
    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    assert not (out / "report_cve.csv").exists()
    assert {r["CVE の一覧にある"] for r in read_rows(out / "report_vulns.csv")} == {""}
    assert "CVE の判定" not in load_workbook(out / "report.xlsx", read_only=True).sheetnames
    assert "CVE の一覧" not in result.output


def test_windows_server_os_and_default_out_dir(examples, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(main, ["check", str(examples / "inventory" / "win-app01"), "--cve-list",
                                       str(examples / "cve_list.csv"), "--db-dir", str(examples / "vulndb"),
                                       "--cache-dir", str(examples / "cache"), "--offline", "--no-xlsx"])
    assert result.exit_code == 0, result.output
    cves = {r["CVE"]: r for r in read_rows(tmp_path / "out" / "win-app01" / "report_cve.csv")}  # 既定は out\<サーバー名>
    assert cves["CVE-2024-21338"]["影響有無"] == "影響あり" and "KB5034768" in cves["CVE-2024-21338"]["備考"]
    assert cves["CVE-2023-32681"]["ソフトウェア"] == "requests"
    updates = {r["ソフトウェア"]: r for r in read_rows(tmp_path / "out" / "win-app01" / "report_updates.csv")}
    assert any(r["この版以上に更新"] == "Windows Update で最新にする" for r in updates.values())


def test_server_without_checkable_software_is_unknown(examples, tmp_path):
    result = check(examples, tmp_path, "win-legacy", "--no-xlsx")
    assert result.exit_code == 0, result.output
    assert {r["影響有無"] for r in read_rows(tmp_path / "out" / "report_cve.csv")} == {"判定不能"}


def test_check_with_saved_trivy_results(examples, tmp_path):
    result = check(examples, tmp_path, "web-ec2", "--scanner", "trivy", "--trivy-results-dir",
                   str(examples / "trivy_fixtures"), "--no-xlsx", db=False)
    assert result.exit_code == 0, result.output
    cves = {r["CVE"]: r["影響有無"] for r in read_rows(tmp_path / "out" / "report_cve.csv")}
    assert cves["CVE-2021-44228"] == "影響あり"


def test_check_errors(examples, tmp_path, monkeypatch):
    monkeypatch.setattr("zeijaku_kakunin.trivy_runner.shutil.which", lambda name: None)
    result = check(examples, tmp_path, "web-ec2", "--scanner", "trivy", db=False)
    assert result.exit_code == 2 and "Trivy が見つかりません" in result.output
    result = check(examples, tmp_path, "web-ec2", "--db-dir", str(tmp_path / "nodb"), db=False)
    assert result.exit_code == 2 and "zk update" in result.output
    # 複数台を並べたフォルダは 1 台ずつ指定するよう案内する
    result = CliRunner().invoke(main, ["check", str(examples / "inventory"), "--db-dir", str(examples / "vulndb")])
    assert result.exit_code == 2 and "1 台ずつ" in result.output
    empty = tmp_path / "list.csv"
    empty.write_text("番号,内容\n1,x\n", encoding="utf-8")
    result = check(examples, tmp_path, "web-ec2", "--cve-list", str(empty), cve_list=False)
    assert result.exit_code == 2 and "CVE 番号" in result.output


def test_preview_and_export_sbom(examples, tmp_path):
    result = CliRunner().invoke(main, ["preview", str(examples / "inventory" / "win-app01"),
                                       "--cve-list", str(examples / "cve_list.xlsx")])
    assert result.exit_code == 0, result.output
    assert "win-app01" in result.output and "CVE の一覧: 5 件" in result.output and "CVE-2021-44228" in result.output
    result = CliRunner().invoke(main, ["export-sbom", "--inventory-dir", str(examples / "inventory"),
                                       "--out-dir", str(tmp_path / "sbom")])
    assert result.exit_code == 0 and (tmp_path / "sbom" / "generated_win-app01.cdx.json").is_file()


def test_resolve_hashes(tmp_path):
    jar = comp("legacy-lib", "1.2.3", kind=KIND_MAVEN, extra_names=("sha1:abc",))
    known = comp("log4j-core", "2.14.1", kind=KIND_MAVEN, group="org.apache.logging.log4j", extra_names=("sha1:def",))
    env = make_env(components=[jar, known])
    calls = []

    def search(sha1):
        calls.append(sha1)
        return {"group": "com.example", "artifact": "legacy-lib", "version": "1.2.3"}

    cache = tmp_path / "c" / "maven.json"
    assert resolve_hashes([env], cache, search=search) == (1, None)
    assert jar.group == "com.example" and calls == ["abc"]         # groupId が分かっている jar は問い合わせない
    again = comp("legacy-lib", "1.2.3", kind=KIND_MAVEN, extra_names=("sha1:abc",))
    assert resolve_hashes([make_env(components=[again])], cache, search=lambda s: 1 / 0) == (1, None)   # キャッシュ


def test_stale_database_warning_is_one_line(examples, tmp_path):
    import shutil
    import sqlite3
    db_dir = tmp_path / "vulndb"
    shutil.copytree(examples / "vulndb", db_dir)
    conn = sqlite3.connect(db_dir / "index.sqlite")
    conn.execute("UPDATE sources SET updated_at = '2026-01-01T00:00:00Z'")
    conn.commit()
    conn.close()
    result = check(examples, tmp_path, "web-ec2", "--db-dir", str(db_dir), "--no-xlsx", db=False)
    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.splitlines() if "更新が古くなっています" in line]
    assert len(lines) == 1 and "Maven（" in lines[0] and "日前）" in lines[0]


def test_update_table_groups_findings_per_package():
    """要更新ソフト: ソフトウェア × 版ごとにまとめ、すべての脆弱性が直る版（修正版の最大）を出す。"""
    def row(cve, fixed, status="影響あり", in_list=False):
        return Row(cve, status, "openssl", "3.0.2-0ubuntu1.10", fixed, "Ubuntu のパッケージ", ecosystem="Ubuntu",
                   in_list=in_list)
    result = Result(vulns=[row("CVE-1", "3.0.2-0ubuntu1.9", in_list=True), row("CVE-2", "3.0.2-0ubuntu1.17"),
                           row("CVE-3", "3.0.2-0ubuntu1.12"), row("CVE-4", ""),
                           row("CVE-5", "3.0.2-0ubuntu1.20", status="影響なし")])   # 影響なしは含めない
    table = tables.update_table(result)
    assert len(table) == 1
    line = dict(zip(tables.UPDATE_HEADER, table[0]))
    assert line["この版以上に更新"] == "3.0.2-0ubuntu1.17"      # 文字列の順では 1.9 が最大になってしまう
    assert (line["脆弱性（件）"], line["修正版の無いもの（件）"], line["うち CVE の一覧にあるもの（件）"]) == ("4", "1", "1")


def test_xlsx_rows_are_capped_but_csv_keeps_everything(examples, tmp_path):
    """Excel の行数の上限（約 104 万行）を超えないよう、シートは xlsx_max_rows で打ち切る。CSV は全件。"""
    config_file = tmp_path / "config.yaml"
    config_file.write_text("xlsx_max_rows: 3\n", encoding="utf-8")
    result = check(examples, tmp_path, "web-ec2", "--config", str(config_file))
    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    vulns = read_rows(out / "report_vulns.csv")
    assert len(vulns) > 3
    assert load_workbook(out / "report.xlsx", read_only=True)["脆弱性の一覧"].max_row == 4   # 見出し + 3 行
    assert f"全 {len(vulns):,} 行は report_vulns.csv" in result.output


def test_previous_run_comparison(examples, tmp_path):
    """前回の出力フォルダと比べ、新たに見つかった / 解消 / 継続 を出す。"""
    first = tmp_path / "first"
    result = check(examples, tmp_path, "web-ec2", "--no-xlsx")
    assert result.exit_code == 0, result.output
    (tmp_path / "out").rename(first)
    path = first / "report_vulns.csv"
    rows = read_rows(path)
    removed = rows.pop(0)
    fixed = {**rows[0], "CVE など": "CVE-2000-0001"}
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows([*rows, fixed])

    result = check(examples, tmp_path, "web-ec2", "--previous", str(first))
    assert result.exit_code == 0, result.output
    changes = read_rows(tmp_path / "out" / "report_changes.csv")
    by_change = {}
    for line in changes:
        by_change.setdefault(line["変化"], []).append((line["CVE など"], line["ソフトウェア"]))
    assert by_change["新たに見つかった"] == [(removed["CVE など"], removed["ソフトウェア"])]
    assert by_change["解消"] == [("CVE-2000-0001", fixed["ソフトウェア"])]
    assert by_change["継続"] and changes[0]["変化"] == "新たに見つかった"
    assert "前回との差分" in load_workbook(tmp_path / "out" / "report.xlsx", read_only=True).sheetnames
    bad = check(examples, tmp_path, "web-ec2", "--previous", str(tmp_path / "out"))
    assert bad.exit_code == 2 and "同じフォルダ" in bad.output


def test_commands(examples):
    help_text = CliRunner().invoke(main, ["--help"]).output
    for name in ("update", "check", "preview", "scan-file", "export-sbom", "demo", "init"):
        assert name in help_text
    for old in ("run", "db-update", "check-inputs", "--only-advisory", "env-master"):
        assert old not in help_text


def test_demo_builds_sample_report(tmp_path):
    """zk demo は同梱のサンプルで、ネットにつながずにサーバーごとのレポートの見本を作る。"""
    out = tmp_path / "demo"
    result = CliRunner().invoke(main, ["demo", "--out-dir", str(out)])
    assert result.exit_code == 0, result.output
    for server in ("batch-emr", "web-ec2", "win-app01", "win-legacy"):
        assert (out / server / "report.xlsx").is_file() and (out / server / "report_cve.csv").is_file()
    assert "見本のレポート" in result.output
    assert "更新が古くなっています" not in result.output  # 見本のデータは古くて当然なので警告しない


def test_init_creates_work_folder(tmp_path):
    base = tmp_path / "vuln"
    result = CliRunner().invoke(main, ["init", str(base)])
    assert result.exit_code == 0, result.output
    for name in ("inventory", "cve_list", "reports", "logs"):
        assert (base / name).is_dir()
    readme = base / "はじめに.txt"
    assert "check_all.ps1" in readme.read_text(encoding="utf-8-sig")
    readme.write_text("自分のメモ", encoding="utf-8")
    assert CliRunner().invoke(main, ["init", str(base)]).exit_code == 0
    assert readme.read_text(encoding="utf-8") == "自分のメモ"             # 既にあるファイルは上書きしない
