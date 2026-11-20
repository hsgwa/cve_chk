import csv

from click.testing import CliRunner
from openpyxl import load_workbook

from vuln_triage.cli import main
from vuln_triage.maven_lookup import resolve_hashes
from vuln_triage.models import KIND_MAVEN
from vuln_triage.report import tables
from vuln_triage.verdict import Judge

from conftest import TODAY, comp, make_advisory, make_env


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.reader(fh))


def run_examples(examples, tmp_path, *extra, scanner=("--db-dir",)):
    if scanner == ("--db-dir",):
        scanner = ("--db-dir", str(examples / "vulndb"))
    args = ["run", "--inventory-dir", str(examples / "inventory"), "--env-master", str(examples / "env_master.csv"),
            "--advisory", str(examples / "advisory_list.xlsx"), *scanner,
            "--cache-dir", str(examples / "cache"), "--offline", "--base-date", "2026-11-20",
            "--out-dir", str(tmp_path / "out"), "--work-dir", str(tmp_path / "work"), *extra]
    return CliRunner().invoke(main, args)


def test_summary_table_aggregates_per_advisory(config):
    envs = [make_env("a", exposure="internet", components=[comp("nginx", "1.0")]),
            make_env("b", components=[comp("nginx", "1.30")]),
            make_env("c", components=[comp("other", "1")])]
    advisories = [make_advisory(advisory_id="A1", product_name="nginx", affected_version="<1.25",
                                company_rank="Rank-A", deadline_days=14, note="メモ")]
    result = Judge(envs, [], config, TODAY).run(advisories)
    row = tables.summary_table(advisories, result.rows, config)[0]
    summary = dict(zip(tables.SUMMARY_HEADER, row))
    assert summary["総合判定"] == "影響あり"
    assert (summary["影響あり環境"], summary["影響なし環境"], summary["未使用環境"]) == ("a", "b", "c")
    assert (summary["社内ランク"], summary["対応期限"]) == ("Rank-A", "2026-12-04")
    header, matrix = tables.matrix_table(advisories, result.rows, envs)
    assert header[3:] == ["a", "b", "c"] and matrix[0][3:] == ["影響あり", "影響なし", "未使用"]


def test_cli_end_to_end(examples, tmp_path):
    result = run_examples(examples, tmp_path)
    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    assert (out / "report_detail.csv").read_bytes().startswith(b"\xef\xbb\xbf")     # Excel で開ける BOM 付き

    detail = read_csv(out / "report_detail.csv")
    assert detail[0] == tables.DETAIL_HEADER
    rows = [dict(zip(detail[0], line)) for line in detail[1:]]

    def status(advisory_id, env):
        return {r["影響有無"] for r in rows if r["社内通達ID"] == advisory_id and r["該当環境"] == env}

    assert status("ADV-001", "web-ec2") == {"影響あり"}            # 脆弱性DB + ルール
    assert status("ADV-001", "batch-emr") == {"影響なし"}          # 修正済みの版
    assert status("ADV-001", "win-app01") == {"影響あり"}          # Windows の inventory.json の jar
    assert status("ADV-001", "win-legacy") == {"判定不能"}         # SBOM なし
    assert status("ADV-003", "batch-emr") == {"影響なし（CVE未検出）"}
    assert status("ADV-004", "web-ec2") == {"影響あり"}            # 個別製品の版取得（Linux の HULFT）
    assert status("ADV-004", "win-app01") == {"影響なし"}          # レジストリの版 + 別名
    assert status("ADV-005", "batch-emr") == {"影響あり（比較不能）"}
    assert status("ADV-008", "win-app01") == {"影響あり"}          # KB 未適用
    assert status("ADV-008", "win-legacy") == {"影響なし"}
    assert status("ADV-008", "web-ec2") == {"対象外"}
    assert status("ADV-009", "win-app01") == {"影響あり"}          # OS ビルド番号
    assert status("ADV-010", "batch-emr") == {"影響あり"}          # EMR リリースラベル
    assert status("ADV-011", "web-ec2") == {"未使用"}

    log4shell = next(r for r in rows if r["社内通達ID"] == "ADV-001" and r["該当環境"] == "web-ec2")
    assert log4shell["判定区分"] == "CVE（脆弱性DB＋ルール）" and log4shell["社内ランク"] == "Rank-S"
    assert log4shell["対応期限"] == "2026-11-05" and "期限超過" in log4shell["備考"]
    assert log4shell["検出パス/ソース"] == "/opt/app/lib/log4j-core-2.14.1.jar" and log4shell["CVSS_v3"] == "10.0"

    summary = read_csv(out / "report_summary.csv")
    assert len(summary) == 12                                      # 通達 11 件すべてが1行ずつ出る
    assert [line[4] for line in summary[1:]].count("影響あり") == 10

    new = read_csv(out / "report_new_findings.csv")
    assert len(new) > 1 and all(line[6] == "影響あり（新規検出）" for line in new[1:])
    amazon = [dict(zip(new[0], line)) for line in new[1:] if line[9] == "batch-emr" and line[3] == "openssl-libs"]
    assert amazon and all(r["CVSS_v3"] or "ベンダーの深刻度" in r["備考"] for r in amazon)   # Amazon Linux の OS パッケージ
    assert any(r["CVSS_v3"] for r in amazon)                                                   # 点数は Debian のデータから

    workbook = load_workbook(out / "report.xlsx")
    assert workbook.sheetnames == ["サマリ", "通達別一覧", "通達×環境", "明細", "新規検出（参考）", "収集状況"]
    assert workbook["通達別一覧"].max_row == 12
    coverage = {row[0]: row for row in workbook["収集状況"].iter_rows(min_row=2, values_only=True)}
    assert coverage["win-legacy"][3] == "未登録" and coverage["win-legacy"][9] == "不可"
    assert "agent.exe" in coverage["win-app01"][13]
    assert "win-legacy" in result.output and "サマリ" in result.output
    assert "脆弱性データの更新日時" in result.output


def test_cli_with_saved_trivy_results(examples, tmp_path):
    result = run_examples(examples, tmp_path, scanner=("--scanner", "trivy", "--trivy-results-dir",
                                                       str(examples / "trivy_fixtures")))
    assert result.exit_code == 0, result.output
    rows = [dict(zip(tables.DETAIL_HEADER, line)) for line in read_csv(tmp_path / "out" / "report_detail.csv")[1:]]
    assert {r["影響有無"] for r in rows if r["社内通達ID"] == "ADV-001" and r["該当環境"] == "web-ec2"} == {"影響あり"}


def test_cli_only_advisory_and_csv_only(examples, tmp_path):
    result = run_examples(examples, tmp_path, "--only-advisory", "--no-xlsx")
    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    assert not (out / "report_new_findings.csv").exists() and not (out / "report.xlsx").exists()


def test_cli_without_cve_scan(examples, tmp_path):
    for flag in (["--scanner", "none"], ["--skip-trivy"]):
        result = CliRunner().invoke(main, [
            "run", "--inventory-dir", str(examples / "inventory"), "--advisory", str(examples / "advisory_list.csv"),
            *flag, "--no-msrc", "--out-dir", str(tmp_path / "out"), "--work-dir", str(tmp_path / "work"),
            "--cache-dir", str(tmp_path / "cache")])
        assert result.exit_code == 0, result.output
        rows = read_csv(tmp_path / "out" / "report_detail.csv")
        cve_only = [r for r in rows[1:] if r[2] == "ADV-003"]
        assert {r[6] for r in cve_only} == {"判定不能"}             # CVE 照合なしでは CVE だけの通達は判定できない


def test_cli_errors(examples, tmp_path, monkeypatch):
    monkeypatch.setattr("vuln_triage.trivy_runner.shutil.which", lambda name: None)
    base = ["run", "--inventory-dir", str(examples / "inventory"), "--out-dir", str(tmp_path / "out"),
            "--work-dir", str(tmp_path / "work"), "--cache-dir", str(tmp_path / "cache")]
    result = CliRunner().invoke(main, [*base, "--advisory", str(examples / "advisory_list.csv"), "--scanner", "trivy"])
    assert result.exit_code == 2 and "Trivy が見つかりません" in result.output

    result = CliRunner().invoke(main, [*base, "--advisory", str(examples / "advisory_list.csv"),
                                       "--db-dir", str(tmp_path / "nodb")])
    assert result.exit_code == 2 and "db-update" in result.output

    bad = tmp_path / "bad.csv"
    bad.write_text("番号,内容\n1,x\n", encoding="utf-8")
    result = CliRunner().invoke(main, [*base, "--advisory", str(bad), "--scanner", "none"])
    assert result.exit_code == 2 and "見つかった見出し" in result.output


def test_check_inputs_and_build_sbom(examples, tmp_path):
    result = CliRunner().invoke(main, [
        "check-inputs", "--inventory-dir", str(examples / "inventory"), "--env-master", str(examples / "env_master.csv"),
        "--advisory", str(examples / "advisory_list.xlsx")])
    assert result.exit_code == 0, result.output
    assert "win-app01" in result.output and "ADV-011 [nginx] -> 該当なし" in result.output
    assert "ADV-006 [Apache Tomcat*] -> " in result.output and "Apache Tomcat 9.0 Tomcat9 9.0.83" in result.output

    result = CliRunner().invoke(main, ["build-sbom", "--inventory-dir", str(examples / "inventory"),
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
    result = run_examples(examples, tmp_path, scanner=("--db-dir", str(db_dir)))
    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.splitlines() if "更新が古くなっています" in line]
    assert len(lines) == 1 and "Maven（" in lines[0] and "日前）" in lines[0]
