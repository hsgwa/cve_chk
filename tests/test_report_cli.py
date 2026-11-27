import csv

from click.testing import CliRunner
from openpyxl import load_workbook

from zeijaku_kakunin.cli import main
from zeijaku_kakunin.maven_lookup import resolve_hashes
from zeijaku_kakunin.models import KIND_MAVEN
from zeijaku_kakunin.report import tables
from zeijaku_kakunin.verdict import Judge

from conftest import TODAY, comp, make_advisory, make_env


def read_csv(path):
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.reader(fh))


def run_examples(examples, tmp_path, *extra, scanner=("--db-dir",)):
    if scanner == ("--db-dir",):
        scanner = ("--db-dir", str(examples / "vulndb"))
    args = ["check", "--inventory-dir", str(examples / "inventory"), "--env-master", str(examples / "env_master.csv"),
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
    assert workbook.sheetnames == ["サマリ", "通達別一覧", "要更新パッケージ", "通達×環境", "明細", "新規検出（参考）", "収集状況"]
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
    monkeypatch.setattr("zeijaku_kakunin.trivy_runner.shutil.which", lambda name: None)
    base = ["check", "--inventory-dir", str(examples / "inventory"), "--out-dir", str(tmp_path / "out"),
            "--work-dir", str(tmp_path / "work"), "--cache-dir", str(tmp_path / "cache")]
    result = CliRunner().invoke(main, [*base, "--advisory", str(examples / "advisory_list.csv"), "--scanner", "trivy"])
    assert result.exit_code == 2 and "Trivy が見つかりません" in result.output

    result = CliRunner().invoke(main, [*base, "--advisory", str(examples / "advisory_list.csv"),
                                       "--db-dir", str(tmp_path / "nodb")])
    assert result.exit_code == 2 and "update" in result.output

    bad = tmp_path / "bad.csv"
    bad.write_text("番号,内容\n1,x\n", encoding="utf-8")
    result = CliRunner().invoke(main, [*base, "--advisory", str(bad), "--scanner", "none"])
    assert result.exit_code == 2 and "見つかった見出し" in result.output


def test_check_inputs_and_build_sbom(examples, tmp_path):
    result = CliRunner().invoke(main, [
        "preview", "--inventory-dir", str(examples / "inventory"), "--env-master", str(examples / "env_master.csv"),
        "--advisory", str(examples / "advisory_list.xlsx")])
    assert result.exit_code == 0, result.output
    assert "win-app01" in result.output and "ADV-011 [nginx] -> 該当なし" in result.output
    assert "ADV-006 [Apache Tomcat*] -> " in result.output and "Apache Tomcat 9.0 Tomcat9 9.0.83" in result.output

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
    result = run_examples(examples, tmp_path, scanner=("--db-dir", str(db_dir)))
    assert result.exit_code == 0, result.output
    lines = [line for line in result.output.splitlines() if "更新が古くなっています" in line]
    assert len(lines) == 1 and "Maven（" in lines[0] and "日前）" in lines[0]


def test_update_table_groups_findings_per_package(config):
    """要更新パッケージ: 環境 × パッケージごとにまとめ、すべての脆弱性が直る版（修正版の最大）を出す。"""
    from datetime import date

    from zeijaku_kakunin.models import Verdict
    from zeijaku_kakunin.report import tables

    def row(cve, fixed, cvss, rank, status="影響あり", advisory=""):
        return Verdict(status=status, env="web", exposure="internet", cve_id=cve, advisory_id=advisory,
                       package="openssl", version="3.0.2-0ubuntu1.10", path="Ubuntu", cvss=cvss, rank=rank,
                       deadline=date(2026, 12, 1), fixed=fixed, ecosystem="Ubuntu")
    rows = [row("CVE-1", "3.0.2-0ubuntu1.9", 9.8, "Rank-S", advisory="ADV-1")]
    new = [row("CVE-2", "3.0.2-0ubuntu1.17", 5.0, "Rank-B", status="影響あり（新規検出）"),
           row("CVE-3", "3.0.2-0ubuntu1.12", 7.5, "Rank-A", status="影響あり（新規検出）"),
           row("CVE-4", "", 4.0, "Rank-C", status="影響あり（新規検出）"),
           row("CVE-5", "3.0.2-0ubuntu1.20", 9.0, "Rank-S", status="影響なし")]          # 影響なしは含めない
    table = tables.update_table(rows, new, config)
    assert len(table) == 1
    line = dict(zip(tables.UPDATE_HEADER, table[0]))
    assert line["この版以上に更新"] == "3.0.2-0ubuntu1.17"      # 文字列の順では 1.9 が最大になってしまう
    assert (line["脆弱性（件）"], line["修正版の無いもの（件）"], line["うち会社公表の通達"]) == ("4", "1", "ADV-1")
    assert (line["社内ランク（最も厳しい）"], line["最大CVSS"]) == ("Rank-S", "9.8")
    assert line["CVE（CVSS の高い順、先頭 10 件）"] == "CVE-1、CVE-3、CVE-2、CVE-4"


def test_xlsx_rows_are_capped_but_csv_keeps_everything(examples, tmp_path):
    """Excel の行数の上限（約 104 万行）を超えないよう、シートは xlsx_max_rows で打ち切る。CSV は全件。"""
    from openpyxl import load_workbook

    config_file = tmp_path / "config.yaml"
    config_file.write_text("xlsx_max_rows: 3\n", encoding="utf-8")
    result = run_examples(examples, tmp_path, "--config", str(config_file))
    assert result.exit_code == 0, result.output
    out = tmp_path / "out"
    new_csv = read_csv(out / "report_new_findings.csv")
    assert len(new_csv) - 1 > 3
    workbook = load_workbook(out / "report.xlsx", read_only=True)
    assert workbook["新規検出（参考）"].max_row == 4                 # 見出し + 3 行
    assert f"全 {len(new_csv) - 1:,} 行は report_new_findings.csv" in result.output


def test_previous_run_comparison(examples, tmp_path):
    """前回の出力フォルダと比べ、新たに影響あり / 解消 / 継続 / 今回の回収なし を出す。"""
    import csv

    first = tmp_path / "first"
    result = run_examples(examples, tmp_path, "--no-xlsx")
    assert result.exit_code == 0, result.output
    (tmp_path / "out").rename(first)

    # 前回の結果を作り替える: 影響ありの 1 行を消す（今回は「新たに影響あり」）、修正済みの行と、
    # 回収していない環境の行を足す（今回は「解消」と「今回の回収なし」）
    path = first / "report_detail.csv"
    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    header = list(rows[0])
    affected = [r for r in rows if r["影響有無"].startswith("影響あり")]
    removed = affected[0]
    rows.remove(removed)
    fixed = {**affected[1], "CVE_ID": "CVE-2000-0001"}
    gone = {**affected[1], "該当環境": "decommissioned-host", "CVE_ID": "CVE-2000-0002"}
    with path.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=header)
        writer.writeheader()
        writer.writerows([*rows, fixed, gone])

    result = run_examples(examples, tmp_path, "--previous", str(first))
    assert result.exit_code == 0, result.output
    changes = read_csv(tmp_path / "out" / "report_changes.csv")
    by_change = {}
    for line in changes[1:]:
        by_change.setdefault(line[0], []).append(line)
    new = {(r[3], r[7], r[4]) for r in by_change["新たに影響あり"]}
    assert (removed["該当環境"], removed["CVE_ID"] or removed["社内通達ID"], removed["製品・パッケージ名"]) in new
    assert [(r[3], r[7]) for r in by_change["解消"]] == [(fixed["該当環境"], "CVE-2000-0001")]
    assert [(r[3], r[7]) for r in by_change["今回の回収なし"]] == [("decommissioned-host", "CVE-2000-0002")]
    assert by_change["継続"]
    assert changes[1][0] == "新たに影響あり"                          # 新たに影響ありが先頭
    assert "前回との差分" in result.output

    from openpyxl import load_workbook
    assert "前回との差分" in load_workbook(tmp_path / "out" / "report.xlsx", read_only=True).sheetnames
    # 前回のフォルダに上書きしない
    bad = run_examples(examples, tmp_path, "--previous", str(tmp_path / "out"))
    assert bad.exit_code == 2 and "同じフォルダ" in bad.output


def test_new_and_old_command_names(examples, tmp_path):
    """新しいコマンド名で動き、旧名（0.7.0 まで）も別名として動いて新しい名前を案内する。一覧に旧名は出ない。"""
    runner = CliRunner()
    help_text = runner.invoke(main, ["--help"]).output
    for new in ("update", "check", "preview", "scan-file", "export-sbom", "demo", "init"):
        assert new in help_text
    for old in ("db-update", "check-inputs", "scan-archive", "build-sbom"):
        assert old not in help_text
    result = runner.invoke(main, ["check-inputs", "--inventory-dir", str(examples / "inventory")])
    assert result.exit_code == 0 and "zk preview" in result.output
    result = run_examples(examples, tmp_path, "--no-xlsx")
    assert result.exit_code == 0


def test_demo_builds_sample_report(tmp_path):
    """zk demo は同梱のサンプルで、ネットにつながずにレポートの見本を作る。"""
    out = tmp_path / "demo"
    result = CliRunner().invoke(main, ["demo", "--out-dir", str(out)])
    assert result.exit_code == 0, result.output
    assert (out / "report.xlsx").is_file() and (out / "report_detail.csv").is_file()
    assert "見本のレポート" in result.output


def test_init_creates_work_folder_and_keeps_existing_files(tmp_path):
    """zk init は作業フォルダの置き場所と空のサーバー一覧を作る。既にあるサーバー一覧は上書きしない。"""
    base = tmp_path / "vuln"
    result = CliRunner().invoke(main, ["init", str(base)])
    assert result.exit_code == 0, result.output
    for name in ("inventory", "advisory", "reports", "logs"):
        assert (base / name).is_dir()
    assert (base / "env_master.csv").read_text(encoding="utf-8-sig") == "env_name,exposure,system_name\n"
    assert "check_all.ps1" in (base / "はじめに.txt").read_text(encoding="utf-8-sig")
    (base / "env_master.csv").write_text("env_name,exposure\nweb01,internet\n", encoding="utf-8")
    assert CliRunner().invoke(main, ["init", str(base)]).exit_code == 0
    assert "web01" in (base / "env_master.csv").read_text(encoding="utf-8")
