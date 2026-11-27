from datetime import date

import pytest
from openpyxl import Workbook

from zeijaku_kakunin.advisory import AdvisoryFormatError, load_advisories


def make_xlsx(path, rows, title="Sheet1", merges=()):
    workbook = Workbook()
    sheet = workbook.active
    sheet.title = title
    for row in rows:
        sheet.append(row)
    for cell_range in merges:
        sheet.merge_cells(cell_range)
    workbook.save(path)
    return path


def test_japanese_headers(tmp_path, config):
    path = make_xlsx(tmp_path / "a.xlsx", [
        ["通達番号", "CVE 番号", "製品名", "影響バージョン", "公表日", "社内ランク", "対応期限(日)", "備考"],
        ["ADV-1", "CVE-2021-44228", "log4j-core", "<2.15.0", date(2026, 11, 2), "Rank-S", "3日", "メモ"],
        ["ADV-2", None, "KB5034441", "missing", "2026/11/05", None, None, None],
        [None, None, None, None, None, None, None, None],
        ["ADV-3", None, "Tomcat", 9.0, None, None, 14.0, None],
    ])
    items = load_advisories(path, config)
    assert [a.advisory_id for a in items] == ["ADV-1", "ADV-2", "ADV-3"]
    first = items[0]
    assert (first.cve_id, first.product_name, first.affected_version) == ("CVE-2021-44228", "log4j-core", "<2.15.0")
    assert (first.published_date, first.company_rank, first.deadline_days, first.note) == (
        date(2026, 11, 2), "Rank-S", 3, "メモ")
    assert items[1].is_kb and items[1].published_date == date(2026, 11, 5)
    # Excel の数値セル 9.0 は 9 として保存されるため "9" になる（版の条件は文字列で書くこと）
    assert items[2].affected_version == "9" and items[2].deadline_days == 14


def test_multiple_cves_in_one_cell(tmp_path, config):
    path = make_xlsx(tmp_path / "a.xlsx", [
        ["通達番号", "CVE番号", "製品名"],
        ["ADV-1", "CVE-2021-44228\ncve-2021-45046、CVE-2021-44228", "log4j-core"],
    ])
    items = load_advisories(path, config)
    assert [a.cve_id for a in items] == ["CVE-2021-44228", "CVE-2021-45046"]
    assert {a.advisory_id for a in items} == {"ADV-1"}


def test_header_row_sheet_and_custom_columns(tmp_path, config):
    path = make_xlsx(tmp_path / "a.xlsx", [
        ["脆弱性対応依頼一覧"],
        [],
        ["整理番号", "脆弱性ID", "ソフト"],
        ["X-1", "CVE-2024-0001", "nginx"],
    ], title="一覧")
    config["advisory_input"].update(sheet="一覧", header_row=3, columns={
        "advisory_id": ["整理番号"], "cve_id": ["脆弱性ID"], "product_name": ["ソフト"]})
    items = load_advisories(path, config)
    assert [(a.advisory_id, a.cve_id, a.product_name) for a in items] == [("X-1", "CVE-2024-0001", "nginx")]


def test_merged_cells(tmp_path, config):
    path = make_xlsx(tmp_path / "a.xlsx", [
        ["通達番号", "CVE番号", "製品名"],
        ["ADV-1", "CVE-2024-0001", "nginx"],
        [None, "CVE-2024-0002", "nginx"],
    ], merges=["A2:A3"])
    config["advisory_input"]["fill_merged"] = True
    assert [a.advisory_id for a in load_advisories(path, config)] == ["ADV-1", "ADV-1"]


def test_missing_id_uses_row_number(tmp_path, config):
    path = make_xlsx(tmp_path / "a.xlsx", [["製品名", "影響バージョン"], ["nginx", "<1.25"]])
    assert load_advisories(path, config)[0].advisory_id == "行2"


def test_missing_required_columns(tmp_path, config):
    path = make_xlsx(tmp_path / "a.xlsx", [["番号", "内容"], ["1", "x"]])
    with pytest.raises(AdvisoryFormatError) as error:
        load_advisories(path, config)
    assert "番号" in str(error.value) and "advisory_input.columns" in str(error.value)


def test_unknown_sheet(tmp_path, config):
    path = make_xlsx(tmp_path / "a.xlsx", [["CVE番号"]])
    config["advisory_input"]["sheet"] = "無い"
    with pytest.raises(AdvisoryFormatError):
        load_advisories(path, config)


def test_csv_cp932(tmp_path, config):
    path = tmp_path / "a.csv"
    path.write_bytes("通達番号,CVE番号,製品名,備考\r\nADV-1,CVE-2024-0001,nginx,至急\r\n".encode("cp932"))
    item = load_advisories(path, config)[0]
    assert (item.advisory_id, item.note) == ("ADV-1", "至急")


def test_example_files_agree(examples, config):
    xlsx = load_advisories(examples / "advisory_list.xlsx", config)
    csv_items = load_advisories(examples / "advisory_list.csv", config)
    assert [a.key for a in xlsx] == [a.key for a in csv_items]
    assert len(xlsx) == 11



def test_cell_types_for_every_field(tmp_path, config):
    """Excel のセルの型（文字列・整数・小数・日付・日時・真偽・空）を、すべての項目で受け付けること。"""
    from datetime import datetime
    header = ["通達番号", "CVE番号", "製品名", "影響バージョン", "公表日", "社内ランク", "対応期限(日)", "備考"]
    rows = [
        ["A1", "CVE-2024-0001", "x", "<1.0", date(2026, 11, 2), "Rank-A", 14, "文字列"],
        [2, None, 123, 9.5, datetime(2026, 11, 2, 9, 30), None, 14.0, 1.5],
        [3.0, None, "y", True, 46328, None, "14日", None],          # 46328 = 2026-11-02 の通し番号
        ["A4", None, "z", "", "2026年11月2日", None, None, None],
        ["A5", None, "w", "", 12, None, None, None],                 # 小さい数値は日付とみなさない
    ]
    items = load_advisories(make_xlsx(tmp_path / "a.xlsx", [header, *rows]), config)
    by_id = {a.advisory_id: a for a in items}
    assert set(by_id) == {"A1", "2", "3", "A4", "A5"}
    assert by_id["2"].product_name == "123" and by_id["2"].affected_version == "9.5" and by_id["2"].note == "1.5"
    assert by_id["2"].published_date == date(2026, 11, 2) and by_id["2"].deadline_days == 14
    assert by_id["3"].published_date == date(2026, 11, 2) and by_id["3"].deadline_days == 14
    assert by_id["A4"].published_date == date(2026, 11, 2)
    assert by_id["A5"].published_date is None


def test_merged_cells_are_filled_by_default(tmp_path, config):
    path = make_xlsx(tmp_path / "a.xlsx", [
        ["通達番号", "CVE番号", "製品名"],
        ["ADV-1", "CVE-2024-0001", "nginx"],
        ["ADV-2", None, "openssl"],
    ], merges=["B2:B3"])
    warnings = []
    items = load_advisories(path, config, warnings)
    assert [(a.advisory_id, a.cve_id) for a in items] == [("ADV-1", "CVE-2024-0001"), ("ADV-2", "CVE-2024-0001")]
    assert warnings == []


def test_merged_cells_warn_when_not_filled(tmp_path, config):
    path = make_xlsx(tmp_path / "a.xlsx", [
        ["通達番号", "CVE番号", "製品名"],
        ["ADV-1", "CVE-2024-0001", "nginx"],
        ["ADV-2", None, "openssl"],
    ], merges=["B2:B3"])
    config["advisory_input"]["fill_merged"] = False
    warnings = []
    items = load_advisories(path, config, warnings)
    assert items[1].cve_id == ""
    assert len(warnings) == 1 and "B2:B3" in warnings[0]


def test_other_sheets_with_data_are_warned(tmp_path, config):
    from openpyxl import Workbook

    workbook = Workbook()
    first = workbook.active
    first.title = "11月"
    first.append(["通達番号", "CVE番号"])
    first.append(["ADV-1", "CVE-2024-0001"])
    second = workbook.create_sheet("12月")
    second.append(["通達番号", "CVE番号"])
    second.append(["ADV-2", "CVE-2024-0002"])
    workbook.create_sheet("空のシート")
    path = tmp_path / "a.xlsx"
    workbook.save(path)
    warnings = []
    assert [a.advisory_id for a in load_advisories(path, config, warnings)] == ["ADV-1"]
    assert len(warnings) == 1 and "「12月」" in warnings[0] and "空のシート" not in warnings[0]


@pytest.mark.parametrize("text, warned", [
    ("CVE-2024-0001", False),
    ("CVE-2024-0001, CVE-2024-0002", False),
    ("ＣＶＥ－２０２４－０００１", False),       # 全角は NFKC で読める
    ("CVE-2024-123", True),                       # 番号の桁不足
    ("CVE-2024-0001、CVE2024-0002", True),        # 2 つ目のハイフン抜け
    ("2024-0001", True),                          # CVE- の書き忘れ
    ("-", False),
])
def test_unreadable_cve_numbers_are_warned(tmp_path, config, text, warned):
    path = make_xlsx(tmp_path / "a.xlsx", [["通達番号", "CVE番号", "製品名"], ["ADV-1", text, "nginx"]])
    warnings = []
    load_advisories(path, config, warnings)
    assert bool(warnings) == warned
    if warned:
        assert "2 行目" in warnings[0]
