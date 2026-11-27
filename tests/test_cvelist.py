import pytest

from zeijaku_kakunin.cvelist import CveListError, load_cve_list


def test_reads_cve_numbers_from_any_cell_of_any_sheet(tmp_path):
    from openpyxl import Workbook

    workbook = Workbook()
    first = workbook.active
    first.append(["通達番号", "内容"])
    first.append(["A-1", "CVE-2021-44228 と cve-2022-42889 に対応すること"])
    second = workbook.create_sheet("追加")
    second.append(["ＣＶＥ－２０２３－３２６８１"])          # 全角でも読む
    second.append(["CVE-2021-44228"])                    # 重複は 1 つにする
    path = tmp_path / "list.xlsx"
    workbook.save(path)
    cves, warnings = load_cve_list(path)
    assert cves == ["CVE-2021-44228", "CVE-2022-42889", "CVE-2023-32681"] and warnings == []


def test_csv_text_and_typos(tmp_path):
    path = tmp_path / "list.csv"
    path.write_bytes("番号,CVE\n1,CVE-2024-0001\n2,CVE2024-0002\n3,CVE-2024-12\n4,2024-11-20\n".encode("cp932"))
    cves, warnings = load_cve_list(path)
    assert cves == ["CVE-2024-0001"]
    assert len(warnings) == 2 and "3 行目" in warnings[0] and "4 行目" in warnings[1]   # 日付は書き損じにしない
    text = tmp_path / "list.txt"
    text.write_text("CVE-2024-0003\n", encoding="utf-8")
    assert load_cve_list(text)[0] == ["CVE-2024-0003"]


def test_errors(tmp_path):
    empty = tmp_path / "empty.csv"
    empty.write_text("番号\n1\n", encoding="utf-8")
    with pytest.raises(CveListError, match="1 つもありません"):
        load_cve_list(empty)
    old = tmp_path / "old.xls"
    old.write_bytes(b"x")
    with pytest.raises(CveListError, match=".xlsx"):
        load_cve_list(old)
