"""これまでの不具合と同じ種類の書き方が、コードに入り込んでいないことを確かめる静的な検査。

docs/DEFECTS.md の「類似不良の担保」の一部。新しいコードを足したときもこの検査で引っかかる。
"""
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src" / "vuln_triage"


def sources(pattern="**/*.py"):
    return {p.relative_to(SRC).as_posix(): p.read_text(encoding="utf-8") for p in SRC.glob(pattern)}


def test_purl_is_parsed_only_in_purl_module():
    """PURL の読み取りが複数あると、片方が subpath などを読み落とす（Go の #v2 の不具合）。"""
    offenders = []
    for name, text in sources().items():
        if name == "purl.py":
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if re.search(r"""(\[4:\]|\.partition\("#"\)|rpartition\("@"\)).*""", line) and "purl" in text[:2000].lower():
                offenders.append(f"{name}:{number}: {line.strip()}")
    assert offenders == []


def test_version_comparison_entry_points():
    """版の比較の入口を決めておく（RPM の版を PEP 440 で比べた不具合）。"""
    allowed = {"matching/versions.py", "vulndb/versions.py"}
    for name, text in sources().items():
        if name in allowed:
            continue
        assert "from packaging" not in text, f"{name} が packaging で版を比べている"
        assert "SpecifierSet" not in text, name
        assert not re.search(r"\bversion_matches\(", text), f"{name} は version_matches_in を使うこと"


def test_every_affected_loop_checks_package_name():
    """1つの記録に複数パッケージがあるとき、名前を確かめずに評価しない（Maven / Ubuntu の誤検出）。"""
    text = (SRC / "vulndb" / "scanner.py").read_text(encoding="utf-8")
    loops = [m.start() for m in re.finditer(r"for affected in record\.get\(\"affected\"\)", text)]
    assert loops, "照合の箇所が見つからない"
    for start in loops:
        body = text[start:start + 900]
        assert "normalize_package(" in body or "_first_fixed" in text[max(0, start - 200):start], \
            "affected を回す箇所で、パッケージ名を確かめていない"


@pytest.mark.parametrize("script", sorted((ROOT / "collectors").glob("*.ps1")) + sorted((ROOT / "scripts").glob("*.ps1")),
                         ids=lambda p: p.name)
def test_powershell_patterns(script):
    text = script.read_text(encoding="utf-8-sig")
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        code = line.split("#", 1)[0]
        # 外部コマンドの標準エラーは ErrorRecord になる（ログに RemoteException と出た不具合）
        if "2>&1" in code:
            window = "\n".join(lines[number - 1:number + 8])
            assert "ErrorRecord" in window, f"{script.name}:{number}: 2>&1 の後に ErrorRecord の扱いが無い"
        # Write-Host '...' + ... は連結されずに別々の引数になる
        assert not re.search(r"Write-Host\s+'[^']*'\s*\+", code), f"{script.name}:{number}: Write-Host の + 連結"
    # List を @() で配列にすると失敗することがある（Set-Section の不具合）
    lists = set(re.findall(r"\$(\w+)\s*=\s*New-Object\s+System\.Collections\.Generic\.List", text))
    for name in lists:
        assert not re.search(rf"@\(\${name}\)", text), f"{script.name}: List ${name} を @() で配列にしている"


def test_saved_file_names_are_valid_on_windows():
    from vuln_triage.vulndb.store import VulnDB
    names = ["Maven", "crates.io", "Red Hat", "Rocky Linux", "Amazon Linux:2", "Amazon Linux:2023",
             "Amazon Linux:2:extras:kernel-5.10", "Amazon Linux:2:extras:php8.2", "Ubuntu"]
    for name in names:
        relative = VulnDB._relative_file(name)
        assert not re.search(r'[<>:"\\|?*]', relative), relative
    assert len({VulnDB._relative_file(n) for n in names}) == len(names)    # 別のデータが同じファイルにならない


@pytest.mark.parametrize("args, expect_fetch", [
    (["--import", "crates.io={zip}"], False),                 # 取り込みだけ（他を更新しない）
    ([], True),                                               # 取得済みのデータを更新
    (["--ecosystem", "PyPI"], True),
    (["--import", "crates.io={zip}", "--ecosystem", "PyPI"], True),
    (["--list"], False),
])
def test_db_update_option_combinations(tmp_path, monkeypatch, args, expect_fetch):
    """--import だけなのに取得済みのデータを取り直した不具合と同じ種類の、オプションの組み合わせの確認。"""
    import json
    import zipfile

    from vuln_triage.cli import main
    from vuln_triage.vulndb import store

    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("X.json", json.dumps({"id": "X", "affected": []}))
    db = tmp_path / "db"
    assert CliRunner().invoke(main, ["db-update", "--db-dir", str(db), "--import", f"Maven={archive}"]).exit_code == 0
    fetched = []
    monkeypatch.setattr(store, "_fetch", lambda url: fetched.append(url) or (_ for _ in ()).throw(OSError("offline")))
    CliRunner().invoke(main, ["db-update", "--db-dir", str(db), *[a.format(zip=archive) for a in args]])
    assert bool(fetched) is expect_fetch, fetched


@pytest.mark.parametrize("script", sorted((ROOT / "collectors").glob("*.ps1")) + sorted((ROOT / "scripts").glob("*.ps1")),
                         ids=lambda p: p.name)
def test_powershell_array_parameters_are_split(script):
    """powershell -File で -X 'a','b' と渡すと、配列ではなく 1 つの文字列 'a,b' になる（Windows 実機で確認した
    -ScanRoots の不具合）。[string[]] の引数は、カンマで分け直していること。"""
    text = script.read_text(encoding="utf-8-sig")
    # スクリプトの引数（先頭の param ブロック）だけを見る。関数の引数は -File を通らない
    block = re.search(r"^param\((.*?)^\)", text, re.MULTILINE | re.DOTALL)
    for name in re.findall(r"\[string\[\]\]\s*\$(\w+)", block.group(1) if block else ""):
        assert re.search(rf"\${name}\s*\|\s*ForEach-Object\s*\{{\s*\$_\s*-split\s*'\[,", text), \
            f"{script.name}: -{name} をカンマで分けていない"


def test_collectors_do_not_block_or_delete_outside_their_folder():
    """対象マシンに影響を与えないための約束（#45、#46 と同じ種類の不具合を防ぐ）。

    - Windows: 対象のファイルは他のプロセスの書き込み・削除を妨げない開き方（Open-Shared）で読む。
      OpenRead や、パスを渡す StreamReader / Get-Content は書き込みを妨げる。
    - Linux: 利用者が指定できるフォルダ（WORK_DIR / OUT_DIR）そのものを消さない。消すのは自分で作った作業フォルダだけ。
    """
    win = (ROOT / "collectors" / "collect_win.ps1").read_text(encoding="utf-8-sig")
    for bad in ("OpenRead(", "StreamReader($Path", "Get-Content -LiteralPath $Path", "Get-Content -LiteralPath $file"):
        assert bad not in win, f"collect_win.ps1: {bad}"
    linux = (ROOT / "collectors" / "collect_linux.sh").read_text(encoding="utf-8")
    for bad in ('rm -rf "$WORK_DIR"', 'rm -rf "$OUT_DIR"', 'rm -rf "$SCRIPT_DIR'):
        assert bad not in linux, f"collect_linux.sh: {bad}"
    assert 'rm -rf "$RUN_WORK"' in linux and "mktemp -d" in linux
