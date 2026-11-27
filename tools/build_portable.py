"""インストール不要の配布物（ポータブル版）を作る。

    python tools/build_portable.py --out dist [--python-embed python-3.13.5-embed-amd64.zip --name windows-x64]

作るもの（dist/zeijaku-kakunin-<版>[-<name>]/ と、その zip）:
    zk.pyz                 ツール本体と依存ライブラリ（すべて Python だけで書かれたもの）を 1 つにした実行ファイル
    zk.cmd / zk            zk.pyz を実行する入口（Windows / Linux）。python\ があればそれを使う
    python\                --python-embed を付けたときだけ。python.org の「埋め込み用」Python をそのまま置く
    scripts\check_all.ps1  調査をまとめて実行するスクリプト
    collectors\            対象マシンで使う回収スクリプト
    config.yaml、LICENSE、THIRD_PARTY_LICENSES.txt（同梱した依存ライブラリと Python のライセンス）

管理 PC には何もインストールしない。フォルダを置いて実行し、要らなくなればフォルダごと消す。
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
import zipapp
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEPENDENCIES = ["pyyaml>=6", "packaging>=23", "click>=8", "openpyxl>=3.1"]

ZK_CMD = r"""@echo off
rem 脆弱確認（zk）。インストール不要。同じフォルダの python\ があればそれを使い、無ければ PATH の python を使う
setlocal
set "ZK_HOME=%~dp0"
set "PYTHONUTF8=1"
if exist "%ZK_HOME%python\python.exe" (
  "%ZK_HOME%python\python.exe" "%ZK_HOME%zk.pyz" %*
) else (
  python "%ZK_HOME%zk.pyz" %*
)
exit /b %ERRORLEVEL%
"""

ZK_SH = """#!/bin/sh
# 脆弱確認（zk）。インストール不要（Python 3.10 以降が必要）
here="$(cd "$(dirname "$0")" && pwd)"
exec "${PYTHON:-python3}" "$here/zk.pyz" "$@"
"""

MAIN = """import sys
from zeijaku_kakunin.cli import main

sys.exit(main(prog_name="zk"))
"""


def version() -> str:
    for line in (ROOT / "src" / "zeijaku_kakunin" / "__init__.py").read_text(encoding="utf-8").splitlines():
        if line.startswith("__version__"):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit("version not found")


def build_pyz(target: Path, licenses: list[str]) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        lib = Path(tmp) / "lib"
        subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "--no-compile", "--disable-pip-version-check",
                        "--target", str(lib), *DEPENDENCIES], check=True)
        # 依存ライブラリのライセンスを集める（MIT / BSD などは配布物にライセンス文を含める必要がある）
        for info in sorted(lib.glob("*.dist-info")):
            texts = [p for p in info.rglob("*") if p.is_file() and p.name.upper().startswith(("LICENSE", "LICENCE", "COPYING", "NOTICE"))]
            meta = (info / "METADATA").read_text(encoding="utf-8", errors="replace")
            name = next((l.split(":", 1)[1].strip() for l in meta.splitlines() if l.startswith("Name:")), info.name)
            ver = next((l.split(":", 1)[1].strip() for l in meta.splitlines() if l.startswith("Version:")), "")
            licenses.append(f"==== {name} {ver} ====\n" + "\n".join(t.read_text(encoding="utf-8", errors="replace") for t in texts))
        # 環境ごとに作り直す部品（C の拡張）は使わない。PyYAML は Python だけの実装で動く
        for compiled in [*lib.rglob("*.so"), *lib.rglob("*.pyd")]:
            compiled.unlink()
        for meta_dir in [*lib.glob("*.dist-info"), *lib.glob("bin")]:
            shutil.rmtree(meta_dir, ignore_errors=True)
        shutil.copytree(ROOT / "src" / "zeijaku_kakunin", lib / "zeijaku_kakunin",
                        ignore=shutil.ignore_patterns("__pycache__"))
        (lib / "__main__.py").write_text(MAIN, encoding="utf-8")
        zipapp.create_archive(lib, target, compressed=True)


def add_embedded_python(embed_zip: Path, dest: Path, licenses: list[str]) -> None:
    with zipfile.ZipFile(embed_zip) as archive:
        archive.extractall(dest)
    # 埋め込み用の Python は ._pth に書いた場所しか見ないので、zk.pyz の置き場所（1 つ上）は sys.argv から読める。
    # site は使わない（使う人の環境の Python パッケージを読み込まない）
    license_file = dest / "LICENSE.txt"
    if license_file.exists():
        licenses.append("==== Python (embeddable package) ====\n" + license_file.read_text(encoding="utf-8", errors="replace"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default="dist")
    parser.add_argument("--python-embed", help="python.org の Windows 用「embeddable package」の zip")
    parser.add_argument("--name", help="配布物の名前に付ける区別（例 windows-x64）")
    args = parser.parse_args()

    name = f"zeijaku-kakunin-{version()}" + (f"-{args.name}" if args.name else "")
    out = Path(args.out)
    folder = out / name
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir(parents=True)
    licenses: list[str] = []

    build_pyz(folder / "zk.pyz", licenses)
    (folder / "zk.cmd").write_bytes(ZK_CMD.replace("\n", "\r\n").encode("utf-8"))
    (folder / "zk").write_text(ZK_SH, encoding="utf-8", newline="\n")
    if args.python_embed:
        add_embedded_python(Path(args.python_embed), folder / "python", licenses)
    (folder / "scripts").mkdir()
    shutil.copy2(ROOT / "scripts" / "check_all.ps1", folder / "scripts")
    shutil.copytree(ROOT / "collectors", folder / "collectors")
    for file in ("config.yaml", "LICENSE"):
        shutil.copy2(ROOT / file, folder)
    (folder / "THIRD_PARTY_LICENSES.txt").write_text(
        "同梱している依存ライブラリと Python のライセンス\n\n" + "\n\n".join(licenses), encoding="utf-8")
    (folder / "README.txt").write_text(
        "脆弱確認（zk）" + version() + "\n\n"
        "インストール不要です。このフォルダを置いて、ここで次を実行します（Windows）。\n"
        "  zk.cmd update             脆弱性データを最新にする\n"
        "  zk.cmd check --help       照合してレポートを出す\n"
        "  powershell -ExecutionPolicy Bypass -File scripts\\check_all.ps1 -BaseDir D:\\vuln\n"
        "要らなくなったら、このフォルダごと消します。\n\n"
        "使い方: https://github.com/hsgwa/cve_chk/blob/main/docs/USAGE.md\n", encoding="utf-8")

    zip_path = shutil.make_archive(str(out / name), "zip", out, name)
    print(folder)
    print(zip_path)


if __name__ == "__main__":
    main()
