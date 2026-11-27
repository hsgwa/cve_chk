"""CLI エントリポイント。"""
from __future__ import annotations

import json
import sys
from datetime import date, datetime
from pathlib import Path

import click

from . import __version__
from .config import load_config
from .cvelist import CveListError, load_cve_list
from .inventory import load_inventories, load_server
from .judge import Judge
from .maven_lookup import resolve_hashes
from .msrc import MsrcClient
from .report.writers import write_reports
from .sbom_builder import assign_purls, write_sboms
from .trivy_runner import TrivyNotFoundError, scan_environments
from .vulndb.ecosystems import needed_sources
from .vulndb.scanner import scan_with_vulndb, stale_sources
from .vulndb.store import VulnDB, VulnDBError


def _safe_streams() -> None:
    """表示できない文字で止まらないようにする。

    英語版の Windows（cp1252）などでは、日本語の表示で UnicodeEncodeError になり、処理が途中で止まっていた
    （Windows Server の CI で確認）。表示できない文字は ? に置き換える。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass


_safe_streams()


def _default_config() -> str | None:
    return "config.yaml" if Path("config.yaml").is_file() else None


def _echo(message: str) -> None:
    click.echo(message, err=True)


def _parse_date(_ctx, _param, value: str | None) -> date | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError as exc:
        raise click.BadParameter("YYYY-MM-DD の形式で指定してください") from exc


@click.group()
@click.version_option(__version__, prog_name="脆弱確認（zk）")
def main() -> None:
    """脆弱確認（zk）: サーバーから回収したソフトの一覧を、脆弱性の情報と突き合わせます。

    \b
    はじめて使うとき:
      zk demo                 サンプルでレポートの見本を作る
      zk init D:\\vuln         作業フォルダを作る（中の「はじめに.txt」を読む）

    \b
    ふだんの流れ:
      zk update --inventory-dir D:\\vuln\\inventory     脆弱性データを最新にする
      zk check D:\\vuln\\inventory\\web01               1 台を調べてレポートを出す
      zk check D:\\vuln\\inventory\\web01 --cve-list 通達.xlsx   一覧の CVE ごとに影響の有無も出す
    """


@main.command("update")
@click.option("--inventory-dir", "--sbom-dir", "inventory_dir", type=click.Path(exists=True, file_okay=False),
              help="回収物のフォルダ（1 台ぶん、または複数台を並べたフォルダ）。出てきたソフトの種類のデータを取得する")
@click.option("--ecosystem", "ecosystems", multiple=True,
              help="追加で取得するデータ（例: Maven、PyPI、Ubuntu、\"Amazon Linux:2023\"）。複数指定可")
@click.option("--import", "imports", multiple=True, metavar="名前=ZIP",
              help="手元にある OSV 形式の zip を取り込む（例: Maven=C:\\dl\\Maven.zip）。ネットに出られない場合用")
@click.option("--full", "force_full", is_flag=True, help="差分ではなく全件を取り直す")
@click.option("--db-dir", help="脆弱性データの置き場所（省略時は config.yaml の vulndb.dir）")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False), help="設定ファイル")
@click.option("--list", "show", is_flag=True, help="取得済みのデータを表示するだけ")
def db_update(inventory_dir, ecosystems, imports, force_full, db_dir, config_path, show):
    """脆弱性データ（OSV.dev / Amazon Linux の公式情報）を取得・更新します。

    引数なしで実行すると、取得済みのデータをすべて更新します。
    2 回目以降は前回からの変更分だけを取得し、config.yaml の vulndb.full_refresh_days ごとに全件を取り直します。
    """
    config = load_config(config_path or _default_config())
    db = VulnDB(db_dir or config["vulndb"]["dir"], config, log=_echo)
    existing = db.sources()
    if show:
        if not existing:
            click.echo("取得済みのデータはありません")
        for name, info in sorted(existing.items()):
            click.echo(f"{name}: {info['records']} 件（最終確認 {info['updated_at']}、全件取得 {info['full_at'] or '-'}）")
        return

    # --import だけを指定したときは取り込みだけ行う（取得済みの他のデータをダウンロードし直さない）
    targets = [] if imports and not ecosystems and not inventory_dir else list(existing)
    for name in ecosystems:
        if name not in targets:
            targets.append(name)
    if inventory_dir:
        envs = load_inventories(inventory_dir)
        assign_purls(envs)
        found, unsupported = needed_sources(envs, config)
        added = [name for name in found if name not in targets]
        targets.extend(added)
        if added:
            _echo("回収データから追加する取得対象: " + "、".join(added))
        for name, count in sorted(unsupported.items()):
            _echo(f"注意: {name} は照合できません（{count} 件のパッケージ）")
    imported = {item.partition("=")[0] for item in imports}
    targets = [name for name in targets if name not in imported]
    if not targets and not imports:
        raise click.UsageError("取得済みのデータがありません。初回は --inventory-dir か --ecosystem を指定してください")

    errors = {}
    for item in imports:
        name, _, path = item.partition("=")
        if not name or not path or not Path(path).is_file():
            raise click.BadParameter(f"「名前=ZIPファイル」の形で指定してください: {item}", param_hint="--import")
        try:
            count = db.import_zip(name, path)
            _echo(f"取り込み: {name} {count} 件")
        except Exception as exc:
            errors[name] = str(exc)
    errors.update(db.update(targets, force_full=force_full))
    made = db.ensure_slim()
    if made:
        _echo(f"照合を速くするための縮小版を作りました: {made} 件（大きな記録だけ。初回のみ）")
    unknown = db.unknown_ecosystems()
    db.close()
    if unknown:
        _echo("注意: 脆弱性データに、分類されていない系統があります（照合に使っていません）: " + "、".join(unknown[:20]))
        _echo("      修正情報がこの系統にしか無い脆弱性は見落とします。docs/DEFECTS.md の手順で確認してください。")
    if errors:
        for name, message in errors.items():
            _echo(f"エラー: {name}: {message}")
        _echo("更新できなかったデータは前回の内容のまま残っています。そのデータが無いエコシステムは照合されず「判定不能」になります。")
        sys.exit(1)
    _echo(f"完了: {db.dir}")


@main.command("check")
@click.argument("server", type=click.Path(exists=True, file_okay=False))
@click.option("--cve-list", type=click.Path(exists=True, dir_okay=False),
              help="調べたい CVE の一覧（Excel / CSV / テキスト。CVE 番号がどこかに書いてあればよい）")
@click.option("--out-dir", help="レポートの出力先（省略時は out\\<サーバー名>）")
@click.option("--previous", type=click.Path(exists=True, file_okay=False),
              help="前回の出力フォルダ。比べて「新たに見つかった」「解消」を出す")
@click.option("--db-dir", help="脆弱性データの置き場所（省略時は config.yaml の vulndb.dir）")
@click.option("--cache-dir", default="cache", show_default=True, help="外部データのキャッシュ置き場")
@click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False),
              help="設定ファイル（省略時はカレントの config.yaml）")
@click.option("--offline", is_flag=True, help="Microsoft の公開データをキャッシュからのみ使う")
@click.option("--no-msrc", is_flag=True, help="Windows OS の判定を行わない")
@click.option("--resolve-hashes", "resolve", is_flag=True, help="名前の分からない jar を SHA-1 で Maven Central に照会する")
@click.option("--no-xlsx", is_flag=True, help="Excel を出力しない（CSV のみ）")
@click.option("--base-date", callback=_parse_date, help="実行日として扱う日付 YYYY-MM-DD（省略時は今日）")
@click.option("--scanner", type=click.Choice(["osv", "trivy"]),
              help="照合に使うもの。osv = 手元の脆弱性データ（既定）、trivy = Trivy")
@click.option("--trivy-results-dir", type=click.Path(exists=True, file_okay=False),
              help="保存済みの Trivy 結果を使う（--scanner trivy の場合）")
@click.option("--save-trivy-json", type=click.Path(file_okay=False), help="Trivy の生の結果を保存するフォルダ")
@click.option("--sample-data", is_flag=True, hidden=True, help="同梱のサンプル（zk demo）。データの古さを警告しない")
def check(server, cve_list, out_dir, previous, db_dir, cache_dir, config_path, offline, no_msrc, resolve, no_xlsx,
          base_date, scanner, trivy_results_dir, save_trivy_json, sample_data=False):
    """1 台のサーバーを調べてレポートを出します。

    SERVER は回収物のフォルダ（対象マシンの out\\<ホスト名>\\ をそのまま置いたもの）です。
    """
    db_info = None
    try:
        config = load_config(config_path or _default_config())
        scanner = scanner or ("trivy" if trivy_results_dir else str(config.get("scanner") or "osv"))
        today = base_date or date.today()
        env = load_server(server)
        out = Path(out_dir) if out_dir else Path("out") / env.name
        previous_rows = None
        if previous:
            from .report.diff import load_previous

            if Path(previous).resolve() == out.resolve():
                raise ValueError("--previous と出力先に同じフォルダは指定できません（前回の結果を上書きしてしまうため）")
            previous_rows = load_previous(previous)
        cves, list_warnings = load_cve_list(cve_list) if cve_list else (None, [])
        _echo(f"サーバー: {env.name}（ソフトウェア {len(env.components)} 件）"
              + (f"、CVE の一覧 {len(cves)} 件" if cves is not None else ""))
        for warning in list_warnings:
            _echo(f"注意: {warning}")

        if resolve:
            count, error = resolve_hashes([env], Path(cache_dir) / "maven_sha1.json")
            _echo(f"SHA-1 で特定できた jar: {count} 件" + (f"（{error}）" if error else ""))

        messages = list(list_warnings)
        if scanner == "osv":
            db = VulnDB(db_dir or config["vulndb"]["dir"], config)
            if not db.exists():
                raise VulnDBError(
                    f"脆弱性データがありません（{db.dir}）。先に次を実行してください:\n"
                    f"  zk update --inventory-dir {server}")
            assign_purls([env])
            db_info = db.sources()
            stale = [] if sample_data else stale_sources(db, config)
            if stale:
                messages.append("脆弱性データの更新が古くなっています: " + "、".join(stale) + "（zk update で更新）")
            findings = scan_with_vulndb([env], db, config, log=_echo)
            db.close()
            if env.missing_db:
                messages.append("脆弱性データが無いため照合していないもの: " + "、".join(sorted(env.missing_db))
                                + f"（zk update --inventory-dir {server} で取得）")
        else:
            write_sboms([env], out / "sbom")
            findings = scan_environments([env], config, trivy_results_dir, save_trivy_json, log=_echo)

        msrc = None
        if cves and not no_msrc and (config.get("msrc") or {}).get("enabled", True):
            msrc = MsrcClient(Path(cache_dir) / "msrc", config, offline=offline)
        result = Judge(env, findings, config, msrc).run(cves)
        result.messages.extend(messages)
        written, lines = write_reports(out, env, result, cves, config, today, xlsx=not no_xlsx,
                                       db_info=db_info, previous=previous_rows)
    except TrivyNotFoundError as exc:
        _echo(f"エラー: {exc}")
        sys.exit(2)
    except (CveListError, FileNotFoundError, ValueError, VulnDBError) as exc:
        _echo(f"エラー: {exc}")
        sys.exit(2)

    click.echo("==== サマリ ====")
    for line in lines:
        click.echo(line)
    click.echo("==== 出力ファイル ====")
    for path in written:
        click.echo(str(path))


@main.command("scan-file")
@click.argument("paths", nargs=-1, required=True, type=click.Path(exists=True))
@click.option("--inventory-dir", required=True, type=click.Path(file_okay=False),
              help="結果を置く回収物のフォルダ（<環境名>/archive_inventory.json を作る）")
@click.option("--env", "env_name", help="環境名。指定するとすべてを 1 つの環境にまとめる（例: 関数とそのレイヤー）。"
              "省略時はファイル・フォルダごとに、その名前の環境を作る")
def scan_archive_command(paths, inventory_dir, env_name):
    """zip / jar / war / ear / whl（と展開したフォルダ）の中のライブラリを調べ、回収物として置きます。

    Lambda のデプロイ用 zip やレイヤー、アプリケーションの war や fat jar などを、サーバーで回収せずに調べられます。
    作った回収物は zk check <inventory-dir>\\<環境名> で照合します。
    """
    from .archive_scan import iter_targets, scan

    for name, targets in iter_targets([Path(p) for p in paths], env_name):
        result = scan(targets)
        out = Path(inventory_dir) / name
        out.mkdir(parents=True, exist_ok=True)
        file = out / "archive_inventory.json"
        data = result.inventory(name, [str(t) for t in targets])
        file.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        click.echo(f"{name}: jar 等 {len(data['sections']['java_archives']['items'])} 件、"
                   f"Python {len(data['sections']['python_packages']['items'])} 件、"
                   f"npm {len(data['sections']['node_packages']['items'])} 件、"
                   f"NuGet {len(data['sections']['dotnet_packages']['items'])} 件"
                   + (f"、読めなかったもの {len(result.skipped)} 件" if result.skipped else "") + f" → {file}")


@main.command("export-sbom")
@click.option("--inventory-dir", required=True, type=click.Path(exists=True, file_okay=False),
              help="回収物のフォルダ（1 台ぶん、または複数台を並べたフォルダ）")
@click.option("--out-dir", default="work/sbom", show_default=True, help="SBOM の出力先")
def build_sbom_command(inventory_dir, out_dir):
    """Windows の inventory.json から CycloneDX SBOM を作るだけ行います（Trivy を使う場合）。"""
    written = write_sboms(load_inventories(inventory_dir), out_dir)
    if not written:
        click.echo("SBOM を作る対象（Java / Python / npm / NuGet）がありませんでした")
    for path in written:
        click.echo(str(path))


@main.command("preview")
@click.argument("server", type=click.Path(exists=True, file_okay=False))
@click.option("--cve-list", type=click.Path(exists=True, dir_okay=False), help="調べたい CVE の一覧")
def preview(server, cve_list):
    """回収物と CVE の一覧が正しく読めるかを確かめます（照合はしません）。"""
    try:
        env = load_server(server)
        cves, warnings = load_cve_list(cve_list) if cve_list else (None, [])
    except (CveListError, FileNotFoundError, ValueError) as exc:
        _echo(f"エラー: {exc}")
        sys.exit(2)
    click.echo(f"==== サーバー: {env.name} ====")
    click.echo(f"OS: {env.os_name or env.os_family} {env.os_build}".rstrip())
    click.echo(f"回収日時: {env.collected_at or '不明'}")
    click.echo(f"ソフトウェア: {len(env.components)} 件"
               + ("" if env.hotfixes is None else f"、適用済みの更新プログラム（KB） {len(env.hotfixes)} 件"))
    for name in env.files:
        click.echo(f"    {name}")
    for warning in env.warnings:
        click.echo(f"    注意: {warning}")
    if cves is not None:
        click.echo(f"==== CVE の一覧: {len(cves)} 件 ====")
        click.echo("    " + "、".join(cves[:20]) + (f" ほか {len(cves) - 20} 件" if len(cves) > 20 else ""))
        for warning in warnings:
            click.echo(f"    注意: {warning}")


def _find_examples() -> Path | None:
    """同梱のサンプル（examples/）を探す。配布物では zk.pyz の隣、リポジトリでは src の 2 つ上。"""
    for folder in Path(__file__).resolve().parents:
        if (folder / "examples" / "cve_list.xlsx").is_file():
            return folder / "examples"
    return None


@main.command("demo")
@click.option("--out-dir", default="demo", show_default=True, help="サンプルのレポートの出力先")
@click.pass_context
def demo(ctx, out_dir):
    """同梱のサンプル（架空のサーバー 4 台）で照合して、レポートの見本を作ります（ネット接続は不要）。"""
    examples = _find_examples()
    if examples is None:
        raise click.ClickException("サンプル（examples フォルダ）が見つかりません。配布物の zip を展開し直してください")
    made = []
    for server in sorted(p for p in (examples / "inventory").iterdir() if p.is_dir()):
        out = Path(out_dir) / server.name
        ctx.invoke(check, server=str(server), cve_list=str(examples / "cve_list.xlsx"), out_dir=str(out),
                   previous=None, db_dir=str(examples / "vulndb"), cache_dir=str(examples / "cache"), config_path=None,
                   offline=True, no_msrc=False, resolve=False, no_xlsx=False, base_date=date(2026, 11, 20),
                   scanner="osv", trivy_results_dir=None, save_trivy_json=None, sample_data=True)
        made.append(out.resolve() / "report.xlsx")
    _echo("見本のレポート:")
    for path in made:
        _echo(f"  {path}")


_INIT_README = """\
この作業フォルダの使い方（脆弱確認 zk）

1. inventory\\ の下に、対象マシンから持ち出した回収物を、ホストごとのフォルダのまま置く
     例: inventory\\web01\\cdx_syft.json、inventory\\web01\\os_info.json
2. 調べたい CVE の一覧（会社の通達の Excel など）があれば cve_list\\ に置く（無くてもよい）
3. ツールのフォルダで次を実行する（全サーバーを 1 台ずつ調べる）
     powershell -ExecutionPolicy Bypass -File scripts\\check_all.ps1 -BaseDir {base}
   1 台だけなら
     zk check {base}\\inventory\\web01 --cve-list {base}\\cve_list\\通達.xlsx
4. reports\\<日付>\\<サーバー名>\\report.xlsx を開く

使い方: https://github.com/hsgwa/cve_chk/blob/main/docs/usage/README.md
"""


@main.command("init")
@click.argument("folder", type=click.Path(file_okay=False))
def init_command(folder):
    """作業フォルダを作ります（回収物と CVE の一覧の置き場所、説明のファイル）。"""
    base = Path(folder).resolve()
    for name in ("inventory", "cve_list", "reports", "logs"):
        (base / name).mkdir(parents=True, exist_ok=True)
    readme = base / "はじめに.txt"
    if not readme.exists():
        readme.write_text(_INIT_README.format(base=base), encoding="utf-8-sig")
    _echo(f"作業フォルダ: {base}")
    _echo("作ったもの: inventory\\ cve_list\\ reports\\ logs\\ はじめに.txt")
    _echo(f"次にすること: {readme} を読む")


if __name__ == "__main__":
    main()
