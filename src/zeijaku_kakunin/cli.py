"""CLI エントリポイント。"""
from __future__ import annotations

import json
import sys
from datetime import date, datetime
from pathlib import Path

import click

from . import __version__
from .advisory import AdvisoryFormatError, load_advisories
from .config import load_config
from .inventory import load_env_master, load_inventories
from .matching.names import build_matcher
from .maven_lookup import resolve_hashes
from .msrc import MsrcClient
from .report.writers import write_reports
from .sbom_builder import assign_purls, write_sboms
from .trivy_runner import TrivyNotFoundError, scan_environments
from .verdict import Judge
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


common_inputs = [
    click.option("--inventory-dir", "--sbom-dir", "inventory_dir", required=True,
                 type=click.Path(exists=True, file_okay=False), help="回収ファイルのフォルダ（<環境名>/ のサブフォルダ構成）"),
    click.option("--env-master", type=click.Path(exists=True, dir_okay=False), help="サーバー一覧（env_master.csv）"),
    click.option("--config", "config_path", type=click.Path(exists=True, dir_okay=False),
                 help="設定ファイル（省略時はカレントの config.yaml）"),
]


def with_options(options):
    def decorator(func):
        for option in reversed(options):
            func = option(func)
        return func
    return decorator


@click.group()
@click.version_option(__version__, prog_name="脆弱確認（zk）")
def main() -> None:
    """脆弱確認（zk）: オフライン環境から回収したソフトの一覧を、会社公表の脆弱性リストと突き合わせます。

    \b
    はじめて使うとき:
      zk demo          サンプルでレポートの見本を作る
      zk init D:\\vuln  作業フォルダを作る（中の「はじめに.txt」を読む）

    \b
    ふだんの流れ:
      zk update   脆弱性データを最新にする
      zk check    照合してレポートを出す
    """


@main.command("update")
@click.option("--inventory-dir", "--sbom-dir", "inventory_dir", type=click.Path(exists=True, file_okay=False),
              help="回収ファイルのフォルダ。ここに新しく出てきたエコシステムのデータも取得する")
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
        envs = load_inventories(inventory_dir, {})
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
@with_options(common_inputs)
@click.option("--advisory", required=True, type=click.Path(exists=True, dir_okay=False),
              help="会社公表の脆弱性リスト（.xlsx / .xlsm / .csv）")
@click.option("--out-dir", default="out", show_default=True, help="レポートの出力先")
@click.option("--only-advisory", is_flag=True, help="会社公表リストにある脆弱性だけを出力する（新規検出を出さない）")
@click.option("--base-date", callback=_parse_date, help="実行日として扱う日付 YYYY-MM-DD（省略時は今日）")
@click.option("--scanner", type=click.Choice(["osv", "trivy", "none"]),
              help="CVE の照合方法。osv = 手元の脆弱性データ（既定）、trivy = Trivy、none = 照合しない")
@click.option("--db-dir", help="脆弱性データの置き場所（省略時は config.yaml の vulndb.dir）")
@click.option("--skip-trivy", is_flag=True, hidden=True, help="--scanner none と同じ（旧オプション）")
@click.option("--trivy-results-dir", type=click.Path(exists=True, file_okay=False),
              help="保存済みの Trivy 結果を使う（--scanner trivy の場合）")
@click.option("--save-trivy-json", type=click.Path(file_okay=False), help="Trivy の生の結果を保存するフォルダ")
@click.option("--work-dir", default="work", show_default=True, help="生成した SBOM の置き場所（Trivy 用）")
@click.option("--cache-dir", default="cache", show_default=True, help="外部データのキャッシュ置き場")
@click.option("--offline", is_flag=True, help="Microsoft の公開データをキャッシュからのみ使う")
@click.option("--no-msrc", is_flag=True, help="Windows OS のビルド番号による判定を行わない")
@click.option("--resolve-hashes", "resolve", is_flag=True, help="名前の分からない jar を SHA-1 で Maven Central に照会する")
@click.option("--no-xlsx", is_flag=True, help="Excel を出力しない（CSV のみ）")
@click.option("--previous", type=click.Path(exists=True, file_okay=False),
              help="前回の出力フォルダ。比べて「新たに影響あり」「解消」を出す（前回との差分）")
@click.option("--sample-data", is_flag=True, hidden=True, help="同梱のサンプル（zk demo）。データの古さを警告しない")
def run(inventory_dir, env_master, config_path, advisory, out_dir, only_advisory, base_date, scanner, db_dir,
        skip_trivy, trivy_results_dir, save_trivy_json, work_dir, cache_dir, offline, no_msrc, resolve, no_xlsx,
        previous, sample_data=False):
    """突き合わせを実行してレポートを出力します。"""
    db_info = None
    try:
        config = load_config(config_path or _default_config())
        if skip_trivy:
            scanner = "none"
        if scanner is None:
            scanner = "trivy" if trivy_results_dir else str(config.get("scanner") or "osv")
        today = base_date or date.today()
        envs = load_inventories(inventory_dir, load_env_master(env_master))
        if not envs:
            raise click.ClickException(f"環境フォルダがありません: {inventory_dir}")
        previous_rows = None
        if previous:
            from .report.diff import load_previous

            if Path(previous).resolve() == Path(out_dir).resolve():
                raise ValueError("--previous と --out-dir に同じフォルダは指定できません（前回の結果を上書きしてしまうため）")
            previous_rows = load_previous(previous)
        advisory_warnings: list[str] = []
        advisories = load_advisories(advisory, config, advisory_warnings)
        _echo(f"環境 {len(envs)} 件、通達 {len(advisories)} 件を読み込みました")
        for warning in advisory_warnings:
            _echo(f"注意: {warning}")

        if resolve:
            count, error = resolve_hashes(envs, Path(cache_dir) / "maven_sha1.json")
            _echo(f"SHA-1 で特定できた jar: {count} 件" + (f"（{error}）" if error else ""))

        findings = []
        messages = list(advisory_warnings)
        if scanner == "osv":
            db = VulnDB(db_dir or config["vulndb"]["dir"], config)
            if not db.exists():
                raise VulnDBError(
                    f"脆弱性データがありません（{db.dir}）。先に次を実行してください:\n"
                    f"  zk update --inventory-dir {inventory_dir}")
            assign_purls(envs)
            db_info = db.sources()
            stale = [] if sample_data else stale_sources(db, config)
            if stale:
                messages.append("脆弱性データの更新が古くなっています: " + "、".join(stale)
                                + "（zk update で更新）")
            findings = scan_with_vulndb(envs, db, config, log=_echo)
            db.close()
            missing = sorted({name for env in envs for name in env.missing_db})
            if missing:
                messages.append("脆弱性データが無いため照合していないもの: " + "、".join(missing)
                                + "（zk update --inventory-dir で取得）")
        elif scanner == "trivy":
            write_sboms(envs, Path(work_dir) / "sbom")
            findings = scan_environments(envs, config, trivy_results_dir, save_trivy_json, log=_echo)
        else:
            _echo("CVE の照合を行わずに実行します（CVE 番号だけの通達は「判定不能」になります）")
            messages.append("CVE の照合（脆弱性データベース）を行わずに実行しました")

        msrc = None
        if not no_msrc and (config.get("msrc") or {}).get("enabled", True):
            msrc = MsrcClient(Path(cache_dir) / "msrc", config, offline=offline)
        result = Judge(envs, findings, config, today, msrc).run(advisories, only_advisory=only_advisory)
        result.messages.extend(messages)
        written, lines = write_reports(out_dir, advisories, envs, result, config, today, xlsx=not no_xlsx,
                                       db_info=db_info, previous=previous_rows)
    except TrivyNotFoundError as exc:
        _echo(f"エラー: {exc}")
        sys.exit(2)
    except (AdvisoryFormatError, FileNotFoundError, ValueError, VulnDBError) as exc:
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
    作った回収物は run（または check_all.ps1）でほかの環境と同じように照合されます。
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
@with_options(common_inputs)
@click.option("--out-dir", default="work/sbom", show_default=True, help="SBOM の出力先")
def build_sbom_command(inventory_dir, env_master, config_path, out_dir):
    """Windows の inventory.json から CycloneDX SBOM を作るだけ行います。"""
    envs = load_inventories(inventory_dir, load_env_master(env_master))
    written = write_sboms(envs, out_dir)
    if not written:
        click.echo("SBOM を作る対象（Java / Python / npm / NuGet）がありませんでした")
    for path in written:
        click.echo(str(path))


@main.command("preview")
@with_options(common_inputs)
@click.option("--advisory", type=click.Path(exists=True, dir_okay=False), help="会社公表の脆弱性リスト")
def check_inputs(inventory_dir, env_master, config_path, advisory):
    """入力が正しく読めるかを確認します（判定は行いません）。"""
    try:
        config = load_config(config_path or _default_config())
        envs = load_inventories(inventory_dir, load_env_master(env_master))
        advisory_warnings: list[str] = []
        advisories = load_advisories(advisory, config, advisory_warnings) if advisory else []
    except (AdvisoryFormatError, FileNotFoundError, ValueError) as exc:
        _echo(f"エラー: {exc}")
        sys.exit(2)

    click.echo("==== 環境 ====")
    for env in envs:
        click.echo(f"{env.name}: {env.exposure} / OS={env.os_name or env.os_family} {env.os_build} / "
                   f"コンポーネント {len(env.components)} 件 / KB "
                   f"{'回収なし' if env.hotfixes is None else str(len(env.hotfixes)) + ' 件'}")
        for name in env.files:
            click.echo(f"    {name}")
        for warning in env.warnings:
            click.echo(f"    注意: {warning}")
    if advisory:
        click.echo(f"==== 会社公表リスト（通達 {len(advisories)} 件） ====")
        for warning in advisory_warnings:
            click.echo(f"    注意: {warning}")
    if advisories:
        click.echo("==== 通達の製品名が回収データのどれに当たるか ====")
        for item in advisories:
            if not item.product_name or item.is_kb:
                continue
            matcher = build_matcher(item.product_name, config.get("aliases") or {})
            hits = sorted({f"{c.name} {c.version}".strip() for env in envs for c in env.components if matcher(c)})
            shown = "、".join(hits[:5]) + (f" ほか {len(hits) - 5} 件" if len(hits) > 5 else "")
            click.echo(f"{item.advisory_id} [{item.product_name}] -> {shown or '該当なし（表記ゆれなら aliases に追加）'}")


def _find_examples() -> Path | None:
    """同梱のサンプル（examples/）を探す。配布物では zk.pyz の隣、リポジトリでは src の 2 つ上。"""
    for folder in Path(__file__).resolve().parents:
        if (folder / "examples" / "env_master.csv").is_file():
            return folder / "examples"
    return None


@main.command("demo")
@click.option("--out-dir", default="demo", show_default=True, help="サンプルのレポートの出力先")
@click.pass_context
def demo(ctx, out_dir):
    """同梱のサンプルで照合して、レポートの見本を作ります（ネット接続は不要）。"""
    examples = _find_examples()
    if examples is None:
        raise click.ClickException("サンプル（examples フォルダ）が見つかりません。配布物の zip を展開し直してください")
    ctx.invoke(run, inventory_dir=str(examples / "inventory"), env_master=str(examples / "env_master.csv"),
               config_path=None, advisory=str(examples / "advisory_list.xlsx"), out_dir=out_dir,
               only_advisory=False, base_date=date(2026, 11, 20), scanner="osv", db_dir=str(examples / "vulndb"),
               skip_trivy=False, trivy_results_dir=None, save_trivy_json=None, work_dir=str(Path(out_dir) / "work"),
               cache_dir=str(examples / "cache"), offline=True, no_msrc=False, resolve=False, no_xlsx=False,
               previous=None, sample_data=True)
    _echo(f"見本のレポート: {Path(out_dir).resolve() / 'report.xlsx'}")


_SERVER_LIST_HEADER = "env_name,exposure,system_name\n"
_INIT_README = """\
この作業フォルダの使い方（脆弱確認 zk）

1. inventory\\ の下に、対象マシンから持ち出した回収物を、ホストごとのフォルダのまま置く
     inventory\\web01\\cdx_syft.json、inventory\\web01\\os_info.json など
2. env_master.csv（サーバー一覧）に、調べる対象マシンを 1 行ずつ書く
     env_name     inventory\\ の下のフォルダ名（ふつうはホスト名）
     exposure     internet（インターネットに公開）か internal（社内だけ）
     system_name  システム名（メモ。空でもよい）
   例: web01,internet,受発注Web
3. advisory\\ に、会社が公表した脆弱性の一覧（Excel か CSV）を置く
4. ツールのフォルダで次を実行する
     powershell -ExecutionPolicy Bypass -File scripts\\check_all.ps1 -BaseDir {base}
5. reports\\<日付>\\report.xlsx を開く

使い方: https://github.com/hsgwa/cve_chk/blob/main/docs/usage/README.md
"""


@main.command("init")
@click.argument("folder", type=click.Path(file_okay=False))
def init_command(folder):
    """作業フォルダを作ります（回収物・サーバー一覧・会社公表リストの置き場所と、説明のファイル）。"""
    base = Path(folder).resolve()
    for name in ("inventory", "advisory", "reports", "logs"):
        (base / name).mkdir(parents=True, exist_ok=True)
    created = []
    server_list = base / "env_master.csv"
    if not server_list.exists():
        server_list.write_text(_SERVER_LIST_HEADER, encoding="utf-8-sig")
        created.append(server_list.name)
    readme = base / "はじめに.txt"
    if not readme.exists():
        readme.write_text(_INIT_README.format(base=base), encoding="utf-8-sig")
        created.append(readme.name)
    _echo(f"作業フォルダ: {base}")
    _echo("作ったもの: inventory\\ advisory\\ reports\\ logs\\ " + " ".join(created))
    _echo(f"次にすること: {readme} を読む")


# ---- 旧名（0.7.0 まで）の別名。一覧には出さず、使うと新しい名前を案内する ----
_OLD_NAMES = {"db-update": "update", "run": "check", "check-inputs": "preview",
              "scan-archive": "scan-file", "build-sbom": "export-sbom"}


def _alias(old: str, new: str) -> click.Command:
    command = main.commands[new]

    def callback(*args, **kwargs):
        _echo(f"注意: 「{old}」は旧名です。今後は「zk {new}」を使ってください")
        return command.callback(*args, **kwargs)

    return click.Command(old, params=command.params, callback=callback, hidden=True,
                         help=f"旧名。zk {new} と同じ")


for _old, _new in _OLD_NAMES.items():
    main.add_command(_alias(_old, _new))


if __name__ == "__main__":
    main()
