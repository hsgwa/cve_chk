"""CLI エントリポイント。"""
from __future__ import annotations

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
from .sbom_builder import write_sboms
from .trivy_runner import TrivyNotFoundError, scan_environments
from .verdict import Judge


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
    click.option("--env-master", type=click.Path(exists=True, dir_okay=False), help="環境マスタ CSV"),
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
@click.version_option(__version__)
def main() -> None:
    """オフライン環境のインベントリと会社公表の脆弱性リストを突き合わせます。"""


@main.command()
@with_options(common_inputs)
@click.option("--advisory", required=True, type=click.Path(exists=True, dir_okay=False),
              help="会社公表の脆弱性リスト（.xlsx / .xlsm / .csv）")
@click.option("--out-dir", default="out", show_default=True, help="レポートの出力先")
@click.option("--only-advisory", is_flag=True, help="会社公表リストにある脆弱性だけを出力する（新規検出を出さない）")
@click.option("--base-date", callback=_parse_date, help="実行日として扱う日付 YYYY-MM-DD（省略時は今日）")
@click.option("--skip-trivy", is_flag=True, help="Trivy を使わずに実行する")
@click.option("--trivy-results-dir", type=click.Path(exists=True, file_okay=False),
              help="保存済みの Trivy 結果を使う（Trivy を実行しない）")
@click.option("--save-trivy-json", type=click.Path(file_okay=False), help="Trivy の生の結果を保存するフォルダ")
@click.option("--work-dir", default="work", show_default=True, help="生成した SBOM の置き場所")
@click.option("--cache-dir", default="cache", show_default=True, help="外部データのキャッシュ置き場")
@click.option("--offline", is_flag=True, help="Microsoft の公開データをキャッシュからのみ使う")
@click.option("--no-msrc", is_flag=True, help="Windows OS のビルド番号による判定を行わない")
@click.option("--resolve-hashes", "resolve", is_flag=True, help="名前の分からない jar を SHA-1 で Maven Central に照会する")
@click.option("--no-xlsx", is_flag=True, help="Excel を出力しない（CSV のみ）")
def run(inventory_dir, env_master, config_path, advisory, out_dir, only_advisory, base_date, skip_trivy,
        trivy_results_dir, save_trivy_json, work_dir, cache_dir, offline, no_msrc, resolve, no_xlsx):
    """突き合わせを実行してレポートを出力します。"""
    try:
        config = load_config(config_path or _default_config())
        today = base_date or date.today()
        envs = load_inventories(inventory_dir, load_env_master(env_master))
        if not envs:
            raise click.ClickException(f"環境フォルダがありません: {inventory_dir}")
        advisories = load_advisories(advisory, config)
        _echo(f"環境 {len(envs)} 件、通達 {len(advisories)} 件を読み込みました")

        if resolve:
            count, error = resolve_hashes(envs, Path(cache_dir) / "maven_sha1.json")
            _echo(f"SHA-1 で特定できた jar: {count} 件" + (f"（{error}）" if error else ""))
        write_sboms(envs, Path(work_dir) / "sbom")

        findings = []
        if skip_trivy:
            _echo("Trivy を使わずに実行します（CVE 番号だけの通達は「判定不能」になります）")
        else:
            findings = scan_environments(envs, config, trivy_results_dir, save_trivy_json, log=_echo)

        msrc = None
        if not no_msrc and (config.get("msrc") or {}).get("enabled", True):
            msrc = MsrcClient(Path(cache_dir) / "msrc", config, offline=offline)
        result = Judge(envs, findings, config, today, msrc).run(advisories, only_advisory=only_advisory)
        if skip_trivy:
            result.messages.append("Trivy を使わずに実行しました")
        written, lines = write_reports(out_dir, advisories, envs, result, config, today, xlsx=not no_xlsx)
    except TrivyNotFoundError as exc:
        _echo(f"エラー: {exc}")
        sys.exit(2)
    except (AdvisoryFormatError, FileNotFoundError, ValueError) as exc:
        _echo(f"エラー: {exc}")
        sys.exit(2)

    click.echo("==== サマリ ====")
    for line in lines:
        click.echo(line)
    click.echo("==== 出力ファイル ====")
    for path in written:
        click.echo(str(path))


@main.command("build-sbom")
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


@main.command("check-inputs")
@with_options(common_inputs)
@click.option("--advisory", type=click.Path(exists=True, dir_okay=False), help="会社公表の脆弱性リスト")
def check_inputs(inventory_dir, env_master, config_path, advisory):
    """入力が正しく読めるかを確認します（判定は行いません）。"""
    try:
        config = load_config(config_path or _default_config())
        envs = load_inventories(inventory_dir, load_env_master(env_master))
        advisories = load_advisories(advisory, config) if advisory else []
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
    if advisories:
        click.echo("==== 通達の製品名が回収データのどれに当たるか ====")
        for item in advisories:
            if not item.product_name or item.is_kb:
                continue
            matcher = build_matcher(item.product_name, config.get("aliases") or {})
            hits = sorted({f"{c.name} {c.version}".strip() for env in envs for c in env.components if matcher(c)})
            shown = "、".join(hits[:5]) + (f" ほか {len(hits) - 5} 件" if len(hits) > 5 else "")
            click.echo(f"{item.advisory_id} [{item.product_name}] -> {shown or '該当なし（表記ゆれなら aliases に追加）'}")


if __name__ == "__main__":
    main()
