# 開発

```
pip install -e ".[dev]"
pytest
python examples/make_advisory_list.py               # サンプルの会社公表リストを作り直す
python tools/build_portable.py --out dist           # インストール不要の配布物を作る
python tools/audit_vulndb.py --db-dir vulndb --inventory-dir inventory   # 実データの監査
```

- `examples/vulndb/` は、本物の OSV.dev / Amazon Linux のデータからサンプルに関係する記録だけを抜き出したものです（`zk update --import` で作成）。
- CI（`.github/workflows/ci.yml`）は push のたびに、単体テスト、Windows Server・Amazon Linux 2023・Ubuntu 24.04 での回収から照合まで、対象マシンに残らないことの確認、配布物の試験を行います。
- リリースを公開すると、`.github/workflows/release.yml` が配布物の zip を作って添付します。
- 図は `docs/images/*.drawio.png` です。図のデータを埋め込んだ PNG なので、draw.io でそのまま開いて編集し、同じ形式（PNG、「図のコピーを含める」をオン）で保存します。
- 変更履歴は [CHANGELOG.md](https://github.com/hsgwa/cve_chk/blob/main/CHANGELOG.md)、不具合の記録は [DEFECTS.md](https://github.com/hsgwa/cve_chk/blob/main/docs/DEFECTS.md) にあります。
