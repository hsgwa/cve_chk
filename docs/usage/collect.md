# 回収（対象マシン）

## 共通

回収スクリプトが書き込むのは、**スクリプトを置いたフォルダの中だけ**です。回収物を持ち出したらフォルダを消せば、元の状態に戻ります。

| | 手順 |
|---|---|
| Linux | 1. `/opt/vuln-collect` に `collect_linux.sh`、syft の tar.gz、チェックサムを置く<br>2. `sudo bash /opt/vuln-collect/collect_linux.sh`<br>3. `/opt/vuln-collect/out/<ホスト名>/` を持ち出す<br>4. `sudo rm -rf /opt/vuln-collect` |
| Windows | 1. `C:\vuln-collect` に `collect_win.ps1` を置く<br>2. 管理者の PowerShell で `powershell -ExecutionPolicy Bypass -File C:\vuln-collect\collect_win.ps1`<br>3. `C:\vuln-collect\out\<ホスト名>\` を持ち出す<br>4. `C:\vuln-collect` を削除する |

- 何もインストールせず、設定・レジストリ・サービス・タスクを変えません。ファイルは読むだけで、ロックしません。
- 既定で優先度を下げて実行します（Linux: `nice -n 19`・`ionice -c3`、Windows: 通常以下）。
- 出力先の空きが 500 MB 未満なら、何も書かずに止めます（終了コード 4）。
- CI で毎回、実行前とフォルダ削除後を比べて差が無いことを確かめています（`tests/e2e/footprint_*`）。
- 残るもの: OS の記録（sudo のログ、シェルの履歴、イベントログ）。個別製品の `cmd` で足したコマンドが書くもの（例: `java -version` の `/tmp/hsperfdata_<ユーザー名>`）。
- サーバーへの負荷は [OPERATIONS.md](https://github.com/hsgwa/cve_chk/blob/main/docs/OPERATIONS.md) の 2 章にあります。

## Linux（EC2、EMR の各ノード）

持ち込むもの: `collectors/collect_linux.sh`、[syft](https://github.com/anchore/syft/releases) の `syft_<版>_linux_amd64.tar.gz`（Graviton は `linux_arm64`）、`syft_<版>_checksums.txt`。

- 出力: `out/<ホスト名>/` に `cdx_syft.json`（SBOM）、`os_info.json`、`collect.log`。
- root で実行します。root でないと読めないフォルダの中身が漏れます。
- チェックサムが合わなければ syft を実行しません。チェックサムが無いときも止めるには `REQUIRE_SYFT_CHECKSUM=1` を付けます。
- NFS などのネットワーク上の領域と、コンテナの保存領域は走査しません。
- EMR はクラスタの動作中に、マスター 1 台とコア 1 台で実行します。
- 終了コード: 0 = 成功、1 = 出力先を作れない、3 = syft の失敗（`os_info.json` は出る）、4 = 空き容量不足。

| 環境変数 | 既定 | 内容 |
|---|---|---|
| `SYFT_TIMEOUT_SEC` | 10800 | syft を打ち切るまでの秒数 |
| `SYFT_MEMORY_LIMIT` | 1GiB | syft のメモリの目安（`GOMEMLIMIT`。上限ではない） |
| `LOW_PRIORITY` | 1 | 0 で通常の優先度 |
| `MIN_FREE_MB` | 500 | 必要な空き容量 |
| `EXTRA_EXCLUDES` | | 走査から外すフォルダ |

その他はスクリプト冒頭のコメントにあります。

### syft だけで回収する場合

syft が作った CycloneDX のファイルだけでも照合できます。OS は SBOM から判別します。

```
tar -xzf syft_<版>_linux_amd64.tar.gz syft
sudo SYFT_CHECK_FOR_APP_UPDATE=false ./syft scan dir:/ \
  --exclude './proc/**' --exclude './sys/**' --exclude './dev/**' \
  --exclude './run/**' --exclude './tmp/**' \
  --exclude './var/lib/docker/**' --exclude './var/lib/containerd/**' \
  -o cyclonedx-json=cdx_syft.json
```

- この方法では、syft が `/tmp` やホームフォルダに一時ファイルを残すことがあります。
- ネットワーク上の領域は自動で除外されません。`findmnt -t nfs,nfs4,cifs,fuse.s3fs,lustre -o TARGET` で確かめて `--exclude` に足します。
- 取れないもの: 個別製品の版（HULFT など）、EMR のリリースラベル、syft の失敗の記録。

## Windows

持ち込むもの: `collectors/collect_win.ps1` だけです。管理者の PowerShell で実行します。

```
powershell -ExecutionPolicy Bypass -File C:\vuln-collect\collect_win.ps1
powershell -ExecutionPolicy Bypass -File C:\vuln-collect\collect_win.ps1 -ScanRoots 'D:\apps','E:\hulft'
powershell -ExecutionPolicy Bypass -File C:\vuln-collect\collect_win.ps1 -AllDrives
```

- 出力: `out\<ホスト名>\` に `inventory.json`、`collect.log`。
- 既定の走査対象は `Program Files`、`Program Files (x86)`、`ProgramData` です。**アプリが他の場所にあれば `-ScanRoots` か `-AllDrives` を付けます。**
- 取得するもの: OS のビルド番号、適用済み KB、インストール済みソフト、exe / dll の版、jar / war / ear の中身、Python・npm・NuGet のパッケージ、実行中のプロセスの場所。
- その他の引数: `-NormalPriority`（通常の優先度）、`-MinFreeMB`、`-SkipDll`（dll を読まない）。
- 終了コード: 0 = 成功、4 = 空き容量不足。

## HULFT / DataMagic などの商用ソフト

パッケージ管理の外の製品は、両スクリプト冒頭の「個別製品の版取得」の表で扱います。初期状態では名前で探して「存在する（版不明）」と記録するだけなので、判定は「影響あり（比較不能）」になります。版を取るには、版が分かるコマンドかファイルを確かめて表に 1 行足します（記入例はコメントにあります）。Windows でインストーラを使った製品は、レジストリから版が取れます。

## 回収後

持ち出した `out/<ホスト名>/` を、作業フォルダの `inventory\` の下にフォルダごと置きます（[files.md](https://github.com/hsgwa/cve_chk/blob/main/docs/usage/files.md)）。
