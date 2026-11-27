# zip・jar・war などのファイルを調べる（Lambda など）

成果物のファイルを、サーバーで回収せずに管理 PC で調べます。対象は Lambda のデプロイ用 zip とレイヤー、war、ear、fat jar（Spring Boot など）、wheel、展開済みのフォルダです。syft も Linux も要りません。

```
zk scan-file function.zip layer-1.zip --inventory-dir D:\vuln\inventory --env lambda-my-function
zk scan-file app.war batch.jar --inventory-dir D:\vuln\inventory
zk scan-file D:\extracted\my-function --inventory-dir D:\vuln\inventory --env lambda-my-function
```

- 結果は `inventory\<環境名>\archive_inventory.json` に置かれます。`zk check D:\vuln\inventory\<環境名>` で照合します（`check_all.ps1` でも、ほかのサーバーと同じように照合されます）。
- `--env` を付けると、指定したものを 1 つの環境にまとめます（関数とレイヤーなど）。付けなければ、ファイルごとにその名前の環境を作ります。
- OS は無い扱いです（Windows OS の CVE は「影響なし」）。Lambda のランタイムと OS は AWS の管理なので対象外です。
- 読めなかったもの（壊れた zip、512 MB を超える入れ子）は「収集状況」シートに出ます。
- Go などの実行ファイル（Lambda の `bootstrap` など）の中のライブラリは調べません。

| 種類 | 見るもの |
|---|---|
| Java | `META-INF/maven/.../pom.properties`。中の jar もたどる（4 段まで）。無ければ MANIFEST かファイル名から推定し、SHA-1 を記録する（`zk check --resolve-hashes` で Maven Central に照会） |
| Python | `*.dist-info/METADATA`、`*.egg-info/PKG-INFO` |
| npm | `node_modules/<名前>/package.json` |
| .NET | `*.deps.json` |

## Lambda のファイルの取り出し方

| 種類 | 取り出し方 |
|---|---|
| zip の関数 | コンソールの「ダウンロード」→「関数コード .zip」。または `aws lambda get-function --function-name <関数名> --query Code.Location --output text` の URL から取得 |
| レイヤー | `aws lambda get-layer-version --layer-name <レイヤー名> --version-number <版> --query Content.Location --output text` の URL から取得 |
| コンテナイメージの関数 | `zk scan-file` では調べられない。`docker save` で tar にし、Linux で `syft scan docker-archive:<tar> -o cyclonedx-json=cdx_syft.json` を実行して環境フォルダに置く |

Amazon Inspector の SBOM エクスポート（CycloneDX）を環境フォルダに置いても読み込みます。
