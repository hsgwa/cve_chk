#!/usr/bin/env bash
# 対象マシンに何も残さないことの試験（Linux。CI のコンテナの中で root で実行する）。
#
#   1. ファイルシステム全体の一覧（パス・種類・大きさ・更新日時・権限・所有者）を取る
#   2. 回収用のフォルダ（/opt/vuln-collect）を作り、回収スクリプトと syft を置いて実行する
#   3. 回収物を取り出し、回収用のフォルダを消す
#   4. もう一度一覧を取り、1 と完全に同じであることを確かめる（違えば終了コード 1）
#
# 使い方: footprint_linux.sh <collectors のフォルダ> <回収物のコピー先>
set -u
SRC="$1"
DEST="$2"
TOOL=/opt/vuln-collect
SNAP=/var/tmp/footprint-snapshots    # 一覧の置き場所（一覧そのものは比べない）

snapshot() {
  # ディレクトリの更新日時は、中のものを作って消すだけで変わるので比べない（中身の一覧で比べる）
  find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path "$SNAP" -o -path /w \) -prune -o \
    \( -type d -printf '%p\td\t%m\t%u\n' \) -o -printf '%p\t%y\t%s\t%T@\t%m\t%u\n' 2>/dev/null | LC_ALL=C sort
}

mkdir -p "$SNAP"
snapshot > "$SNAP/before"

mkdir -p "$TOOL"
cp "$SRC"/collect_linux.sh "$SRC"/syft_*_linux_*.tar.gz "$SRC"/syft_*_checksums.txt "$TOOL"/
EXTRA_EXCLUDES="./w/** .$SNAP/**" bash "$TOOL/collect_linux.sh"
code=$?
mkdir -p "$DEST"
cp -r "$TOOL"/out/*/. "$DEST"/
rm -rf "$TOOL"

snapshot > "$SNAP/after"
if diff "$SNAP/before" "$SNAP/after" > "$SNAP/diff"; then
  echo "footprint OK: 回収用のフォルダを消したら、ファイルシステムは実行前と同じ（$(wc -l < "$SNAP/before") 件を比較）"
else
  echo "footprint NG: 回収用のフォルダの外に変化があります"
  head -n 50 "$SNAP/diff"
  exit 1
fi
rm -rf "$SNAP"
exit "$code"
