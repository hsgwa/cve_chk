#!/usr/bin/env bash
# =============================================================================
# collect_linux.sh - Linux（EC2 / EMR ノード）のインベントリ回収
#
# 持ち込むもの（同じフォルダに置く）:
#   collect_linux.sh
#   syft_<版>_linux_amd64.tar.gz   （Graviton なら linux_arm64 版）
#   syft_<版>_checksums.txt        （同じリリースのチェックサム。あれば tar.gz の SHA-256 を確かめる）
#
# 実行:   sudo bash collect_linux.sh
# 出力:   ./out/<ホスト名>/cdx_syft.json   syft が作る CycloneDX SBOM
#         ./out/<ホスト名>/os_info.json    OS 情報・個別製品の版・収集の成否
#         ./out/<ホスト名>/collect.log     実行ログ
# 回収:   out/<ホスト名>/ フォルダごと管理 PC の <inventory-dir>/ 配下へコピー
#
# 対象マシンに残すもの: このスクリプトが書き込むのは、スクリプトを置いたフォルダの中だけ
#   （out/ と、実行中だけ使う .work/。syft の一時ファイルやキャッシュも .work/ の中に置き、終わると消す）。
#   回収が終わったら、このフォルダごと消せば元の状態に戻る（例: sudo rm -rf /opt/vuln-collect）。
#   OS が記録するもの（sudo のログ、シェルの履歴など）は残る。個別製品の cmd で書いたコマンドが書き込むものは対象外。
#
# 終了コード: 0 = 成功、1 = 出力先を作れない、3 = syft が失敗（os_info.json は出る）、4 = 空き容量が足りない
#
# 環境変数で変更できるもの:
#   SCAN_ROOT       走査する起点（既定 /）
#   EXTRA_EXCLUDES  追加で除外するパターン（空白区切り。例: "./data/** ./backup/**"）
#   OUT_DIR         出力先（既定 ./out/<ホスト名>）
#   WORK_DIR        syft の展開と一時ファイルの置き場所（既定 ./.work。中に実行ごとのフォルダを作り、
#                   終わるとそのフォルダだけを消す。noexec の場所は不可）
#   MIN_FREE_MB     出力先の空き容量がこれ（MB。既定 500）未満なら、何も書かずに止める
#   SYFT_MEMORY_LIMIT syft のメモリの目安（既定 1GiB。Go の GOMEMLIMIT。超えそうになるとメモリの回収を早める）
#   SYFT_TARBALL    syft の tar.gz の場所（既定 スクリプトと同じフォルダから自動選択）
#   SYFT_BIN        展開済みの syft を直接指定する場合（チェックサムは確かめない）
#   REQUIRE_SYFT_CHECKSUM 1 ならチェックサムを確かめられないとき syft を実行しない（既定 0。一致しないときは常に実行しない）
#   LOW_PRIORITY    1（既定）なら CPU とディスクの優先度を最低にして実行する（nice -n 19、ionice -c3）。0 で無効
#   SYFT_TIMEOUT_SEC syft の打ち切り時間（秒。既定 10800 = 3 時間）。打ち切ると syft の失敗として記録する
# =============================================================================
set -u

# ---- 個別製品の版取得 --------------------------------------------------------
# syft では検出できない製品（インストーラで任意の場所に置く商用ソフト）をここに書く。
# 書式: "製品名|種類|対象|版を抜き出す正規表現"
#   cmd    対象のコマンドを実行し、出力から正規表現で版を抜き出す
#   file   対象のファイル（ワイルドカード可）の中身から正規表現で版を抜き出す
#   exists 対象のパス（ワイルドカード可）があれば「存在する（版不明）」とする
#   proc   対象の名前（空白区切り）のプロセスが動いていれば「存在する（版不明）」とする
#   find   対象の名前（大文字小文字無視、ワイルドカード可）のファイル/フォルダを探し、
#          あれば「存在する（版不明）」とする
# 版不明で見つかった製品は、管理 PC 側で「影響あり（比較不能）」と判定される。
# ★ HULFT / DataMagic の「版が分かるコマンドやファイル」は環境ごとに異なるため、
#    実機で確認して cmd か file の行を追加すること（下はコメントの記入例）。
CUSTOM_PRODUCTS=(
  "HULFT|proc|hulsndd hulrcvd hulobsd|"
  "HULFT|exists|${HULEXEP:-/nonexistent}|"
  "HULFT|find|*hulft*|"
  "DataMagic|find|*datamagic*|"
  # "HULFT|cmd|/opt/hulft/bin/<版を表示するコマンド>|[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.]*"
  # "DataMagic|file|/opt/datamagic/<版が書かれたファイル>|[0-9]+\.[0-9]+\.[0-9]+"
)
# find で探す場所と深さ
FIND_ROOTS="${FIND_ROOTS:-/opt /usr/local /home /app /apps /data /var/opt /srv}"
FIND_MAXDEPTH=4
# -----------------------------------------------------------------------------

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HOST="$(hostname 2>/dev/null || echo unknown)"
OUT_DIR="${OUT_DIR:-$SCRIPT_DIR/out/$HOST}"
SCAN_ROOT="${SCAN_ROOT:-/}"
EXTRA_EXCLUDES="${EXTRA_EXCLUDES:-}"
WORK_DIR="${WORK_DIR:-$SCRIPT_DIR/.work}"
MIN_FREE_MB="${MIN_FREE_MB:-500}"
SYFT_MEMORY_LIMIT="${SYFT_MEMORY_LIMIT:-1GiB}"
SYFT_BIN="${SYFT_BIN:-}"
LOW_PRIORITY="${LOW_PRIORITY:-1}"
SYFT_TIMEOUT_SEC="${SYFT_TIMEOUT_SEC:-10800}"

# ---- 負荷を抑える（既定） ------------------------------------------------------
# 業務処理を優先させるため、CPU とディスクの優先度を最低にして自分自身を実行し直す
if [ "$LOW_PRIORITY" != "0" ] && [ -z "${VT_LOW_PRIORITY_APPLIED:-}" ]; then
  export VT_LOW_PRIORITY_APPLIED=1
  PRIO=()
  command -v nice >/dev/null 2>&1 && PRIO+=(nice -n 19)
  command -v ionice >/dev/null 2>&1 && ionice -c3 true 2>/dev/null && PRIO+=(ionice -c3)
  if [ ${#PRIO[@]} -gt 0 ]; then
    exec "${PRIO[@]}" bash "$0" "$@"
  fi
fi
START_EPOCH="$(date +%s)"

# ---- 空き容量（足りなければ何も書かずに止める） ------------------------------------
CHECK_DIR="$OUT_DIR"
while [ ! -d "$CHECK_DIR" ]; do CHECK_DIR="$(dirname "$CHECK_DIR")"; done
FREE_MB="$(df -Pk "$CHECK_DIR" 2>/dev/null | awk 'NR == 2 {print int($4 / 1024)}')"
if [ -n "$FREE_MB" ] && [ "$FREE_MB" -lt "$MIN_FREE_MB" ]; then
  echo "空き容量が足りないため止めます: $CHECK_DIR の空き ${FREE_MB} MB（${MIN_FREE_MB} MB 以上が必要。MIN_FREE_MB で変更）" >&2
  exit 4
fi

mkdir -p "$OUT_DIR" || { echo "出力先を作成できません: $OUT_DIR" >&2; exit 1; }
LOG="$OUT_DIR/collect.log"
: > "$LOG"
log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG" >&2; }

# ---- 実行中だけ使う作業フォルダ（終わったら消す。指定された WORK_DIR そのものは消さない） ----
mkdir -p "$WORK_DIR" && RUN_WORK="$(mktemp -d "$WORK_DIR/run.XXXXXX")" || {
  log "エラー: 作業フォルダを作成できません: $WORK_DIR"; exit 1; }
cleanup() {
  rm -rf "$RUN_WORK"
  rmdir "$WORK_DIR" 2>/dev/null || true      # 空のときだけ消える（他のものが入っていれば残す）
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
mkdir -p "$RUN_WORK/tmp" "$RUN_WORK/home" "$RUN_WORK/cache" "$RUN_WORK/config"
# syft が一時ファイル・キャッシュ・設定を作る場所を、すべて作業フォルダの中にする
SYFT_ENV=(env HOME="$RUN_WORK/home" TMPDIR="$RUN_WORK/tmp" XDG_CACHE_HOME="$RUN_WORK/cache"
          XDG_CONFIG_HOME="$RUN_WORK/config" XDG_DATA_HOME="$RUN_WORK/home"
          SYFT_CHECK_FOR_APP_UPDATE=false GOMEMLIMIT="$SYFT_MEMORY_LIMIT")

json_escape() {
  # JSON 文字列として安全な形にする（制御文字は空白に置き換える）
  printf '%s' "$1" | tr '\000-\037' ' ' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

run_limited() {
  # timeout コマンドがあれば 30 秒で打ち切る
  if command -v timeout >/dev/null 2>&1; then timeout 30 "$@"; else "$@"; fi
}

log "収集開始: host=$HOST scan_root=$SCAN_ROOT out=$OUT_DIR"
if [ -n "${VT_LOW_PRIORITY_APPLIED:-}" ] && [ "$LOW_PRIORITY" != "0" ]; then
  log "優先度: 低（nice $(nice 2>/dev/null || echo '?')、ionice $(ionice -p $$ 2>/dev/null || echo 'なし')）。LOW_PRIORITY=0 で通常の優先度"
fi
[ "$(id -u)" -ne 0 ] && log "注意: root ではありません。読めないフォルダは結果から漏れます（sudo での実行を推奨）"

# ---- OS 情報 -----------------------------------------------------------------
OS_ID=""; OS_VERSION_ID=""; OS_PRETTY=""
if [ -r /etc/os-release ]; then
  OS_ID="$(. /etc/os-release 2>/dev/null; echo "${ID:-}")"
  OS_VERSION_ID="$(. /etc/os-release 2>/dev/null; echo "${VERSION_ID:-}")"
  OS_PRETTY="$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-}")"
fi
KERNEL="$(uname -r 2>/dev/null || true)"
ARCH="$(uname -m 2>/dev/null || true)"

EMR_RELEASE=""
for f in /emr/instance-controller/extraInstanceData.json /mnt/var/lib/info/extraInstanceData.json \
         /mnt/var/lib/info/job-flow.json; do
  if [ -r "$f" ]; then
    EMR_RELEASE="$(grep -oE 'emr-[0-9]+\.[0-9]+\.[0-9]+' "$f" 2>/dev/null | head -n 1)"
    [ -n "$EMR_RELEASE" ] && break
  fi
done
[ -n "$EMR_RELEASE" ] && log "EMR リリース: $EMR_RELEASE"

# ---- 除外するマウント（ネットワーク・仮想ファイルシステム） -------------------
EXCLUDES=("./proc/**" "./sys/**" "./dev/**" "./run/**" "./tmp/**" "./var/lib/docker/**" "./var/lib/containerd/**")
SKIPPED_MOUNTS=()
if [ -r /proc/mounts ]; then
  while read -r _dev mnt fstype _rest; do
    case "$fstype" in
      nfs|nfs4|cifs|smb3|smbfs|fuse.s3fs|fuse.goofys|fuse.mount-s3|fuse.sshfs|lustre|efs|ceph|glusterfs|9p)
        case "$mnt" in
          "$SCAN_ROOT"|"${SCAN_ROOT%/}"/*)
            rel="${mnt#"${SCAN_ROOT%/}"}"
            EXCLUDES+=(".${rel}/**")
            SKIPPED_MOUNTS+=("$mnt ($fstype)")
            log "ネットワーク上の領域を除外: $mnt ($fstype)" ;;
        esac ;;
    esac
  done < /proc/mounts
fi
for own in "$SCRIPT_DIR" "$RUN_WORK"; do      # 自分のフォルダ（syft の展開先を含む）は走査しない
  case "$own" in
    "${SCAN_ROOT%/}"/*) EXCLUDES+=(".${own#"${SCAN_ROOT%/}"}/**") ;;
  esac
done
for pattern in $EXTRA_EXCLUDES; do EXCLUDES+=("$pattern"); done

# ---- syft --------------------------------------------------------------------
SYFT_STATUS="failed"; SYFT_REASON=""; SYFT_VERSION=""; SYFT_EXIT=""; SYFT_CHECKSUM="unverified"
SBOM="$OUT_DIR/cdx_syft.json"
rm -f "$SBOM"

if [ -z "$SYFT_BIN" ]; then
  case "$ARCH" in
    x86_64|amd64) SYFT_ARCH="amd64" ;;
    aarch64|arm64) SYFT_ARCH="arm64" ;;
    *) SYFT_ARCH="$ARCH" ;;
  esac
  # 版の順で最も新しいもの（文字の順だと 1.9 が 1.18 より後になる）
  TARBALL="${SYFT_TARBALL:-$(ls "$SCRIPT_DIR"/syft_*_linux_"$SYFT_ARCH".tar.gz 2>/dev/null | sort -V 2>/dev/null | tail -n 1)}"
  if [ -n "$TARBALL" ] && [ -r "$TARBALL" ]; then
    # ---- syft の tar.gz の真正性（配布元のチェックサムと比べる） ----
    TAR_NAME="$(basename "$TARBALL")"
    TAR_VERSION="${TAR_NAME#syft_}"; TAR_VERSION="${TAR_VERSION%%_linux_*}"
    SUMS="${SYFT_CHECKSUMS:-$(dirname "$TARBALL")/syft_${TAR_VERSION}_checksums.txt}"
    if [ -r "$SUMS" ] && command -v sha256sum >/dev/null 2>&1; then
      EXPECTED="$(awk -v f="$TAR_NAME" '$2 == f || $2 == "*" f {print $1; exit}' "$SUMS")"
      ACTUAL="$(sha256sum "$TARBALL" | awk '{print $1}')"
      if [ -n "$EXPECTED" ] && [ "$EXPECTED" = "$ACTUAL" ]; then
        SYFT_CHECKSUM="ok"
        log "syft の tar.gz のチェックサムが一致しました（SHA-256、$(basename "$SUMS")）"
      else
        SYFT_CHECKSUM="mismatch"
      fi
    else
      log "注意: syft の tar.gz のチェックサムを確かめていません（$SUMS がありません）。配布元の syft_${TAR_VERSION}_checksums.txt を同じフォルダに置くと確かめます"
    fi
  fi
  if [ -z "$TARBALL" ] || [ ! -r "$TARBALL" ]; then
    SYFT_REASON="syft の tar.gz が見つかりません（syft_*_linux_${SYFT_ARCH}.tar.gz をスクリプトと同じフォルダに置く）"
  elif [ "$SYFT_CHECKSUM" = "mismatch" ]; then
    SYFT_REASON="syft の tar.gz のチェックサムが配布元と一致しません（改ざん・破損の恐れがあるため実行しません）: $TARBALL"
  elif [ "$SYFT_CHECKSUM" != "ok" ] && [ "${REQUIRE_SYFT_CHECKSUM:-0}" = "1" ]; then
    SYFT_REASON="syft の tar.gz のチェックサムを確かめられないため実行しません（REQUIRE_SYFT_CHECKSUM=1）"
  else
    if tar -xzf "$TARBALL" -C "$RUN_WORK" syft 2>>"$LOG"; then
      chmod +x "$RUN_WORK/syft" 2>/dev/null
      SYFT_BIN="$RUN_WORK/syft"
    else
      SYFT_REASON="syft の tar.gz を展開できません: $TARBALL"
    fi
  fi
fi

if [ -n "$SYFT_BIN" ]; then
  SYFT_VERSION="$("${SYFT_ENV[@]}" "$SYFT_BIN" version 2>>"$LOG" | awk '/^Version:/ {print $2}')"
  if [ -z "$SYFT_VERSION" ]; then
    SYFT_REASON="syft を実行できません（展開先が noexec の可能性。WORK_DIR を変更する）"
  else
    log "syft $SYFT_VERSION で $SCAN_ROOT を走査します（時間がかかります）"
    ARGS=()
    for pattern in "${EXCLUDES[@]}"; do ARGS+=(--exclude "$pattern"); done
    LIMIT=()
    command -v timeout >/dev/null 2>&1 && [ "$SYFT_TIMEOUT_SEC" != "0" ] && LIMIT=(timeout "$SYFT_TIMEOUT_SEC")
    ${LIMIT[@]+"${LIMIT[@]}"} "${SYFT_ENV[@]}" "$SYFT_BIN" scan "dir:$SCAN_ROOT" "${ARGS[@]}" -o "cyclonedx-json=$SBOM" -q 2>>"$LOG"
    SYFT_EXIT=$?
    if [ "$SYFT_EXIT" -ne 0 ] && [ "$SYFT_EXIT" -ne 124 ]; then
      # 古い syft には scan サブコマンドが無い
      ${LIMIT[@]+"${LIMIT[@]}"} "${SYFT_ENV[@]}" "$SYFT_BIN" "dir:$SCAN_ROOT" "${ARGS[@]}" -o "cyclonedx-json=$SBOM" -q 2>>"$LOG"
      SYFT_EXIT=$?
    fi
    if [ "$SYFT_EXIT" -eq 0 ] && [ -s "$SBOM" ]; then
      SYFT_STATUS="ok"
      log "SBOM を作成しました: $SBOM"
    elif [ "$SYFT_EXIT" -eq 124 ]; then
      SYFT_REASON="syft が ${SYFT_TIMEOUT_SEC} 秒で終わらず打ち切りました（SYFT_TIMEOUT_SEC で延長、SCAN_ROOT や EXTRA_EXCLUDES で範囲を調整）"
      rm -f "$SBOM"
    else
      SYFT_REASON="syft が終了コード $SYFT_EXIT で失敗しました（collect.log を参照）"
      rm -f "$SBOM"
    fi
  fi
fi
[ "$SYFT_STATUS" != "ok" ] && log "エラー: $SYFT_REASON"

# ---- 個別製品 ----------------------------------------------------------------
CUSTOM_JSON=""
add_custom() {  # name status version source reason
  local entry
  entry="{\"name\":\"$(json_escape "$1")\",\"status\":\"$2\",\"version\":\"$(json_escape "$3")\",\"source\":\"$(json_escape "$4")\",\"reason\":\"$(json_escape "$5")\"}"
  CUSTOM_JSON="${CUSTOM_JSON:+$CUSTOM_JSON,}$entry"
  log "個別製品: $1 -> $2 ${3:+version=$3 }${4:+($4)}"
}

extract() {  # text regex
  if [ -z "$2" ]; then echo ""; else printf '%s' "$1" | grep -oE -- "$2" 2>/dev/null | head -n 1; fi
}

for spec in "${CUSTOM_PRODUCTS[@]}"; do
  IFS='|' read -r p_name p_type p_target p_regex <<< "$spec"
  case "$p_type" in
    cmd)
      p_bin="${p_target%% *}"
      if ! command -v "$p_bin" >/dev/null 2>&1 && [ ! -x "$p_bin" ]; then
        add_custom "$p_name" not_found "" "$p_target" ""
      else
        p_out="$(run_limited sh -c "$p_target" 2>&1)"; p_rc=$?
        p_ver="$(extract "$p_out" "$p_regex")"
        if [ -n "$p_ver" ] || [ "$p_rc" -eq 0 ]; then
          add_custom "$p_name" found "$p_ver" "$p_target" ""
        else
          add_custom "$p_name" error "" "$p_target" "コマンドが終了コード $p_rc で失敗"
        fi
      fi ;;
    file)
      p_found=0
      for p_file in $p_target; do
        [ -e "$p_file" ] || continue
        p_found=1
        if [ -r "$p_file" ]; then
          add_custom "$p_name" found "$(extract "$(head -c 65536 "$p_file" 2>/dev/null | tr -d '\000')" "$p_regex")" "$p_file" ""
        else
          add_custom "$p_name" error "" "$p_file" "ファイルを読めません（権限不足）"
        fi
      done
      [ "$p_found" -eq 0 ] && add_custom "$p_name" not_found "" "$p_target" "" ;;
    exists)
      p_found=0
      for p_file in $p_target; do
        [ -e "$p_file" ] || continue
        p_found=1; add_custom "$p_name" found "" "$p_file" ""
      done
      [ "$p_found" -eq 0 ] && add_custom "$p_name" not_found "" "$p_target" "" ;;
    proc)
      p_found=0
      for p_proc in $p_target; do
        p_pid="$(ps -eo pid=,comm= 2>/dev/null | awk -v n="$p_proc" '$2 == n {print $1; exit}')"
        [ -n "$p_pid" ] || continue
        p_found=1
        p_exe="$(readlink "/proc/$p_pid/exe" 2>/dev/null || echo "$p_proc")"
        add_custom "$p_name" found "" "実行中: $p_exe" ""
      done
      [ "$p_found" -eq 0 ] && add_custom "$p_name" not_found "" "プロセス: $p_target" "" ;;
    find)
      p_hit=""
      for p_root in $FIND_ROOTS; do
        [ -d "$p_root" ] || continue
        p_hit="$(find "$p_root" -maxdepth "$FIND_MAXDEPTH" -iname "$p_target" -print 2>/dev/null | head -n 1)"
        [ -n "$p_hit" ] && break
      done
      if [ -n "$p_hit" ]; then add_custom "$p_name" found "" "$p_hit" ""
      else add_custom "$p_name" not_found "" "名前検索: $p_target" ""; fi ;;
    *)
      add_custom "$p_name" error "" "$p_target" "種類 $p_type は使えません" ;;
  esac
done

# ---- 読めなかったフォルダ（root 以外で実行した場合） ---------------------------
UNREADABLE_JSON=""
if [ "$(id -u)" -ne 0 ]; then
  while IFS= read -r dir; do
    [ -n "$dir" ] || continue
    UNREADABLE_JSON="${UNREADABLE_JSON:+$UNREADABLE_JSON,}{\"path\":\"$(json_escape "$dir")\"}"
  done < <(find "$SCAN_ROOT" -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run \) -prune -o \
             -type d ! -readable -print 2>/dev/null | head -n 200)
fi
for mnt in ${SKIPPED_MOUNTS[@]+"${SKIPPED_MOUNTS[@]}"}; do
  UNREADABLE_JSON="${UNREADABLE_JSON:+$UNREADABLE_JSON,}{\"path\":\"$(json_escape "除外したマウント: $mnt")\"}"
done

# ---- os_info.json ------------------------------------------------------------
cat > "$OUT_DIR/os_info.json" <<JSON
{
  "schema": "vuln-triage-osinfo/1",
  "collector_version": "1",
  "host": "$(json_escape "$HOST")",
  "collected_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')",
  "duration_sec": $(( $(date +%s) - START_EPOCH )),
  "low_priority": $([ -n "${VT_LOW_PRIORITY_APPLIED:-}" ] && [ "$LOW_PRIORITY" != "0" ] && echo true || echo false),
  "run_as_root": $([ "$(id -u)" -eq 0 ] && echo true || echo false),
  "scan_root": "$(json_escape "$SCAN_ROOT")",
  "os": {
    "family": "linux",
    "id": "$(json_escape "$OS_ID")",
    "version_id": "$(json_escape "$OS_VERSION_ID")",
    "pretty_name": "$(json_escape "$OS_PRETTY")",
    "kernel": "$(json_escape "$KERNEL")",
    "arch": "$(json_escape "$ARCH")"
  },
  "emr_release": "$(json_escape "$EMR_RELEASE")",
  "syft": {
    "status": "$SYFT_STATUS",
    "version": "$(json_escape "$SYFT_VERSION")",
    "exit_code": "$(json_escape "$SYFT_EXIT")",
    "checksum": "$SYFT_CHECKSUM",
    "reason": "$(json_escape "$SYFT_REASON")"
  },
  "sections": {
    "custom_products": {"status": "ok", "items": [$CUSTOM_JSON]},
    "unreadable": {"status": "ok", "items": [$UNREADABLE_JSON]}
  },
  "completed": true
}
JSON

log "収集終了（$(( $(date +%s) - START_EPOCH )) 秒）。$OUT_DIR をフォルダごと回収してください"
[ "$SYFT_STATUS" = "ok" ] || exit 3
exit 0
