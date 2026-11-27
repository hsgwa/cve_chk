<#
=============================================================================
check_all.ps1 - 作業フォルダのサーバーを 1 台ずつ調べる（脆弱性データの更新 → 1 台ずつ照合 → レポート）

  作業フォルダ（-BaseDir）の決まった場所にあるデータで、次を順に行う。
    1. 脆弱性データの更新（zk update。-SkipDbUpdate で省略）
    2. inventory\ の下のサーバーごとに zk check を実行する。
       cve_list\ に CVE の一覧があれば、最も新しいファイルを使う（無くてもよい）
    3. レポートを reports\<日付>\<サーバー名>\ に出す。前回のレポートがあれば「前回との差分」も出す

  作業フォルダの構成（zk init で作れる）:
    <BaseDir>\inventory\<サーバー名>\   回収物（人が置く）
    <BaseDir>\cve_list\                 CVE の一覧（任意。.xlsx / .xlsm / .csv / .txt。最も新しいものを使う）
    <BaseDir>\reports\<日付>\           レポート（自動。reports\latest.txt に最新のフォルダ名）
    <BaseDir>\logs\                     実行ログ（自動。run_YYYYMMDD.log）

  終了コード: 0 = 成功、1 = データの更新の一部に失敗したが照合はできた、2 = 照合できなかったサーバーがある

実行（管理 PC で、ツールのフォルダから）:
  powershell -ExecutionPolicy Bypass -File scripts\check_all.ps1 -BaseDir D:\vuln
=============================================================================
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$BaseDir,
    # 脆弱性データの置き場所（省略時は config.yaml の vulndb.dir）
    [string]$DbDir,
    # 設定ファイル（省略時はツールのフォルダの config.yaml）
    [string]$Config,
    # python.exe の場所（省略時は、ツールのフォルダに python\ があればそれ、無ければ PATH の python）
    [string]$Python,
    # ツールのフォルダ（省略時はこのスクリプトの1つ上）
    [string]$WorkDir,
    # 脆弱性データの更新をしない（同じ日に更新済みの場合など）
    [switch]$SkipDbUpdate,
    # ログを残す日数
    [int]$KeepLogDays = 90
)

$ErrorActionPreference = 'Continue'
if (-not $WorkDir) { $WorkDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
Set-Location -LiteralPath $WorkDir
# インストール不要の配布物（ポータブル版）なら、同梱の Python と zk.pyz を使う。無ければ pip で入れたものを使う
if (-not $Python) {
    $bundled = Join-Path $WorkDir 'python\python.exe'
    $Python = if (Test-Path -LiteralPath $bundled) { $bundled } else { 'python' }
}
$zkPyz = Join-Path $WorkDir 'zk.pyz'
# @(...) で必ず配列にする（要素が 1 つだと文字列になり、@toolArgs で 1 文字ずつに分かれてしまう）
[string[]]$toolArgs = @(if (Test-Path -LiteralPath $zkPyz) { $zkPyz } else { '-m'; 'zeijaku_kakunin' })
if (-not (Test-Path -LiteralPath $BaseDir -PathType Container)) {
    Write-Host ('作業フォルダがありません: {0}。先に、ツールのフォルダで zk init {0} を実行してください' -f $BaseDir)
    exit 2
}
$BaseDir = (Resolve-Path -LiteralPath $BaseDir).Path
$inventoryDir = Join-Path $BaseDir 'inventory'
$cveListDir = Join-Path $BaseDir 'cve_list'
$reportsDir = Join-Path $BaseDir 'reports'
$logDir = Join-Path $BaseDir 'logs'
foreach ($dir in @($reportsDir, $logDir)) { [void][System.IO.Directory]::CreateDirectory($dir) }
$logFile = Join-Path $logDir ('run_{0}.log' -f (Get-Date -Format 'yyyyMMdd'))

function Write-Log([string]$Message) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Write-Host $line
}

# Python の出力を UTF-8 にそろえる（ログの文字化け防止）
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

function Invoke-Tool([string[]]$Arguments) {
    Write-Log ('実行: {0} {1} {2}' -f $Python, ($toolArgs -join ' '), ($Arguments -join ' '))
    try {
        & $Python @toolArgs @Arguments 2>&1 | ForEach-Object {
            # 標準エラーの行は ErrorRecord になるので、元の文字列を取り出す
            if ($_ -is [System.Management.Automation.ErrorRecord]) {
                $text = if ($null -ne $_.TargetObject) { "$($_.TargetObject)" } else { $_.Exception.Message }
            } else {
                $text = "$_"
            }
            Add-Content -Path $logFile -Value $text -Encoding UTF8
            Write-Host $text
        }
        return $LASTEXITCODE
    } catch {
        Write-Log ('実行できません: {0}' -f $_.Exception.Message)
        return 2
    }
}

Write-Log ('開始: 作業フォルダ {0}' -f $BaseDir)
$common = @()
if ($DbDir) { $common += @('--db-dir', $DbDir) }
if ($Config) { $common += @('--config', $Config) }

$servers = @(Get-ChildItem -LiteralPath $inventoryDir -Directory -ErrorAction SilentlyContinue | Sort-Object Name)
if ($servers.Count -eq 0) {
    Write-Log ('終了: 失敗。回収物がありません: {0} の下に、対象マシンから持ち出したホストごとのフォルダを置いてください' -f $inventoryDir)
    exit 2
}

# 1. 脆弱性データの更新（全サーバーで出てくるソフトの種類をまとめて 1 回）
$updateCode = 0
if (-not $SkipDbUpdate) {
    $updateCode = Invoke-Tool (@('update', '--inventory-dir', $inventoryDir) + $common)
    if ($updateCode -ne 0) { Write-Log ('注意: 脆弱性データの更新に失敗したものがあります（終了コード {0}）。前回のデータで照合します' -f $updateCode) }
}

# 2. CVE の一覧（任意。最も新しいファイル。Excel が開いている間に作る一時ファイル ~$*.xlsx は除く）
$cveList = Get-ChildItem -LiteralPath $cveListDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in '.xlsx', '.xlsm', '.csv', '.txt' -and -not $_.Name.StartsWith('~$') } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($cveList) { Write-Log ('CVE の一覧: {0}（更新 {1:yyyy-MM-dd HH:mm}）' -f $cveList.Name, $cveList.LastWriteTime) }
else { Write-Log 'CVE の一覧: なし（見つかった脆弱性をすべて出します）' }

# 3. 出力先と、前回のレポート
$previousRun = Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
    Sort-Object Name -Descending | Select-Object -First 1
$name = Get-Date -Format 'yyyy-MM-dd'
if (Test-Path -LiteralPath (Join-Path $reportsDir $name)) { $name = Get-Date -Format 'yyyy-MM-dd_HHmmss' }
$runDir = Join-Path $reportsDir $name

# 4. 1 台ずつ調べる
$failed = New-Object System.Collections.Generic.List[string]
foreach ($server in $servers) {
    $arguments = @('check', $server.FullName, '--out-dir', (Join-Path $runDir $server.Name),
        '--cache-dir', (Join-Path $BaseDir 'cache')) + $common
    if ($cveList) { $arguments += @('--cve-list', $cveList.FullName) }
    if ($previousRun) {
        $previous = Join-Path $previousRun.FullName $server.Name
        if (Test-Path -LiteralPath (Join-Path $previous 'report_vulns.csv')) { $arguments += @('--previous', $previous) }
    }
    $code = Invoke-Tool $arguments
    if ($code -ne 0) { $failed.Add($server.Name); Write-Log ('失敗: {0}（終了コード {1}）' -f $server.Name, $code) }
}

if (Test-Path -LiteralPath $runDir) {
    # フォルダ名は英数字だけなので ASCII で書く（PowerShell 5.1 の UTF8 は BOM が付き、他のスクリプトで読みにくい）
    Set-Content -LiteralPath (Join-Path $reportsDir 'latest.txt') -Value $name -Encoding ASCII
}
if ($failed.Count -gt 0) {
    $exitCode = 2
    Write-Log ('終了: 失敗。調べられなかったサーバー: {0}。ログを確認してください' -f ($failed -join '、'))
} else {
    $exitCode = if ($updateCode -ne 0) { 1 } else { 0 }
    Write-Log ('終了: 成功。{0} 台。レポート: {1}' -f $servers.Count, $runDir)
}

# 古いログを消す（レポートは証跡なので消さない）
Get-ChildItem -LiteralPath $logDir -Filter 'run_*.log' -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepLogDays) } |
    Remove-Item -Force -ErrorAction SilentlyContinue

exit $exitCode
