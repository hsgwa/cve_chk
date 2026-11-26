<#
=============================================================================
run_check.ps1 - 調査をまとめて実行する（脆弱性データの更新 → 照合 → レポート）。調査のたびに実行する

  作業フォルダ（-BaseDir）の決まった場所にあるデータで、次を順に行う。
    1. 脆弱性データの更新（db-update。-SkipDbUpdate で省略）
    2. 照合（run）。会社公表リストは advisory\ のうち最も新しいファイルを使う
    3. レポートを reports\<日付>\ に出す。前回のレポートがあれば「前回との差分」も出す

  作業フォルダの構成:
    <BaseDir>\inventory\<環境名>\   回収物を置く（人が置く）
    <BaseDir>\advisory\             会社公表リスト（.xlsx / .xlsm / .csv。人が置く。最も新しいものを使う）
    <BaseDir>\env_master.csv        環境マスタ（人が用意する）
    <BaseDir>\reports\<日付>\       レポート（自動。reports\latest.txt に最新のフォルダ名）
    <BaseDir>\logs\                 実行ログ（自動。run_YYYYMMDD.log）

  終了コード: 0 = 成功、1 = データの更新の一部に失敗したが照合はできた、2 = 照合できなかった

実行（管理 PC で、ツールのフォルダから）:
  powershell -ExecutionPolicy Bypass -File scripts\run_check.ps1 -BaseDir D:\vuln
=============================================================================
#>
param(
    [Parameter(Mandatory = $true)]
    [string]$BaseDir,
    # 脆弱性データの置き場所（省略時は config.yaml の vulndb.dir）
    [string]$DbDir,
    # 設定ファイル（省略時はツールのフォルダの config.yaml）
    [string]$Config,
    # python.exe の場所（省略時は PATH の python）
    [string]$Python = 'python',
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
$BaseDir = (Resolve-Path -LiteralPath $BaseDir).Path
$inventoryDir = Join-Path $BaseDir 'inventory'
$advisoryDir = Join-Path $BaseDir 'advisory'
$envMaster = Join-Path $BaseDir 'env_master.csv'
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
    Write-Log ('実行: {0} -m vuln_triage {1}' -f $Python, ($Arguments -join ' '))
    try {
        & $Python -m vuln_triage @Arguments 2>&1 | ForEach-Object {
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

if (-not (Test-Path -LiteralPath $inventoryDir)) {
    Write-Log ('終了: 失敗。回収物のフォルダがありません: {0}' -f $inventoryDir)
    exit 2
}

# 1. 脆弱性データの更新
$updateCode = 0
if (-not $SkipDbUpdate) {
    $updateCode = Invoke-Tool (@('db-update', '--inventory-dir', $inventoryDir) + $common)
    if ($updateCode -ne 0) { Write-Log ('注意: 脆弱性データの更新に失敗したものがあります（終了コード {0}）。前回のデータで照合します' -f $updateCode) }
}

# 2. 会社公表リスト（最も新しいファイル。Excel が開いている間に作る一時ファイル ~$*.xlsx は除く）
$advisory = Get-ChildItem -LiteralPath $advisoryDir -File -ErrorAction SilentlyContinue |
    Where-Object { $_.Extension -in '.xlsx', '.xlsm', '.csv' -and -not $_.Name.StartsWith('~$') } |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $advisory) {
    Write-Log ('終了: 失敗。会社公表リストがありません: {0}（.xlsx / .xlsm / .csv を置く）' -f $advisoryDir)
    exit 2
}
Write-Log ('会社公表リスト: {0}（更新 {1:yyyy-MM-dd HH:mm}）' -f $advisory.Name, $advisory.LastWriteTime)

# 3. 出力先と、前回のレポート
$previous = Get-ChildItem -LiteralPath $reportsDir -Directory -ErrorAction SilentlyContinue |
    Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'report_detail.csv') } |
    Sort-Object Name -Descending | Select-Object -First 1
$name = Get-Date -Format 'yyyy-MM-dd'
if (Test-Path -LiteralPath (Join-Path $reportsDir $name)) { $name = Get-Date -Format 'yyyy-MM-dd_HHmmss' }
$outDir = Join-Path $reportsDir $name

$arguments = @('run', '--inventory-dir', $inventoryDir, '--advisory', $advisory.FullName, '--out-dir', $outDir,
    '--cache-dir', (Join-Path $BaseDir 'cache')) + $common
if (Test-Path -LiteralPath $envMaster) { $arguments += @('--env-master', $envMaster) }
else { Write-Log ('注意: 環境マスタがありません（{0}）。すべての環境を internal として扱い、回収漏れも検出できません' -f $envMaster) }
if ($previous) { $arguments += @('--previous', $previous.FullName); Write-Log ('前回のレポート: {0}' -f $previous.Name) }

$runCode = Invoke-Tool $arguments
if ($runCode -eq 0) {
    # フォルダ名は英数字だけなので ASCII で書く（PowerShell 5.1 の UTF8 は BOM が付き、他のスクリプトで読みにくい）
    Set-Content -LiteralPath (Join-Path $reportsDir 'latest.txt') -Value $name -Encoding ASCII
    $exitCode = if ($updateCode -ne 0) { 1 } else { 0 }
    Write-Log ('終了: 成功。レポート: {0}' -f $outDir)
} else {
    $exitCode = 2
    Write-Log ('終了: 失敗（照合の終了コード {0}）。ログを確認してください' -f $runCode)
}

# 古いログを消す（レポートは証跡なので消さない）
Get-ChildItem -LiteralPath $logDir -Filter 'run_*.log' -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepLogDays) } |
    Remove-Item -Force -ErrorAction SilentlyContinue

exit $exitCode
