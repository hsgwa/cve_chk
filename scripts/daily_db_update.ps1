<#
=============================================================================
daily_db_update.ps1 - 脆弱性データの毎日の更新（タスクスケジューラから実行する）

  python -m vuln_triage db-update を実行し、結果を logs\db-update_YYYYMMDD.log に追記する。
  終了コードは db-update のものをそのまま返す（0 = 成功、1 = 一部失敗、2 = 使い方の誤り）。

手動で試す:
  powershell -ExecutionPolicy Bypass -File scripts\daily_db_update.ps1 -InventoryDir D:\vuln\inventory
=============================================================================
#>
param(
    # 回収データのフォルダ。指定すると、新しく出てきたエコシステムのデータも取得する
    [string]$InventoryDir,
    # 脆弱性データの置き場所（省略時は config.yaml の vulndb.dir）
    [string]$DbDir,
    # 設定ファイル（省略時は作業フォルダの config.yaml）
    [string]$Config,
    # python.exe の場所（省略時は PATH の python）
    [string]$Python = 'python',
    # 作業フォルダ（省略時はこのスクリプトの1つ上 = ツールのフォルダ）
    [string]$WorkDir,
    # ログの置き場所（省略時は 作業フォルダ\logs）
    [string]$LogDir,
    # ログを残す日数
    [int]$KeepDays = 30,
    # 差分ではなく全件を取り直す
    [switch]$Full
)

$ErrorActionPreference = 'Continue'
if (-not $WorkDir) { $WorkDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path) }
Set-Location -LiteralPath $WorkDir
if (-not $LogDir) { $LogDir = Join-Path $WorkDir 'logs' }
[void][System.IO.Directory]::CreateDirectory($LogDir)
$logFile = Join-Path $LogDir ('db-update_{0}.log' -f (Get-Date -Format 'yyyyMMdd'))

function Write-Log([string]$Message) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $logFile -Value $line -Encoding UTF8
    Write-Host $line
}

# Python の出力を UTF-8 にそろえる（ログの文字化け防止）
$env:PYTHONUTF8 = '1'
$env:PYTHONIOENCODING = 'utf-8'

$arguments = @('-m', 'vuln_triage', 'db-update')
if ($InventoryDir) { $arguments += @('--inventory-dir', $InventoryDir) }
if ($DbDir) { $arguments += @('--db-dir', $DbDir) }
if ($Config) { $arguments += @('--config', $Config) }
if ($Full) { $arguments += '--full' }

Write-Log ('開始: {0} {1}' -f $Python, ($arguments -join ' '))
$exitCode = 1
try {
    & $Python @arguments 2>&1 | ForEach-Object {
        # 標準エラーの行は ErrorRecord になるので、元の文字列を取り出す
        if ($_ -is [System.Management.Automation.ErrorRecord]) {
            $text = if ($null -ne $_.TargetObject) { "$($_.TargetObject)" } else { $_.Exception.Message }
        } else {
            $text = "$_"
        }
        Add-Content -Path $logFile -Value $text -Encoding UTF8
        Write-Host $text
    }
    $exitCode = $LASTEXITCODE
} catch {
    Write-Log ('実行できません: {0}' -f $_.Exception.Message)
    $exitCode = 2
}
if ($exitCode -eq 0) { Write-Log '終了: 成功' }
else { Write-Log ('終了: 失敗（終了コード {0}）。更新できなかったデータは前回の内容のまま残っています' -f $exitCode) }

# 古いログを消す
Get-ChildItem -LiteralPath $LogDir -Filter 'db-update_*.log' -ErrorAction SilentlyContinue |
    Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepDays) } |
    Remove-Item -Force -ErrorAction SilentlyContinue

exit $exitCode
