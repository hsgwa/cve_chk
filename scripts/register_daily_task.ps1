<#
=============================================================================
register_daily_task.ps1 - 脆弱性データの毎日の更新を、Windows のタスクスケジューラに登録する

  毎日決まった時刻に scripts\daily_db_update.ps1 を実行するタスクを登録（同じ名前があれば上書き）する。
  Windows 標準の機能（ScheduledTasks）だけを使う。

例:
  # 毎朝 6:30 に更新（ログオン中のみ実行）
  powershell -ExecutionPolicy Bypass -File scripts\register_daily_task.ps1 -InventoryDir D:\vuln\inventory

  # ログオフ中も実行する（パスワードを尋ねられる）
  powershell -ExecutionPolicy Bypass -File scripts\register_daily_task.ps1 -InventoryDir D:\vuln\inventory -RunWhetherLoggedOn

  # 登録を消す
  powershell -ExecutionPolicy Bypass -File scripts\register_daily_task.ps1 -Unregister
=============================================================================
#>
param(
    [string]$Time = '06:30',
    [string]$InventoryDir,
    [string]$DbDir,
    [string]$Config,
    # python.exe の場所（省略時は PATH から探して、その絶対パスを登録する）
    [string]$Python,
    [string]$TaskName = 'vuln-triage db-update',
    # ログオフ中も実行する（実行するユーザーのパスワードが必要）
    [switch]$RunWhetherLoggedOn,
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolDir = Split-Path -Parent $scriptDir

if ($Unregister) {
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
    Write-Host ('タスク「{0}」を削除しました' -f $TaskName)
    exit 0
}

if (-not $Python) {
    $command = Get-Command python -ErrorAction SilentlyContinue
    if (-not $command) { throw 'python が見つかりません。-Python で python.exe の場所を指定してください' }
    $Python = $command.Source
}
$Python = (Resolve-Path -LiteralPath $Python).Path

function Quote([string]$Value) { return '"' + $Value.Replace('"', '\"') + '"' }

$arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass',
    '-File', (Quote (Join-Path $scriptDir 'daily_db_update.ps1')),
    '-Python', (Quote $Python), '-WorkDir', (Quote $toolDir))
if ($InventoryDir) { $arguments += @('-InventoryDir', (Quote (Resolve-Path -LiteralPath $InventoryDir).Path)) }
if ($DbDir) { $arguments += @('-DbDir', (Quote $DbDir)) }
if ($Config) { $arguments += @('-Config', (Quote (Resolve-Path -LiteralPath $Config).Path)) }

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($arguments -join ' ') -WorkingDirectory $toolDir
$trigger = New-ScheduledTaskTrigger -Daily -At $Time
# 停止中で時刻を過ぎたら起動後に実行、失敗したら 30 分後に 2 回まで再試行、2 時間で打ち切り
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 30) -ExecutionTimeLimit (New-TimeSpan -Hours 2)
$user = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
$description = '脆弱性データ（OSV.dev / Amazon Linux）の毎日の差分更新。ログ: ' + (Join-Path $toolDir 'logs')

if ($RunWhetherLoggedOn) {
    $credential = Get-Credential -UserName $user -Message 'タスクを実行するユーザーのパスワードを入力してください'
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -Description $description -User $credential.UserName `
        -Password $credential.GetNetworkCredential().Password -RunLevel Limited -Force | Out-Null
} else {
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -Description $description -Principal $principal -Force | Out-Null
}

Write-Host ('タスク「{0}」を登録しました（毎日 {1}）' -f $TaskName, $Time)
Write-Host ('  実行内容: powershell.exe {0}' -f ($arguments -join ' '))
Write-Host ('  すぐに試す: Start-ScheduledTask -TaskName "{0}"' -f $TaskName)
Write-Host ('  結果の確認: {0}\db-update_<日付>.log、またはタスクスケジューラの「履歴」' -f (Join-Path $toolDir 'logs'))
