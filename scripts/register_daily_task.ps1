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

  # ログオフ中も実行する（パスワードを保存しない S4U。インターネットには出られるが、ネットワーク共有には
  # 接続できない。管理者として開いた PowerShell で登録する）
  powershell -ExecutionPolicy Bypass -File scripts\register_daily_task.ps1 -InventoryDir D:\vuln\inventory -NoPassword

  # 毎日の自動実行（脆弱性データの更新 → 照合 → レポート）を登録する。作業フォルダの構成は daily_run.ps1 を参照
  powershell -ExecutionPolicy Bypass -File scripts\register_daily_task.ps1 -Run -BaseDir D:\vuln -NoPassword

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
    [string]$TaskName,
    # 脆弱性データの更新だけでなく、照合とレポートまで行う（scripts\daily_run.ps1）。-BaseDir が必要
    [switch]$Run,
    # -Run の作業フォルダ（inventory\、advisory\、env_master.csv、reports\ を置く）
    [string]$BaseDir,
    # ログオフ中も実行する（実行するユーザーのパスワードが必要）
    [switch]$RunWhetherLoggedOn,
    # ログオフ中も実行する。パスワードを保存しない（S4U）。インベントリや脆弱性データをネットワーク共有に置く場合は使えない
    [switch]$NoPassword,
    [switch]$Unregister
)

$ErrorActionPreference = 'Stop'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolDir = Split-Path -Parent $scriptDir

if (-not $TaskName) { $TaskName = if ($Run) { 'vuln-triage run' } else { 'vuln-triage db-update' } }

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

if ($Run) {
    if (-not $BaseDir) { throw '-Run には -BaseDir（作業フォルダ）が必要です' }
    [void][System.IO.Directory]::CreateDirectory($BaseDir)
    foreach ($sub in 'inventory', 'advisory') { [void][System.IO.Directory]::CreateDirectory((Join-Path $BaseDir $sub)) }
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', (Quote (Join-Path $scriptDir 'daily_run.ps1')),
        '-Python', (Quote $Python), '-WorkDir', (Quote $toolDir), '-BaseDir', (Quote (Resolve-Path -LiteralPath $BaseDir).Path))
    $logHint = Join-Path (Resolve-Path -LiteralPath $BaseDir).Path 'logsun_<日付>.log'
} else {
    $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', (Quote (Join-Path $scriptDir 'daily_db_update.ps1')),
        '-Python', (Quote $Python), '-WorkDir', (Quote $toolDir))
    if ($InventoryDir) { $arguments += @('-InventoryDir', (Quote (Resolve-Path -LiteralPath $InventoryDir).Path)) }
    $logHint = Join-Path $toolDir 'logs\db-update_<日付>.log'
}
if ($DbDir) { $arguments += @('-DbDir', (Quote $DbDir)) }
if ($Config) { $arguments += @('-Config', (Quote (Resolve-Path -LiteralPath $Config).Path)) }

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ($arguments -join ' ') -WorkingDirectory $toolDir
$trigger = New-ScheduledTaskTrigger -Daily -At $Time
# 停止中で時刻を過ぎたら起動後に実行、失敗したら 30 分後に 2 回まで再試行、2 時間（-Run は 6 時間）で打ち切り
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 2 `
    -RestartInterval (New-TimeSpan -Minutes 30) -ExecutionTimeLimit (New-TimeSpan -Hours $(if ($Run) { 6 } else { 2 }))
$user = '{0}\{1}' -f $env:USERDOMAIN, $env:USERNAME
$description = if ($Run) { '脆弱性の毎日の自動調査（データの更新・照合・レポート）。ログ: ' + $logHint }
               else { '脆弱性データ（OSV.dev / Amazon Linux）の毎日の差分更新。ログ: ' + $logHint }

if ($NoPassword) {
    $principal = New-ScheduledTaskPrincipal -UserId $user -LogonType S4U -RunLevel Limited
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
        -Description $description -Principal $principal -Force | Out-Null
} elseif ($RunWhetherLoggedOn) {
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
Write-Host ('  結果の確認: {0}、またはタスクスケジューラの「履歴」' -f $logHint)
