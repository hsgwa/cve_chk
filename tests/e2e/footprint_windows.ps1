<#
対象マシンに何も残さないことの試験（Windows。CI の Windows Server で管理者として実行する）。

  1. 対照: PowerShell を同じ起動のしかたで起動し、待つだけのスクリプトを実行する。その前後の一覧の違いは、
     このツールと関係なく Windows が書き換えるもの（雑音）として記録する
  2. 一覧を取る: ユーザーのプロファイル・一時フォルダ・ProgramData・Windows\Temp のファイル
     （パス・大きさ・更新日時）、インストール済みソフト（レジストリ）、サービス、タスク
  3. 回収用のフォルダ（C:\vuln-collect）を作り、回収スクリプトを置いて実行する
  4. 回収物を取り出し、回収用のフォルダを消す
  5. もう一度一覧を取り、2 との違いから雑音を除いて、違いが無いことを確かめる（あれば終了コード 1）

比べないもの（回収スクリプトは書かない。Windows のデスクトップのプロセスがいつでも書き換える）:
  - PowerShell が起動のたびに書くファイル（StartupProfileData-*）
  - ユーザーのレジストリの記録（ntuser.dat*、UsrClass.dat*）
  - エクスプローラーの縮小版のキャッシュ（thumbcache_*）、ストアアプリの設定（AppData\Local\Packages\）

使い方: footprint_windows.ps1 -Collector <collect_win.ps1> -Dest <回収物のコピー先> -ScanRoots <走査するフォルダ>...
#>
param(
    [Parameter(Mandatory = $true)][string]$Collector,
    [Parameter(Mandatory = $true)][string]$Dest,
    [Parameter(Mandatory = $true)][string[]]$ScanRoots,
    [int]$ControlSeconds = 30
)
$ErrorActionPreference = 'Stop'
$tool = 'C:\vuln-collect'
$control = 'C:\vuln-footprint-control'
$ignoreNames = @('StartupProfileData-*', 'ntuser.dat*', 'UsrClass.dat*', 'thumbcache_*')
$ignorePaths = @('*\AppData\Local\Packages\*')

function Test-Ignored([System.IO.FileInfo]$File) {
    foreach ($pattern in $ignoreNames) { if ($File.Name -like $pattern) { return $true } }
    foreach ($pattern in $ignorePaths) { if ($File.FullName -like $pattern) { return $true } }
    return $false
}

function Get-Snapshot {
    $items = @{}
    $roots = @($env:USERPROFILE, $env:TEMP, $env:ProgramData, (Join-Path $env:SystemRoot 'Temp')) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { -not (Test-Ignored $_) } |
            ForEach-Object { $items['F ' + $_.FullName] = '{0}|{1}' -f $_.Length, $_.LastWriteTimeUtc.Ticks }
    }
    foreach ($key in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
                     'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall') {
        Get-ChildItem -Path $key -ErrorAction SilentlyContinue | ForEach-Object { $items['R ' + $_.Name] = '' }
    }
    Get-Service | ForEach-Object { $items['S ' + $_.Name] = [string]$_.StartType }
    Get-ScheduledTask | ForEach-Object { $items['T ' + $_.TaskPath + $_.TaskName] = '' }
    return $items
}

function Get-Changes($Before, $After) {
    $changed = New-Object System.Collections.Generic.List[string]
    foreach ($key in $Before.Keys) {
        if (-not $After.ContainsKey($key)) { $changed.Add('削除 ' + $key) }
        elseif ($After[$key] -ne $Before[$key]) { $changed.Add('変更 ' + $key) }
    }
    foreach ($key in $After.Keys) { if (-not $Before.ContainsKey($key)) { $changed.Add('追加 ' + $key) } }
    return $changed
}

# ---- 1. 対照（雑音を調べる） ----
New-Item -ItemType Directory -Force $control | Out-Null
$wait = Join-Path $control 'wait.ps1'
Set-Content -LiteralPath $wait -Value "Start-Sleep -Seconds $ControlSeconds" -Encoding UTF8
$s0 = Get-Snapshot
powershell -NoProfile -ExecutionPolicy Bypass -File $wait
$s1 = Get-Snapshot
Remove-Item -LiteralPath $control -Recurse -Force
$noise = @{}
foreach ($change in (Get-Changes $s0 $s1)) { $noise[$change.Substring(3)] = $true }
Write-Host ('対照（{0} 秒）で変わったもの（雑音）: {1} 件' -f $ControlSeconds, $noise.Count)

# ---- 2〜4. 回収 ----
$before = Get-Snapshot
New-Item -ItemType Directory -Force $tool | Out-Null
Copy-Item -LiteralPath $Collector -Destination $tool
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $tool 'collect_win.ps1') -ScanRoots ($ScanRoots -join ',') -SkipDll
$code = $LASTEXITCODE
New-Item -ItemType Directory -Force $Dest | Out-Null
Get-ChildItem (Join-Path $tool 'out') -Directory | ForEach-Object { Copy-Item -Path (Join-Path $_.FullName '*') -Destination $Dest -Recurse }
Remove-Item -LiteralPath $tool -Recurse -Force
$after = Get-Snapshot

# ---- 5. 比べる ----
$changes = @(Get-Changes $before $after | Where-Object { -not $noise.ContainsKey($_.Substring(3)) })
if ($changes.Count -eq 0) {
    Write-Host ('footprint OK: 回収用のフォルダを消したら、実行前と同じ（{0} 件を比較。雑音 {1} 件を除く）' -f $before.Count, $noise.Count)
} else {
    Write-Host 'footprint NG: 回収用のフォルダの外に変化があります'
    $changes | Select-Object -First 50 | ForEach-Object { Write-Host $_ }
    exit 1
}
exit $code
