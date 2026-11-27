<#
対象マシンに何も残さないことの試験（Windows。CI の Windows Server で管理者として実行する）。

  1. 次の一覧を取る: ユーザーのプロファイル・一時フォルダ・ProgramData・Windows\Temp のファイル
     （パス・大きさ・更新日時）、インストール済みソフト（レジストリ）、サービス、タスク
  2. 回収用のフォルダ（C:\vuln-collect）を作り、回収スクリプトを置いて実行する
  3. 回収物を取り出し、回収用のフォルダを消す
  4. もう一度一覧を取り、1 と同じであることを確かめる（違えば終了コード 1）

PowerShell 自身が起動のたびに書くファイル（StartupProfileData-*）は、このツールに関係なく
PowerShell を使えば書かれるので比べない。

使い方: footprint_windows.ps1 -Collector <collect_win.ps1> -Dest <回収物のコピー先> -ScanRoots <走査するフォルダ>...
#>
param(
    [Parameter(Mandatory = $true)][string]$Collector,
    [Parameter(Mandatory = $true)][string]$Dest,
    [Parameter(Mandatory = $true)][string[]]$ScanRoots
)
$ErrorActionPreference = 'Stop'
$tool = 'C:\vuln-collect'
$ignore = 'StartupProfileData-'

function Get-Snapshot {
    $lines = New-Object System.Collections.Generic.List[string]
    $roots = @($env:USERPROFILE, $env:TEMP, $env:ProgramData, (Join-Path $env:SystemRoot 'Temp')) |
        Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
    foreach ($root in $roots) {
        Get-ChildItem -LiteralPath $root -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -notlike "$ignore*" } |
            ForEach-Object { $lines.Add(('F {0}|{1}|{2}' -f $_.FullName, $_.Length, $_.LastWriteTimeUtc.Ticks)) }
    }
    foreach ($key in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                     'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
                     'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall') {
        Get-ChildItem -Path $key -ErrorAction SilentlyContinue | ForEach-Object { $lines.Add('R ' + $_.Name) }
    }
    Get-Service | ForEach-Object { $lines.Add(('S {0}|{1}' -f $_.Name, $_.StartType)) }
    Get-ScheduledTask | ForEach-Object { $lines.Add(('T {0}{1}' -f $_.TaskPath, $_.TaskName)) }
    return ($lines | Sort-Object)
}

$before = Get-Snapshot

New-Item -ItemType Directory -Force $tool | Out-Null
Copy-Item -LiteralPath $Collector -Destination $tool
powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $tool 'collect_win.ps1') -ScanRoots ($ScanRoots -join ',') -SkipDll
$code = $LASTEXITCODE
New-Item -ItemType Directory -Force $Dest | Out-Null
Get-ChildItem (Join-Path $tool 'out') -Directory | ForEach-Object { Copy-Item -Path (Join-Path $_.FullName '*') -Destination $Dest -Recurse }
Remove-Item -LiteralPath $tool -Recurse -Force

$after = Get-Snapshot
$diff = @(Compare-Object -ReferenceObject $before -DifferenceObject $after)
if ($diff.Count -eq 0) {
    Write-Host ('footprint OK: 回収用のフォルダを消したら、実行前と同じ（{0} 件を比較）' -f $before.Count)
} else {
    Write-Host 'footprint NG: 回収用のフォルダの外に変化があります'
    $diff | Select-Object -First 50 | ForEach-Object { Write-Host ('{0} {1}' -f $_.SideIndicator, $_.InputObject) }
    exit 1
}
exit $code
