<#
=============================================================================
collect_win.ps1 - Windows のインベントリ回収（exe の持ち込み不要）

実行（管理者として開いた PowerShell で）:
    powershell -ExecutionPolicy Bypass -File collect_win.ps1
    powershell -ExecutionPolicy Bypass -File collect_win.ps1 -ScanRoots 'D:\apps','E:\hulft'
    powershell -ExecutionPolicy Bypass -File collect_win.ps1 -AllDrives

出力:   .\out\<ホスト名>\inventory.json   インベントリ本体
        .\out\<ホスト名>\collect.log      実行ログ
回収:   out\<ホスト名>\ フォルダごと管理 PC の <inventory-dir>\ 配下へコピー

取得するもの:
    OS のビルド番号 / 適用済み KB / インストール済みソフト（レジストリ）/
    exe・dll のバージョン情報 / jar・war・ear の中身（入れ子も）/
    Python パッケージ / npm パッケージ / NuGet パッケージ / 個別製品の版 /
    実行中のプロセスとサービスの場所 / 読めなかったフォルダ
PowerShell 5.1 以降で動作する。
=============================================================================
#>
param(
    # 走査するフォルダ。省略時は Program Files、Program Files (x86)、ProgramData
    [string[]]$ScanRoots,
    # 固定ドライブをすべて走査する（時間がかかる）
    [switch]$AllDrives,
    [string]$OutDir,
    # dll のバージョン情報を取らない（exe のみにして時間を短縮する）
    [switch]$SkipDll,
    # 入れ子になった jar をたどる深さ
    [int]$MaxNestDepth = 3
)

# ---- 個別製品の版取得 --------------------------------------------------------
# レジストリや通常の走査で版が取れない製品をここに書く。
#   fileversion  Target（ワイルドカード可）の exe/dll のバージョン情報を版とする
#   filetext     Target（ワイルドカード可）のファイルの中身から Regex で版を抜き出す
#   cmd          Target のコマンドを実行し、出力から Regex で版を抜き出す
#   exists       Target（ワイルドカード可）があれば「存在する（版不明）」とする
#   find         Target の名前（ワイルドカード可）のファイル/フォルダを走査対象から探し、
#                あれば「存在する（版不明）」とする
# 版不明で見つかった製品は、管理 PC 側で「影響あり（比較不能）」と判定される。
# ★ HULFT / DataMagic のインストール先と版の取り方は環境ごとに異なるため、
#    実機で確認して fileversion などの行を追加すること（下はコメントの記入例）。
$CustomProducts = @(
    @{ Name = 'HULFT';     Type = 'find'; Target = '*hulft*' }
    @{ Name = 'DataMagic'; Type = 'find'; Target = '*datamagic*' }
    # @{ Name = 'HULFT';     Type = 'fileversion'; Target = 'C:\<インストール先>\bin\<主要な exe>.exe' }
    # @{ Name = 'DataMagic'; Type = 'filetext';    Target = 'C:\<インストール先>\<版が書かれたファイル>'; Regex = '\d+\.\d+\.\d+' }
)
# find で探す深さ
$FindDepth = 3
# -----------------------------------------------------------------------------

$ErrorActionPreference = 'Continue'
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$hostName = [System.Environment]::MachineName
if (-not $OutDir) { $OutDir = Join-Path (Join-Path $scriptDir 'out') $hostName }
[void][System.IO.Directory]::CreateDirectory($OutDir)
$logPath = Join-Path $OutDir 'collect.log'
Set-Content -Path $logPath -Value '' -Encoding UTF8

function Write-Log([string]$Message) {
    $line = '[{0}] {1}' -f (Get-Date -Format 'HH:mm:ss'), $Message
    Write-Host $line
    Add-Content -Path $logPath -Value $line -Encoding UTF8
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$sections = [ordered]@{}
function Set-Section([string]$Name, $Items, [string]$Status = 'ok', [string]$Reason = '') {
    # List[object] を @() で配列にすると失敗する場合があるため ToArray() を使う
    if ($Items -is [System.Collections.Generic.List[object]]) { $array = $Items.ToArray() }
    else { $array = @($Items) }
    $sections[$Name] = [ordered]@{ status = $Status; reason = $Reason; items = $array }
    Write-Log ('{0}: {1} 件 ({2}) {3}' -f $Name, $array.Count, $Status, $Reason)
}

$isAdmin = $false
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $isAdmin = (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
} catch { }
Write-Log ('収集開始: host={0} admin={1}' -f $hostName, $isAdmin)
if (-not $isAdmin) { Write-Log '注意: 管理者ではありません。読めないフォルダは結果から漏れます' }

# ---- OS ----------------------------------------------------------------------
$os = [ordered]@{ family = 'windows'; product_name = ''; display_version = ''; build = ''; arch = ''; system_root = "$env:SystemRoot" }
try {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $os.product_name = [string]$cv.ProductName
    try {
        # Windows 11 はレジストリの ProductName が "Windows 10" のままなので WMI の名称を優先する
        $caption = (Get-CimInstance Win32_OperatingSystem -ErrorAction Stop).Caption
        if ($caption) { $os.product_name = [string]$caption }
    } catch { }
    if ($cv.DisplayVersion) { $os.display_version = [string]$cv.DisplayVersion }
    elseif ($cv.ReleaseId) { $os.display_version = [string]$cv.ReleaseId }
    $major = $cv.CurrentMajorVersionNumber
    $minor = $cv.CurrentMinorVersionNumber
    if ($null -eq $major) {
        $parts = ([string]$cv.CurrentVersion).Split('.')
        $major = $parts[0]
        $minor = if ($parts.Count -gt 1) { $parts[1] } else { 0 }
    }
    $ubr = if ($null -ne $cv.UBR) { $cv.UBR } else { 0 }
    $os.build = '{0}.{1}.{2}.{3}' -f $major, $minor, $cv.CurrentBuildNumber, $ubr
    $os.arch = [string]$env:PROCESSOR_ARCHITECTURE
    Write-Log ('OS: {0} {1} build {2}' -f $os.product_name, $os.display_version, $os.build)
} catch {
    Write-Log ('OS 情報を取得できません: {0}' -f $_.Exception.Message)
}

# ---- 適用済み KB -------------------------------------------------------------
try {
    $hotfixes = @(Get-HotFix -ErrorAction Stop | ForEach-Object {
        [ordered]@{ id = [string]$_.HotFixID; installed_on = [string]$_.InstalledOn; description = [string]$_.Description }
    })
    Set-Section 'hotfixes' $hotfixes
} catch {
    Set-Section 'hotfixes' @() 'failed' $_.Exception.Message
}

# ---- インストール済みソフト（レジストリ） --------------------------------------
try {
    $software = New-Object System.Collections.Generic.List[object]
    $seen = @{}
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $readAny = $false
    foreach ($key in $keys) {
        $entries = Get-ItemProperty $key -ErrorAction SilentlyContinue
        if ($null -ne $entries) { $readAny = $true }
        foreach ($entry in @($entries)) {
            if (-not $entry.DisplayName) { continue }
            $id = '{0}|{1}' -f $entry.DisplayName, $entry.DisplayVersion
            if ($seen.ContainsKey($id)) { continue }
            $seen[$id] = $true
            $software.Add([ordered]@{
                name = [string]$entry.DisplayName; version = [string]$entry.DisplayVersion
                publisher = [string]$entry.Publisher; install_location = [string]$entry.InstallLocation
            })
        }
    }
    if ($readAny) { Set-Section 'installed_software' $software }
    else { Set-Section 'installed_software' @() 'failed' 'レジストリを読めません' }
} catch {
    Set-Section 'installed_software' @() 'failed' $_.Exception.Message
}

# ---- 実行中のプロセスとサービス -----------------------------------------------
try {
    $running = @{}
    try {
        Get-CimInstance Win32_Process -ErrorAction Stop | ForEach-Object {
            if ($_.ExecutablePath) { $running[[string]$_.ExecutablePath] = $true }
        }
        Get-CimInstance Win32_Service -ErrorAction Stop | ForEach-Object {
            $path = [string]$_.PathName
            if ($path -match '^\s*"([^"]+)"') { $running[$Matches[1]] = $true }
            elseif ($path -match '^\s*(\S+\.exe)') { $running[$Matches[1]] = $true }
        }
    } catch {
        Get-Process -ErrorAction SilentlyContinue | ForEach-Object { if ($_.Path) { $running[[string]$_.Path] = $true } }
    }
    Set-Section 'running' @($running.Keys | Sort-Object | ForEach-Object { [ordered]@{ path = $_ } })
} catch {
    Set-Section 'running' @() 'failed' $_.Exception.Message
}

# ---- 走査対象 -----------------------------------------------------------------
if ($AllDrives) {
    $ScanRoots = @([System.IO.DriveInfo]::GetDrives() |
        Where-Object { $_.DriveType -eq [System.IO.DriveType]::Fixed -and $_.IsReady } |
        ForEach-Object { $_.RootDirectory.FullName })
} elseif (-not $ScanRoots) {
    $ScanRoots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, $env:ProgramData) | Where-Object { $_ }
}
$ScanRoots = @($ScanRoots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique)
Write-Log ('走査対象: {0}' -f ($ScanRoots -join ', '))

# 走査しないフォルダ（OS 本体と、このスクリプトの出力先）
$excludeDirs = @()
if ($env:SystemRoot) { $excludeDirs += $env:SystemRoot.TrimEnd('\').ToLower() }
$excludeDirs += $OutDir.TrimEnd('\', '/').ToLower()
$excludeNames = @('$recycle.bin', 'system volume information')

$javaArchives = New-Object System.Collections.Generic.List[object]
$pythonPackages = New-Object System.Collections.Generic.List[object]
$nodePackages = New-Object System.Collections.Generic.List[object]
$dotnetPackages = New-Object System.Collections.Generic.List[object]
$executables = New-Object System.Collections.Generic.List[object]
$unreadable = New-Object System.Collections.Generic.List[object]
$exeSeen = @{}
$dotnetSeen = @{}
$counts = @{ files = 0; archives = 0 }

function Read-EntryText($Entry) {
    $reader = New-Object System.IO.StreamReader($Entry.Open(), [System.Text.Encoding]::UTF8)
    try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
}

function Get-Sha1([string]$Path) {
    try {
        $sha = [System.Security.Cryptography.SHA1]::Create()
        $stream = [System.IO.File]::OpenRead($Path)
        try { return ([System.BitConverter]::ToString($sha.ComputeHash($stream)) -replace '-', '').ToLower() }
        finally { $stream.Dispose(); $sha.Dispose() }
    } catch { return '' }
}

# jar / war / ear を開いて Maven の座標を取り出す。入れ子の jar もたどる。
function Read-Archive([System.IO.Stream]$Stream, [string]$DisplayPath, [int]$Depth, [string]$Sha1) {
    $zip = $null
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($Stream, [System.IO.Compression.ZipArchiveMode]::Read)
        $found = 0
        $nested = 0
        $manifest = $null
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            if ($name -like 'META-INF/maven/*/pom.properties') {
                $props = @{}
                foreach ($line in ((Read-EntryText $entry) -split "`r?`n")) {
                    if ($line -match '^\s*([A-Za-z]+)\s*=\s*(.*?)\s*$') { $props[$Matches[1]] = $Matches[2] }
                }
                if ($props['artifactId'] -and $props['version']) {
                    $javaArchives.Add([ordered]@{
                        group = [string]$props['groupId']; artifact = [string]$props['artifactId']
                        version = [string]$props['version']; path = $DisplayPath; method = 'pom.properties'
                    })
                    $found++
                }
            } elseif ($name -eq 'META-INF/MANIFEST.MF') {
                $manifest = Read-EntryText $entry
            } elseif ($Depth -lt $MaxNestDepth -and $name -match '\.(jar|war|ear)$' -and $entry.Length -gt 0) {
                $memory = New-Object System.IO.MemoryStream
                try {
                    $inner = $entry.Open()
                    try { $inner.CopyTo($memory) } finally { $inner.Dispose() }
                    $memory.Position = 0
                    Read-Archive $memory ('{0}!/{1}' -f $DisplayPath, $name) ($Depth + 1) ''
                    $nested++
                } finally { $memory.Dispose() }
            }
        }
        if ($found -eq 0 -and $nested -eq 0) {
            # pom.properties が無い jar: MANIFEST、だめならファイル名から推定する
            $title = ''; $version = ''; $method = ''
            if ($manifest) {
                $joined = $manifest -replace "`r?`n ", ''
                if ($joined -match '(?m)^Bundle-SymbolicName:\s*([^;\r\n]+)') { $title = $Matches[1].Trim() }
                if ($joined -match '(?m)^Bundle-Version:\s*(\S+)') { $version = $Matches[1].Trim() }
                if (-not $title -and $joined -match '(?m)^Implementation-Title:\s*(.+?)\s*$') { $title = $Matches[1].Trim() }
                if (-not $version -and $joined -match '(?m)^Implementation-Version:\s*(\S+)') { $version = $Matches[1].Trim() }
                if ($title) { $method = 'manifest' }
            }
            $leaf = ($DisplayPath -split '[\\/]')[-1]
            if ($leaf -match '^(.+?)-(\d[\w.\-]*?)\.(jar|war|ear)$') {
                $fileTitle = $Matches[1]; $fileVersion = $Matches[2]
                if (-not $title -or -not $version) { $title = $fileTitle; $version = $fileVersion; $method = 'filename' }
                elseif ($title.Contains(' ')) { $title = $fileTitle }
            }
            if ($title) {
                $javaArchives.Add([ordered]@{
                    group = ''; artifact = $title; version = $version; path = $DisplayPath; method = $method; sha1 = $Sha1
                })
            } else {
                $name = [System.IO.Path]::GetFileNameWithoutExtension($leaf)
                $javaArchives.Add([ordered]@{
                    group = ''; artifact = $name; version = ''; path = $DisplayPath; method = 'unknown'; sha1 = $Sha1
                })
            }
        }
    } catch {
        $unreadable.Add([ordered]@{ path = $DisplayPath; reason = ('アーカイブを読めません: {0}' -f $_.Exception.Message) })
    } finally {
        if ($zip) { $zip.Dispose() }
    }
}

function Read-MetadataFile([string]$Path) {
    # Python の METADATA / PKG-INFO から Name と Version を読む
    $name = ''; $version = ''
    $reader = New-Object System.IO.StreamReader($Path, [System.Text.Encoding]::UTF8)
    try {
        for ($i = 0; $i -lt 60; $i++) {
            $line = $reader.ReadLine()
            if ($null -eq $line -or $line -eq '') { break }
            if ($line -match '^Name:\s*(.+?)\s*$') { $name = $Matches[1] }
            elseif ($line -match '^Version:\s*(.+?)\s*$') { $version = $Matches[1] }
        }
    } finally { $reader.Dispose() }
    if ($name -and $version) { $pythonPackages.Add([ordered]@{ name = $name; version = $version; path = $Path }) }
}

function Invoke-File([string]$Path) {
    $counts.files++
    $leaf = [System.IO.Path]::GetFileName($Path)
    $ext = [System.IO.Path]::GetExtension($Path).ToLower()
    try {
        if ($ext -eq '.jar' -or $ext -eq '.war' -or $ext -eq '.ear') {
            $counts.archives++
            $stream = [System.IO.File]::OpenRead($Path)
            try { Read-Archive $stream $Path 0 (Get-Sha1 $Path) } finally { $stream.Dispose() }
        } elseif ($leaf -eq 'METADATA' -and $Path -match '\.dist-info[\\/]METADATA$') {
            Read-MetadataFile $Path
        } elseif ($leaf -eq 'PKG-INFO' -and $Path -match '\.egg-info[\\/]PKG-INFO$') {
            Read-MetadataFile $Path
        } elseif ($ext -eq '.egg-info') {
            Read-MetadataFile $Path
        } elseif ($leaf -eq 'package.json' -and $Path -match '[\\/]node_modules[\\/](@[^\\/]+[\\/])?[^\\/]+[\\/]package\.json$') {
            $json = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($json.name -and $json.version) {
                $nodePackages.Add([ordered]@{ name = [string]$json.name; version = [string]$json.version; path = $Path })
            }
        } elseif ($leaf -like '*.deps.json') {
            $json = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($json.libraries) {
                foreach ($prop in $json.libraries.PSObject.Properties) {
                    if ($prop.Value.type -ne 'package') { continue }
                    $pair = $prop.Name -split '/', 2
                    if ($pair.Count -ne 2) { continue }
                    $id = '{0}|{1}|{2}' -f $pair[0], $pair[1], $Path
                    if ($dotnetSeen.ContainsKey($id)) { continue }
                    $dotnetSeen[$id] = $true
                    $dotnetPackages.Add([ordered]@{ name = $pair[0]; version = $pair[1]; path = $Path })
                }
            }
        } elseif ($ext -eq '.exe' -or ($ext -eq '.dll' -and -not $SkipDll)) {
            $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
            if ($info.ProductName -or $info.ProductVersion -or $info.FileVersion) {
                # 同じフォルダ・同じ製品・同じ版の dll は1件にまとめる（件数を抑える）
                $id = if ($ext -eq '.dll') {
                    '{0}|{1}|{2}' -f [System.IO.Path]::GetDirectoryName($Path), $info.ProductName, $info.ProductVersion
                } else { $Path }
                if (-not $exeSeen.ContainsKey($id)) {
                    $exeSeen[$id] = $true
                    $executables.Add([ordered]@{
                        product_name = [string]$info.ProductName; file_name = $leaf
                        product_version = [string]$info.ProductVersion; file_version = [string]$info.FileVersion
                        company = [string]$info.CompanyName; path = $Path
                    })
                }
            }
        }
    } catch {
        $unreadable.Add([ordered]@{ path = $Path; reason = $_.Exception.Message })
    }
}

function Invoke-Walk([string]$Root) {
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try { $files = [System.IO.Directory]::GetFiles($dir) }
        catch { $unreadable.Add([ordered]@{ path = $dir; reason = $_.Exception.Message }); continue }
        foreach ($file in $files) { Invoke-File $file }
        try { $subdirs = [System.IO.Directory]::GetDirectories($dir) } catch { continue }
        foreach ($sub in $subdirs) {
            $lower = $sub.TrimEnd('\').ToLower()
            if ($excludeDirs -contains $lower) { continue }
            if ($excludeNames -contains [System.IO.Path]::GetFileName($lower)) { continue }
            try {
                # ジャンクションやシンボリックリンクはたどらない（循環を避ける）
                $attributes = [System.IO.File]::GetAttributes($sub)
                if (($attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            } catch { continue }
            $stack.Push($sub)
        }
    }
}

$scanStatus = 'ok'; $scanReason = ''
try {
    foreach ($root in $ScanRoots) {
        Write-Log ('走査中: {0}' -f $root)
        Invoke-Walk $root
    }
    Write-Log ('走査したファイル: {0} 件（うちアーカイブ {1} 件）' -f $counts.files, $counts.archives)
} catch {
    $scanStatus = 'failed'; $scanReason = $_.Exception.Message
}
if ($ScanRoots.Count -eq 0) { $scanStatus = 'failed'; $scanReason = '走査対象のフォルダがありません' }
Set-Section 'executables' $executables $scanStatus $scanReason
Set-Section 'java_archives' $javaArchives $scanStatus $scanReason
Set-Section 'python_packages' $pythonPackages $scanStatus $scanReason
Set-Section 'node_packages' $nodePackages $scanStatus $scanReason
Set-Section 'dotnet_packages' $dotnetPackages $scanStatus $scanReason

# ---- 個別製品 -----------------------------------------------------------------
$custom = New-Object System.Collections.Generic.List[object]
function Add-Custom([string]$Name, [string]$Status, [string]$Version, [string]$Source, [string]$Reason) {
    $custom.Add([ordered]@{ name = $Name; status = $Status; version = $Version; source = $Source; reason = $Reason })
    Write-Log ('個別製品: {0} -> {1} {2} ({3})' -f $Name, $Status, $Version, $Source)
}
function Get-Match([string]$Text, [string]$Regex) {
    if (-not $Regex) { return '' }
    $m = [regex]::Match($Text, $Regex)
    if ($m.Success) { return $m.Value } else { return '' }
}
foreach ($product in $CustomProducts) {
    $name = $product.Name; $target = $product.Target
    try {
        switch ($product.Type) {
            'fileversion' {
                $files = @(Get-Item -Path $target -ErrorAction SilentlyContinue)
                if ($files.Count -eq 0) { Add-Custom $name 'not_found' '' $target '' }
                foreach ($file in $files) {
                    $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($file.FullName)
                    $version = if ($info.ProductVersion) { $info.ProductVersion } else { $info.FileVersion }
                    Add-Custom $name 'found' ([string]$version) $file.FullName ''
                }
            }
            'filetext' {
                $files = @(Get-Item -Path $target -ErrorAction SilentlyContinue)
                if ($files.Count -eq 0) { Add-Custom $name 'not_found' '' $target '' }
                foreach ($file in $files) {
                    $text = Get-Content -LiteralPath $file.FullName -Raw -ErrorAction Stop
                    Add-Custom $name 'found' (Get-Match $text $product.Regex) $file.FullName ''
                }
            }
            'cmd' {
                $command = ($target -split '\s+')[0].Trim('"')
                if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
                    Add-Custom $name 'not_found' '' $target ''
                } else {
                    $output = (& cmd.exe /c $target 2>&1 | Out-String)
                    Add-Custom $name 'found' (Get-Match $output $product.Regex) $target ''
                }
            }
            'exists' {
                $files = @(Get-Item -Path $target -ErrorAction SilentlyContinue)
                if ($files.Count -eq 0) { Add-Custom $name 'not_found' '' $target '' }
                else { Add-Custom $name 'found' '' $files[0].FullName '' }
            }
            'find' {
                $hit = $null
                foreach ($root in $ScanRoots) {
                    $hit = Get-ChildItem -LiteralPath $root -Filter $target -Recurse -Depth $FindDepth -Force `
                        -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($hit) { break }
                }
                if ($hit) { Add-Custom $name 'found' '' $hit.FullName '' }
                else { Add-Custom $name 'not_found' '' ('名前検索: {0}' -f $target) '' }
            }
            default { Add-Custom $name 'error' '' $target ('種類 {0} は使えません' -f $product.Type) }
        }
    } catch {
        Add-Custom $name 'error' '' $target $_.Exception.Message
    }
}
Set-Section 'custom_products' $custom
Set-Section 'unreadable' $unreadable

# ---- 書き出し -----------------------------------------------------------------
$inventory = [ordered]@{
    schema = 'vuln-triage-inventory/1'
    collector_version = '1'
    host = $hostName
    collected_at = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    run_as_admin = $isAdmin
    os = $os
    scan_roots = @($ScanRoots)
    sections = $sections
    completed = $true
}
$json = $inventory | ConvertTo-Json -Depth 8
$outFile = Join-Path $OutDir 'inventory.json'
[System.IO.File]::WriteAllText($outFile, $json, (New-Object System.Text.UTF8Encoding($false)))
Write-Log ('収集終了: {0}' -f $outFile)
Write-Log ('{0} をフォルダごと回収してください' -f $OutDir)
