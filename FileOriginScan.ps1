<#
.SYNOPSIS
    散落文件归属诊断器：把一个目录里的散落 exe/dll 反查回具体软件。

.DESCRIPTION
    三路证据交叉判定：卸载注册表登记的安装路径、文件版本信息（公司/产品/描述）、数字签名。
    输出控制台结论 + HTML 报告（含归属明细、未归属清单、处理建议）。
    典型用途：盘符根目录、下载目录、临时目录里那堆"说不清是谁装的"文件。

.EXAMPLE
    .\FileOriginScan.ps1 -Path D:\

.EXAMPLE
    .\FileOriginScan.ps1 -Path "$env:USERPROFILE\Downloads" -Recurse

.EXAMPLE
    .\FileOriginScan.ps1 -Path D:\SomeApp -SkipSignature
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Path,

    [switch]$Recurse,
    [switch]$SkipSignature,
    [switch]$ForceSignature,
    [int]$MaxFiles = 5000,
    [string]$OutDir,
    [string]$OutFile,
    [switch]$Quiet
)

$ErrorActionPreference = 'Continue'
$script:ToolVersion = '1.1.0'
$script:ToolName = '散落文件归属诊断器 v' + $script:ToolVersion
$script:ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }

$script:ExecExtensions = @('.exe', '.dll', '.sys', '.ocx', '.cpl', '.scr', '.drv', '.msi', '.com')

# ---------------------------------------------------------------- 基础工具

function Format-Size {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return ('{0:N2} GB' -f ($Bytes / 1GB)) }
    if ($Bytes -ge 1MB) { return ('{0:N2} MB' -f ($Bytes / 1MB)) }
    if ($Bytes -ge 1KB) { return ('{0:N1} KB' -f ($Bytes / 1KB)) }
    return ('{0} B' -f $Bytes)
}

function Normalize-Dir {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return '' }
    $s = $Text.Trim().Trim('"').Trim("'")
    $s = $s -replace '/', '\'
    $s = $s.TrimEnd('\')
    if ($s -match '^[A-Za-z]:$') { $s = $s + '\' }
    return $s.ToLowerInvariant()
}

function Test-PathUnder {
    param([string]$FileDir, [string]$Root)
    if ([string]::IsNullOrWhiteSpace($Root) -or [string]::IsNullOrWhiteSpace($FileDir)) { return $false }
    if ($FileDir -eq $Root) { return $true }
    if ($Root.EndsWith('\')) { return $FileDir.StartsWith($Root) }
    return $FileDir.StartsWith($Root + '\')
}

function Get-SignerSimpleName {
    param([string]$Subject)
    if ([string]::IsNullOrWhiteSpace($Subject)) { return '' }
    $m = [regex]::Match($Subject, 'CN\s*=\s*([^,]+)')
    if ($m.Success) { return $m.Groups[1].Value.Trim() }
    return $Subject
}

function Get-SignatureSafe {
    param([string]$LiteralPath)
    try {
        if ((Get-Command Get-AuthenticodeSignature).Parameters.ContainsKey('LiteralPath')) {
            return Get-AuthenticodeSignature -LiteralPath $LiteralPath -ErrorAction SilentlyContinue
        }
        return Get-AuthenticodeSignature -FilePath $LiteralPath -ErrorAction SilentlyContinue
    } catch {
        return $null
    }
}

function Get-PeArchitecture {
    param([string]$LiteralPath)
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($LiteralPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
        if ($stream.Length -lt 0x40) { return '' }
        $reader = New-Object System.IO.BinaryReader($stream)
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -le 0 -or ($peOffset + 6) -gt $stream.Length) { return '' }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) { return '' }
        switch ($reader.ReadUInt16()) {
            0x014c  { return 'x86' }
            0x8664  { return 'x64' }
            0xAA64  { return 'ARM64' }
            0x01c4  { return 'ARM' }
            0x0200  { return 'IA64' }
            default { return ('PE-0x{0:X4}' -f $_.ToString()) }
        }
    } catch {
        return ''
    } finally {
        if ($stream) { $stream.Dispose() }
    }
}

function Encode-Html {
    param([string]$Text)
    if ($null -eq $Text) { return '' }
    try { return [System.Net.WebUtility]::HtmlEncode([string]$Text) }
    catch { return ([string]$Text) -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;' }
}

function Write-Head {
    param([string]$Title)
    if ($Quiet) { return }
    Write-Host ''
    Write-Host ('─' * 72) -ForegroundColor DarkGray
    Write-Host ("  $Title") -ForegroundColor Cyan
    Write-Host ('─' * 72) -ForegroundColor DarkGray
}

# ---------------------------------------------------------------- 已知组件库

$script:StopTokens = @(
    'inc', 'llc', 'ltd', 'co', 'corp', 'corporation', 'company', 'limited', 'gmbh', 'sa', 'srl',
    'bv', 'ab', 'as', 'oy', 'pte', 'software', 'technologies', 'technology', 'systems', 'system',
    'solutions', 'group', 'international', 'the', 'and', 'of', 'team', 'project', 'foundation',
    'community', 'products', 'product', 'labs', 'studio', 'studios', 'apps', 'application', 'applications'
)

$script:KnownComponents = @(
    @{ Pattern = '^(vcruntime|msvcp|msvcr|concrt|vccorlib)\d+(_\d+)?\.dll$'; Label = 'Microsoft Visual C++ 运行库（随 VC++ Redistributable 安装）' },
    @{ Pattern = '^mfc\d+u?\.dll$';                                        Label = 'Microsoft MFC 运行库（随 VC++ Redistributable 安装）' },
    @{ Pattern = '^ucrtbase\.dll$';                                        Label = 'Windows 通用 C 运行时 UCRT（系统组件）' },
    @{ Pattern = '^api-ms-win-.*\.dll$';                                   Label = 'Windows API 转发库（系统组件）' },
    @{ Pattern = '^dnssd\.dll$';                                           Label = 'Bonjour / DNS-SD 服务组件（Apple 软件自带）' },
    @{ Pattern = '^mdnsresponder.*\.dll$';                                 Label = 'Bonjour / DNS-SD 服务组件（Apple 软件自带）' },
    @{ Pattern = '^webkit\.dll$';                                          Label = 'Apple WebKit 渲染引擎（Apple 应用自带）' },
    @{ Pattern = '^(javascriptcore|wtf|cfnetwork|corefoundation|coregraphics|coretext|quartzcore|objc|libdispatch|coreaudio|coremedia|corevideo|avfoundationcf|mediaaccessibility|coredav|coresvga|coresvgadx|coreadi.*|corefp|corelskd)\.dll$'; Label = 'Apple 底层框架库（Apple 应用自带）' },
    @{ Pattern = '^libicu.*\.dll$';                                        Label = 'ICU 国际化组件（第三方通用库）' },
    @{ Pattern = '^icudt.*\.dll$';                                         Label = 'ICU 语言数据文件（第三方通用库）' },
    @{ Pattern = '^sqlite3?\.dll$';                                        Label = 'SQLite 数据库引擎（第三方通用库）' },
    @{ Pattern = '^zlib1?\.dll$';                                          Label = 'zlib 压缩库（第三方通用库）' },
    @{ Pattern = '^libxml2.*\.dll$';                                       Label = 'libxml2 解析库（第三方通用库）' },
    @{ Pattern = '^libxslt.*\.dll$';                                       Label = 'libxslt 转换库（第三方通用库）' },
    @{ Pattern = '^libtidy.*\.dll$';                                       Label = 'Tidy HTML 清理库（第三方通用库）' },
    @{ Pattern = '^pthreadvc2\.dll$';                                      Label = 'pthreads-win32 线程库（第三方通用库）' },
    @{ Pattern = '^libcurl.*\.dll$';                                       Label = 'libcurl 网络传输库（第三方通用库）' },
    @{ Pattern = '^gnsdk_.*\.dll$';                                        Label = 'Gracenote 媒体识别库（音乐类软件自带）' },
    @{ Pattern = '^(openal32|wrap_oal|eax|dsound)\.dll$';                  Label = '音频输出组件（第三方通用库）' },
    @{ Pattern = '^(d3dx9_\d+|d3dcompiler_\d+|xinput\d+_\d+)\.dll$';       Label = 'DirectX 运行库（游戏/多媒体软件依赖）' },
    @{ Pattern = '^(msvcp|vcruntime)\d+_1\.dll$';                          Label = 'Microsoft Visual C++ 运行库（随 VC++ Redistributable 安装）' }
)

$script:SystemFiles = @{
    'pagefile.sys'        = 'Windows 虚拟内存分页文件'
    'swapfile.sys'        = 'Windows 应用交换文件'
    'hiberfil.sys'        = 'Windows 休眠文件'
    'dumpstack.log.tmp'   = 'Windows 转储堆栈日志'
    'bootmgr'             = 'Windows 启动管理器文件'
    'bootnxt'             = 'Windows 启动配置数据'
}

# ---------------------------------------------------------------- 读取已装软件

function Get-InstalledApp {
    $roots = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $seen = @{}
    $list = New-Object System.Collections.Generic.List[object]

    foreach ($root in $roots) {
        $entries = @()
        try { $entries = @(Get-ItemProperty -Path $root -ErrorAction SilentlyContinue) } catch { $entries = @() }
        foreach ($e in $entries) {
            try {
                $name = $e.DisplayName
                if ([string]::IsNullOrWhiteSpace($name)) { continue }

                $publisher = [string]$e.Publisher
                $installRaw = [string]$e.InstallLocation
                $version = [string]$e.DisplayVersion

                $key = ($name + '|' + $version + '|' + $installRaw).ToLowerInvariant()
                if ($seen.ContainsKey($key)) { continue }
                $seen[$key] = $true

                $instDir = Normalize-Dir $installRaw
                $pubTokens = @(Get-TokenList $publisher)

                $isRootInstall = $false
                if ($instDir -match '^[a-z]:\\$') { $isRootInstall = $true }

                $list.Add([pscustomobject]@{
                    Name            = [string]$name
                    Version         = $version
                    Publisher       = $publisher
                    InstallLocation = $installRaw
                    InstallDir      = $instDir
                    IsRootInstall   = $isRootInstall
                    NameTokens      = @(Get-TokenList $name)
                    PubTokens       = $pubTokens
                    Uninstall       = [string]$e.UninstallString
                    Hive            = $root
                })
            } catch { }
        }
    }
    return $list
}

function Get-TokenList {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return @() }
    $parts = [regex]::Split($Text.ToLowerInvariant(), '[^a-z0-9\u4e00-\u9fa5]+')
    $result = @()
    foreach ($p in $parts) {
        if ($p.Length -lt 3) { continue }
        if ($script:StopTokens -contains $p) { continue }
        if ($result -notcontains $p) { $result += $p }
    }
    return $result
}

function Test-NameContains {
    param([string]$Haystack, [string]$Needle)
    if ([string]::IsNullOrWhiteSpace($Haystack) -or [string]::IsNullOrWhiteSpace($Needle)) { return $false }
    if ($Needle.Length -lt 4) { return $false }
    return $Haystack.ToLowerInvariant().Contains($Needle.ToLowerInvariant())
}

function Get-KnownComponent {
    param([string]$FileName)
    if ([string]::IsNullOrWhiteSpace($FileName)) { return '' }
    $lower = $FileName.ToLowerInvariant()
    foreach ($k in $script:KnownComponents) {
        if ($lower -match $k.Pattern) { return $k.Label }
    }
    return ''
}

# ---------------------------------------------------------------- 归属判定

function Get-Attribution {
    param($File, $Apps)

    if ($script:SystemFiles.ContainsKey($File.Name.ToLowerInvariant())) {
        return [pscustomobject]@{
            Product    = $script:SystemFiles[$File.Name.ToLowerInvariant()]
            Confidence = '高'
            Reason     = 'Windows 保留文件，不属于任何可卸载软件，禁止删除'
            Kind       = 'System'
        }
    }

    $bestScore = 0
    $bestApp = $null
    $bestReasons = @()
    $candidateApps = New-Object System.Collections.Generic.List[string]

    foreach ($app in $Apps) {
        $score = 0
        $reasons = New-Object System.Collections.Generic.List[string]

        if ($app.InstallDir -and (Test-PathUnder -FileDir $File.Dir -Root $app.InstallDir)) {
            $score += 100
            if ($app.IsRootInstall) {
                $reasons.Add("文件所在目录就是该软件登记的安装目录（安装位置被设成了盘符根目录 " + $app.InstallLocation + "）")
            } else {
                $reasons.Add("文件位于该软件登记的安装目录 " + $app.InstallLocation)
            }
        }

        foreach ($text in @($File.ProductName, $File.Description, $File.OriginalName)) {
            if ([string]::IsNullOrWhiteSpace($text)) { continue }
            if (Test-NameContains -Haystack $text -Needle $app.Name) {
                $score += 45
                $reasons.Add("文件的产品信息「" + $text + "」与该软件名称一致")
                break
            }
        }

        if ($File.Company -and $app.PubTokens.Count -gt 0) {
            $ft = @(Get-TokenList $File.Company)
            $overlap = @($ft | Where-Object { $app.PubTokens -contains $_ })
            if ($overlap.Count -gt 0) {
                $score += 25
                $reasons.Add("文件公司名「" + $File.Company + "」与发布者「" + $app.Publisher + "」同源")
            }
        }

        if ($File.SignerName -and $app.PubTokens.Count -gt 0) {
            $st = @(Get-TokenList $File.SignerName)
            $overlap = @($st | Where-Object { $app.PubTokens -contains $_ })
            if ($overlap.Count -gt 0) {
                $score += 20
                $reasons.Add("数字签名者「" + $File.SignerName + "」与发布者一致")
            }
        }

        if ($File.Description -and $app.NameTokens.Count -gt 0) {
            $dt = @(Get-TokenList $File.Description)
            $overlap = @($dt | Where-Object { $app.NameTokens -contains $_ })
            if ($overlap.Count -gt 0) {
                $score += 12
                $reasons.Add("文件描述「" + $File.Description + "」与该软件名称关键词重合")
            }
        }

        if ($score -gt 0) {
            if ($score -gt $bestScore) {
                $bestScore = $score
                $bestApp = $app
                $bestReasons = @($reasons)
                $candidateApps = New-Object System.Collections.Generic.List[string]
                $candidateApps.Add($app.Name)
            } elseif ($score -eq $bestScore -and $bestApp) {
                if ($candidateApps.Count -lt 4 -and -not $candidateApps.Contains($app.Name)) {
                    $candidateApps.Add($app.Name)
                }
            }
        }
    }

    $component = Get-KnownComponent -FileName $File.Name
    $reasonText = if ($bestReasons.Count -gt 0) { ($bestReasons -join '；') } else { '' }

    if ($bestApp -and $bestScore -ge 100) {
        return [pscustomobject]@{
            Product    = $bestApp.Name
            Confidence = '高'
            Reason     = $reasonText
            Kind       = 'App'
        }
    }

    if ($bestApp -and $bestScore -ge 45) {
        return [pscustomobject]@{
            Product    = $bestApp.Name
            Confidence = '中'
            Reason     = $reasonText
            Kind       = 'App'
        }
    }

    if ($component) {
        $extra = ''
        if ($bestApp) { $extra = '；最接近的候选软件：' + $bestApp.Name }
        return [pscustomobject]@{
            Product    = $component
            Confidence = '参考'
            Reason     = '文件名命中已知公共组件库' + $extra
            Kind       = 'Component'
        }
    }

    if ($bestApp -and $bestScore -ge 20) {
        $nameText = $bestApp.Name
        if ($candidateApps.Count -gt 1) { $nameText = ($candidateApps -join ' / ') + '（同厂商，需进一步确认）' }
        return [pscustomobject]@{
            Product    = $nameText
            Confidence = '低'
            Reason     = $reasonText
            Kind       = 'Vendor'
        }
    }

    $isExecutable = $script:ExecExtensions -contains $File.Ext
    $noVersionInfo = ([string]::IsNullOrWhiteSpace($File.Company) -and [string]::IsNullOrWhiteSpace($File.ProductName) -and [string]::IsNullOrWhiteSpace($File.Description) -and [string]::IsNullOrWhiteSpace($File.FileVersion))
    if ($isExecutable -and $noVersionInfo -and [string]::IsNullOrWhiteSpace($File.SignerName)) {
        return [pscustomobject]@{
            Product    = '来源不明（无版本信息、无数字签名）'
            Confidence = ''
            Reason     = '可执行文件，但既无版本信息也无数字签名，且未匹配到任何已安装软件；可能是便携程序文件、自编译程序，或卸载残留'
            Kind       = 'Suspicious'
        }
    }

    return [pscustomobject]@{
        Product    = '未识别'
        Confidence = ''
        Reason     = '版本信息与签名均无法匹配到已安装软件'
        Kind       = 'Unknown'
    }
}

# ---------------------------------------------------------------- 主流程

if ([string]::IsNullOrWhiteSpace($Path)) {
    $Path = Read-Host '请输入要扫描的目录（例如 D:\ 或 C:\Users\Public\Downloads）'
}
if ([string]::IsNullOrWhiteSpace($Path)) {
    Write-Host '未提供目录，已退出。' -ForegroundColor Red
    return
}

try {
    $targetItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if (-not $targetItem.PSIsContainer) { throw '目标不是目录' }
    $target = $targetItem.FullName
} catch {
    Write-Host ('无法访问目录：' + $Path + ' — ' + $_.Exception.Message) -ForegroundColor Red
    return
}

Write-Host ''
Write-Host ('  ' + $script:ToolName) -ForegroundColor White
Write-Host ('  扫描目录：' + $target) -ForegroundColor Gray

$enumArgs = @{ LiteralPath = $target; File = $true; Force = $true; ErrorAction = 'SilentlyContinue' }
if ($Recurse) { $enumArgs['Recurse'] = $true }
$allFiles = @(Get-ChildItem @enumArgs)
$truncated = $false
if ($allFiles.Count -gt $MaxFiles) {
    $truncated = $true
    $allFiles = @($allFiles | Select-Object -First $MaxFiles)
}

$useSignature = (-not $SkipSignature) -and ($allFiles.Count -le 500 -or $ForceSignature)

Write-Host ('  文件数量：' + $allFiles.Count + '    读取签名：' + $(if ($useSignature) { '是' } else { '否（文件过多或已手动跳过）' })) -ForegroundColor Gray

$apps = Get-InstalledApp
Write-Host ('  已安装软件记录：' + $apps.Count + ' 条') -ForegroundColor Gray

# ---- 逐个文件取证
$records = New-Object System.Collections.Generic.List[object]
$index = 0
foreach ($f in $allFiles) {
    $index++
    if (-not $Quiet -and $allFiles.Count -gt 30) {
        Write-Progress -Activity '读取文件信息' -Status ($index.ToString() + ' / ' + $allFiles.Count + '  ' + $f.Name) -PercentComplete ([int](($index / $allFiles.Count) * 100))
    }

    $company = ''; $productName = ''; $description = ''; $originalName = ''; $fileVersion = ''
    try {
        $vi = $f.VersionInfo
        if ($vi) {
            $company = [string]$vi.CompanyName
            $productName = [string]$vi.ProductName
            $description = [string]$vi.FileDescription
            $originalName = [string]$vi.OriginalFilename
            $fileVersion = [string]$vi.FileVersion
        }
    } catch { }

    $signerName = ''; $signerSubject = ''; $sigStatus = ''
    if ($useSignature) {
        $sig = Get-SignatureSafe -LiteralPath $f.FullName
        if ($sig) {
            $sigStatus = [string]$sig.Status
            if ($sig.SignerCertificate) {
                $signerSubject = [string]$sig.SignerCertificate.Subject
                $signerName = Get-SignerSimpleName -Subject $signerSubject
            }
        }
    }

    $arch = ''
    if ($script:ExecExtensions -contains $f.Extension.ToLowerInvariant()) {
        $arch = Get-PeArchitecture -LiteralPath $f.FullName
    }

    $record = [pscustomobject]@{
        Name         = $f.Name
        Dir          = (Normalize-Dir $f.DirectoryName)
        FullName     = $f.FullName
        Ext          = $f.Extension.ToLowerInvariant()
        Size         = [long]$f.Length
        Modified     = $f.LastWriteTime
        Attributes   = [string]$f.Attributes
        Company      = $company
        ProductName  = $productName
        Description  = $description
        OriginalName = $originalName
        FileVersion  = $fileVersion
        SignerName   = $signerName
        SignerSubject = $signerSubject
        SigStatus    = $sigStatus
        Arch         = $arch
        IsSigned     = [bool]($signerName -ne '')
    }

    $attribution = Get-Attribution -File $record -Apps $apps
    $record | Add-Member -NotePropertyName Product -NotePropertyValue $attribution.Product -Force
    $record | Add-Member -NotePropertyName Confidence -NotePropertyValue $attribution.Confidence -Force
    $record | Add-Member -NotePropertyName Reason -NotePropertyValue $attribution.Reason -Force
    $record | Add-Member -NotePropertyName Kind -NotePropertyValue $attribution.Kind -Force

    $records.Add($record)
}
Write-Progress -Activity '读取文件信息' -Completed

# ---- 汇总
$totalSize = ($records | Measure-Object -Property Size -Sum).Sum
if (-not $totalSize) { $totalSize = 0 }

$unmatched = @($records | Where-Object { $_.Kind -eq 'Unknown' })
$suspicious = @($records | Where-Object { $_.Kind -eq 'Suspicious' })
$attributed = @($records | Where-Object { $_.Kind -ne 'Unknown' -and $_.Kind -ne 'Suspicious' })

$unsigned = @()
if ($useSignature) {
    $unsigned = @($records | Where-Object { (-not $_.IsSigned) -and ($script:ExecExtensions -contains $_.Ext) -and $_.Kind -ne 'System' })
}

$archGroups = @()
if ($records.Count -gt 0) {
    $archGroups = @($records | Where-Object { $_.Arch } | Group-Object Arch | Sort-Object Count -Descending | ForEach-Object { [pscustomobject]@{ Arch = $_.Name; Count = $_.Count } })
}

$groups = @()
if ($records.Count -gt 0) {
    $groups = @(
        $records | Group-Object -Property Product | ForEach-Object {
            $g = $_.Group
            $size = ($g | Measure-Object -Property Size -Sum).Sum
            if (-not $size) { $size = 0 }
            $conf = ($g | Group-Object Confidence | Sort-Object Count -Descending | Select-Object -First 1).Name
            [pscustomobject]@{
                Product    = $_.Name
                Count      = $g.Count
                Size       = [long]$size
                Confidence = $conf
                Extensions = (($g | Group-Object Ext | Sort-Object Count -Descending | Select-Object -First 4 | ForEach-Object { if ($_.Name) { $_.Name } else { '(无扩展名)' } }) -join ' ')
                Sample     = (($g | Select-Object -First 3 | ForEach-Object { $_.Name }) -join '、')
                Reason     = ($g | Group-Object Reason | Sort-Object Count -Descending | Select-Object -First 1).Name
            }
        } | Sort-Object -Property @{ Expression = { switch ($_.Confidence) { '高' { 0 } '中' { 1 } '低' { 2 } '参考' { 3 } default { 4 } } } }, @{ Expression = 'Count'; Descending = $true }
    )
}

# ---- 结论
$normalizedTarget = Normalize-Dir $target
$driveRoot = [System.IO.Path]::GetPathRoot($target)
$isDriveRoot = ($normalizedTarget -eq (Normalize-Dir $driveRoot))

$conclusions = New-Object System.Collections.Generic.List[string]
$actions = New-Object System.Collections.Generic.List[string]
$systemFileCount = @($attributed | Where-Object { $_.Kind -eq 'System' }).Count

if ($isDriveRoot) {
    $conclusions.Add('扫描目录 ' + $target + ' 是盘符根目录。根目录不属于任何软件的常规安装位置，出现在这里的文件通常是三类：程序被直接装到了盘符根目录、便携程序被解压到根目录、用户手动放进来的文件。')
}

$rootInstalled = @($apps | Where-Object { $_.IsRootInstall -and $_.InstallDir -eq $normalizedTarget })
if ($rootInstalled.Count -gt 0) {
    $names = ($rootInstalled | ForEach-Object { $_.Name + ' ' + $_.Version }) -join '、'
    $conclusions.Add('注册表中有 ' + $rootInstalled.Count + ' 个已安装程序把安装目录登记为 ' + $target + ' 根目录：' + $names + '。本目录中被归属到这些软件的文件就是它们的程序本体，删除或移动会直接破坏这些软件。')
}

$highConf = @($attributed | Where-Object { $_.Confidence -eq '高' -and $_.Kind -eq 'App' })
if ($highConf.Count -gt 0) {
    $conclusions.Add('有 ' + $highConf.Count + ' 个文件可通过安装路径直接确认归属（高置信度），它们属于正在使用的软件目录内容。')
}

if ($attributed.Count -gt 0) {
    $productCount = @($attributed | Group-Object Product).Count
    $summary = '共 ' + $records.Count + ' 个文件，其中 ' + $attributed.Count + ' 个可归属到 ' + $productCount + ' 个来源，' + $unmatched.Count + ' 个未能自动识别'
    if ($suspicious.Count -gt 0) { $summary = $summary + '，' + $suspicious.Count + ' 个来源不明' }
    $conclusions.Add($summary + '。')
} elseif ($records.Count -gt 0) {
    $conclusions.Add('共 ' + $records.Count + ' 个文件，均未能匹配到已安装软件，更可能是个人文件、便携程序文件或系统文件。')
} else {
    $conclusions.Add('该目录当前没有文件，无需处理。')
}

if ($suspicious.Count -gt 0) {
    $conclusions.Add('有 ' + $suspicious.Count + ' 个可执行文件既没有版本信息、也没有数字签名，无法反推来源；它们可能是便携程序的组成文件，也可能是软件卸载后留下的残留。')
}

if ($unmatched.Count -gt 0) {
    $conclusions.Add('未归属的 ' + $unmatched.Count + ' 个文件需要人工确认后再处理，不要批量删除。')
}

if ($unsigned.Count -gt 0) {
    $conclusions.Add('签名校验发现 ' + $unsigned.Count + ' 个可执行文件没有有效数字签名，无法从签名信息判断来源。')
}

if ($isDriveRoot -and $records.Count -gt 0 -and $unmatched.Count -eq 0 -and $attributed.Count -eq $systemFileCount) {
    $conclusions.Add('除上述 Windows 系统保留文件外，该盘符根目录没有其他散落文件，属于正常状态。')
}

if ($truncated) {
    $conclusions.Add('文件数量超过上限 ' + $MaxFiles + '，本次只分析了前 ' + $MaxFiles + ' 个文件；如需全量分析请用 -MaxFiles 提高上限。')
}

if ($records.Count -eq 0) {
    $actions.Add('该目录没有文件，本次扫描未发现需要处理的散落文件。')
}
if ($records.Count -gt 0) {
    $actions.Add('先不要批量删除。已归属的文件属于正在使用的软件，删除或移动会造成程序损坏或启动失败。')
}
if ($rootInstalled.Count -gt 0) {
    $drive = $driveRoot.TrimEnd('\')
    $actions.Add('正确做法：卸载这些程序（设置 → 应用 → 已安装的应用），重装时把安装路径填成显式子目录（例如 ' + $drive + '\iTunes），不要只填 ' + $drive + '\ 这个盘符本身。重装完成后，根目录里的这些文件会随之消失。')
}
if ($systemFileCount -gt 0) {
    $actions.Add('检测到 ' + $systemFileCount + ' 个 Windows 系统保留文件（pagefile.sys、hiberfil.sys、swapfile.sys 等）。它们不属于任何可卸载软件，删除会影响系统稳定性；需要调整时走系统设置：分页文件在「系统属性 → 高级 → 性能 → 虚拟内存」中修改，休眠文件用管理员 PowerShell 执行 powercfg /h off 关闭。')
}
$componentCount = @($attributed | Where-Object { $_.Kind -eq 'Component' }).Count
if ($componentCount -gt 0) {
    $actions.Add('常见的运行库组件（VC++ 运行库、Bonjour、WebKit、ICU/SQLite 等）不要单独删除，它们由所属软件管理，会随软件卸载一起清理。')
}
if ($unmatched.Count -gt 0) {
    $actions.Add('未归属文件逐个核对来源：右键 → 属性 → 详细信息（看"公司/产品名称"）与"数字签名"标签页，或在 PowerShell 里执行 Get-AuthenticodeSignature ''路径'' 查看签名者。')
    $personalExt = @($unmatched | Where-Object { @('.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.jpg', '.jpeg', '.png', '.mp4', '.mp3', '.zip', '.rar', '.7z', '.iso') -contains $_.Ext })
    if ($personalExt.Count -gt 0) {
        $actions.Add('其中有 ' + $personalExt.Count + ' 个文档/媒体/压缩包类文件，属于个人文件的可能性更大，建议归档到 ' + $driveRoot.TrimEnd('\') + '\个人资料\<分类> 这样的独立目录，而不是留在根目录。')
    }
}
if ($suspicious.Count -gt 0) {
    $actions.Add('对来源不明的可执行文件，先记录指纹再决定：Get-FileHash ''路径'' -Algorithm SHA256 存档，必要时送到 VirusTotal 一类服务核对；它们也可能是某个便携程序的组成文件，删除前请确认对应程序还能正常启动。')
}
if ($unsigned.Count -gt 0) {
    $actions.Add('未签名的可执行文件本身不等于有问题（很多开源软件与自编译程序都不签名），但在盘符根目录、下载目录这类位置出现时，值得优先排查来源。')
}
if ($useSignature -eq $false -and $allFiles.Count -gt 0) {
    $actions.Add('本次未做数字签名校验（文件过多或使用了 -SkipSignature）。需要更精确的判定时，可加 -ForceSignature 重跑。')
}

# ---- 控制台输出
if (-not $Quiet) {
    Write-Head '概览'
    Write-Host ('  文件总数    : ' + $records.Count)
    Write-Host ('  占用空间    : ' + (Format-Size -Bytes $totalSize))
    Write-Host ('  已归属      : ' + $attributed.Count)
    Write-Host ('  未归属      : ' + $unmatched.Count)
    Write-Host ('  来源不明    : ' + $suspicious.Count)
    if ($useSignature) { Write-Host ('  未签名      : ' + $unsigned.Count) }
    $sourceCount = 0
    if ($attributed.Count -gt 0) { $sourceCount = @($attributed | Group-Object Product).Count }
    Write-Host ('  来源数量    : ' + $sourceCount)
    if ($archGroups.Count -gt 0) {
        Write-Host ('  架构分布    : ' + (($archGroups | ForEach-Object { $_.Arch + ' ' + $_.Count }) -join ' / '))
    }

    Write-Head '结论'
    if ($conclusions.Count -eq 0) { Write-Host '  无可报告的结论。' } else {
        $n = 0
        foreach ($c in $conclusions) { $n++; Write-Host ('  ' + $n + '. ' + $c) }
    }

    if ($groups.Count -gt 0) {
        Write-Head '归属明细'
        $groups | Select-Object @{n = '来源'; e = { $_.Product } }, @{n = '文件数'; e = { $_.Count } }, @{n = '大小'; e = { Format-Size -Bytes $_.Size } }, @{n = '置信度'; e = { $_.Confidence } }, @{n = '代表文件'; e = { $_.Sample } } | Format-Table -AutoSize | Out-String -Width 200 | Write-Host
    }

    Write-Head '建议动作'
    $n = 0
    foreach ($a in $actions) { $n++; Write-Host ('  ' + $n + '. ' + $a) }
}

# ---- 报告输出
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = Join-Path $script:ScriptDir 'reports' }
if (-not (Test-Path -LiteralPath $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

$slug = ($target -replace '[\\/:*?"<>|]', '_').Trim('_')
if ([string]::IsNullOrWhiteSpace($slug)) { $slug = 'scan' }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

if ([string]::IsNullOrWhiteSpace($OutFile)) {
    $htmlPath = Join-Path $OutDir ('文件归属报告_' + $slug + '_' + $stamp + '.html')
} else {
    $htmlPath = $OutFile
}

$css = @'
:root { --ink:#1b1f24; --muted:#5b6672; --line:#dfe4ea; --bg:#f6f7f9; --accent:#1a5fb4; --warn:#b4600a; --danger:#b3261e; --ok:#1a7f4b; }
* { box-sizing:border-box; }
body { margin:0; padding:32px 28px 56px; background:var(--bg); color:var(--ink); font:14px/1.65 "Microsoft YaHei UI","Segoe UI",system-ui,sans-serif; }
main { max-width:1180px; margin:0 auto; }
h1 { font-size:24px; margin:0 0 6px; }
h2 { font-size:16px; margin:34px 0 10px; padding-bottom:6px; border-bottom:1px solid var(--line); }
.sub { color:var(--muted); font-size:13px; margin:0 0 4px; }
.path { font-family:Consolas,"Cascadia Mono",monospace; color:var(--ink); }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin-top:14px; }
.stat { background:#fff; border:1px solid var(--line); border-radius:6px; padding:12px 14px; }
.stat .k { color:var(--muted); font-size:12px; }
.stat .v { font-size:20px; font-weight:600; margin-top:2px; }
.stat.warn .v { color:var(--warn); }
.stat.danger .v { color:var(--danger); }
.stat.ok .v { color:var(--ok); }
ol, ul { padding-left:22px; margin:8px 0; }
li { margin:5px 0; }
table { width:100%; border-collapse:collapse; background:#fff; border:1px solid var(--line); border-radius:6px; overflow:hidden; margin-top:8px; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th.num { text-align:right; }
th { background:#eef1f5; font-weight:600; font-size:12.5px; color:#39424d; white-space:nowrap; }
tr:last-child td { border-bottom:none; }
td.num { text-align:right; white-space:nowrap; font-variant-numeric:tabular-nums; }
td.mono, .mono { font-family:Consolas,"Cascadia Mono",monospace; font-size:12.5px; }
.tag { display:inline-block; padding:1px 7px; border-radius:10px; font-size:12px; border:1px solid var(--line); background:#f2f4f7; color:#39424d; white-space:nowrap; }
.tag.high { background:#e7f4ec; border-color:#bfe0cb; color:#1a7f4b; }
.tag.mid  { background:#eaf1fb; border-color:#c6d9f4; color:#1a5fb4; }
.tag.low  { background:#fdf3e3; border-color:#f0dcbc; color:#8a5a10; }
.tag.ref  { background:#f2f0fa; border-color:#d8d2ee; color:#5145a5; }
.tag.none { background:#f3f4f6; border-color:#e2e5e9; color:#6b7280; }
.note { background:#fff; border:1px solid var(--line); border-left:3px solid var(--accent); border-radius:4px; padding:12px 14px; color:#2c333b; }
.reason { color:var(--muted); font-size:12.5px; }
footer { margin-top:40px; padding-top:14px; border-top:1px solid var(--line); color:var(--muted); font-size:12.5px; }
'@

function Get-ConfClass {
    param([string]$Confidence)
    switch ($Confidence) {
        '高' { return 'high' }
        '中' { return 'mid' }
        '低' { return 'low' }
        '参考' { return 'ref' }
        default { return 'none' }
    }
}

$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine('<!DOCTYPE html>')
[void]$sb.AppendLine('<html lang="zh-CN"><head><meta charset="utf-8">')
[void]$sb.AppendLine('<meta name="viewport" content="width=device-width, initial-scale=1">')
[void]$sb.AppendLine('<title>文件归属报告 - ' + (Encode-Html $target) + '</title>')
[void]$sb.AppendLine('<style>' + $css + '</style></head><body><main>')

[void]$sb.AppendLine('<h1>散落文件归属报告</h1>')
[void]$sb.AppendLine('<p class="sub">扫描目录：<span class="path">' + (Encode-Html $target) + '</span>' + $(if ($Recurse) { ' （含子目录）' } else { ' （仅当前层）' }) + '</p>')
[void]$sb.AppendLine('<p class="sub">扫描时间：' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss') + '　|　工具：' + (Encode-Html $script:ToolName) + '</p>')

[void]$sb.AppendLine('<h2>概览</h2><div class="stats">')
[void]$sb.AppendLine('<div class="stat"><div class="k">文件总数</div><div class="v">' + $records.Count + '</div></div>')
[void]$sb.AppendLine('<div class="stat"><div class="k">占用空间</div><div class="v">' + (Format-Size -Bytes $totalSize) + '</div></div>')
[void]$sb.AppendLine('<div class="stat ok"><div class="k">已归属</div><div class="v">' + $attributed.Count + '</div></div>')
[void]$sb.AppendLine('<div class="stat warn"><div class="k">未归属</div><div class="v">' + $unmatched.Count + '</div></div>')
$suspClass = 'stat'
if ($suspicious.Count -gt 0) { $suspClass = 'stat danger' }
[void]$sb.AppendLine('<div class="' + $suspClass + '"><div class="k">来源不明</div><div class="v">' + $suspicious.Count + '</div></div>')
if ($useSignature) {
    $unsignedClass = 'stat ok'
    if ($unsigned.Count -gt 0) { $unsignedClass = 'stat warn' }
    [void]$sb.AppendLine('<div class="' + $unsignedClass + '"><div class="k">未签名可执行文件</div><div class="v">' + $unsigned.Count + '</div></div>')
}
[void]$sb.AppendLine('<div class="stat"><div class="k">已装软件记录</div><div class="v">' + $apps.Count + '</div></div>')
[void]$sb.AppendLine('</div>')

[void]$sb.AppendLine('<h2>结论</h2><ol>')
if ($conclusions.Count -eq 0) { [void]$sb.AppendLine('<li>无可报告的结论。</li>') }
foreach ($c in $conclusions) { [void]$sb.AppendLine('<li>' + (Encode-Html $c) + '</li>') }
[void]$sb.AppendLine('</ol>')

[void]$sb.AppendLine('<h2>归属明细</h2>')
if ($groups.Count -eq 0) {
    [void]$sb.AppendLine('<p class="note">该目录下没有文件。</p>')
} else {
    [void]$sb.AppendLine('<table><thead><tr><th>来源</th><th class="num">文件数</th><th class="num">大小</th><th>置信度</th><th>扩展名</th><th>判定依据</th></tr></thead><tbody>')
    foreach ($g in $groups) {
        $gConf = $g.Confidence
        if ([string]::IsNullOrWhiteSpace($gConf)) { $gConf = '-' }
        [void]$sb.AppendLine('<tr>')
        [void]$sb.AppendLine('<td>' + (Encode-Html $g.Product) + '</td>')
        [void]$sb.AppendLine('<td class="num">' + $g.Count + '</td>')
        [void]$sb.AppendLine('<td class="num">' + (Format-Size -Bytes $g.Size) + '</td>')
        [void]$sb.AppendLine('<td><span class="tag ' + (Get-ConfClass $g.Confidence) + '">' + (Encode-Html $gConf) + '</span></td>')
        [void]$sb.AppendLine('<td class="mono">' + (Encode-Html $g.Extensions) + '</td>')
        [void]$sb.AppendLine('<td class="reason">' + (Encode-Html $g.Reason) + '</td>')
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
}

[void]$sb.AppendLine('<h2>文件清单</h2>')
if ($records.Count -eq 0) {
    [void]$sb.AppendLine('<p class="note">该目录下没有文件。</p>')
} else {
    [void]$sb.AppendLine('<table><thead><tr><th>文件名</th><th class="num">大小</th><th>归属</th><th>置信度</th><th>架构</th><th>公司 / 产品</th><th>数字签名</th><th class="num">修改时间</th></tr></thead><tbody>')
    foreach ($r in ($records | Sort-Object -Property @{ Expression = 'Kind' }, Name)) {
        $companyText = $r.Company
        if ($r.ProductName) {
            if ($companyText) { $companyText = $companyText + ' / ' + $r.ProductName } else { $companyText = $r.ProductName }
        }
        $rConf = $r.Confidence
        if ([string]::IsNullOrWhiteSpace($rConf)) { $rConf = '-' }
        $sigText = '-'
        if ($r.SignerName) {
            $sigText = $r.SignerName
            if ($r.SigStatus -and $r.SigStatus -ne 'Valid') { $sigText = $sigText + '（' + $r.SigStatus + '）' }
        } elseif ($r.SigStatus) {
            $sigText = '未签名（' + $r.SigStatus + '）'
        }
        $archText = $r.Arch
        if ([string]::IsNullOrWhiteSpace($archText)) { $archText = '-' }
        [void]$sb.AppendLine('<tr>')
        [void]$sb.AppendLine('<td class="mono">' + (Encode-Html $r.Name) + '</td>')
        [void]$sb.AppendLine('<td class="num">' + (Format-Size -Bytes $r.Size) + '</td>')
        [void]$sb.AppendLine('<td>' + (Encode-Html $r.Product) + '</td>')
        [void]$sb.AppendLine('<td><span class="tag ' + (Get-ConfClass $r.Confidence) + '">' + (Encode-Html $rConf) + '</span></td>')
        [void]$sb.AppendLine('<td class="mono">' + (Encode-Html $archText) + '</td>')
        [void]$sb.AppendLine('<td class="reason">' + (Encode-Html $companyText) + '</td>')
        [void]$sb.AppendLine('<td class="reason">' + (Encode-Html $sigText) + '</td>')
        [void]$sb.AppendLine('<td class="num">' + $r.Modified.ToString('yyyy-MM-dd HH:mm') + '</td>')
        [void]$sb.AppendLine('</tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
}

if ($unmatched.Count -gt 0) {
    [void]$sb.AppendLine('<h2>未归属文件（需人工确认）</h2>')
    [void]$sb.AppendLine('<table><thead><tr><th>文件名</th><th class="num">大小</th><th>扩展名</th><th class="num">修改时间</th></tr></thead><tbody>')
    foreach ($u in ($unmatched | Sort-Object Name)) {
        [void]$sb.AppendLine('<tr><td class="mono">' + (Encode-Html $u.Name) + '</td><td class="num">' + (Format-Size -Bytes $u.Size) + '</td><td class="mono">' + (Encode-Html $u.Ext) + '</td><td class="num">' + $u.Modified.ToString('yyyy-MM-dd HH:mm') + '</td></tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
}

if ($suspicious.Count -gt 0) {
    [void]$sb.AppendLine('<h2>来源不明的可执行文件（需人工确认）</h2>')
    [void]$sb.AppendLine('<p class="note">这些文件没有版本信息、没有数字签名，也没有匹配到任何已安装软件。可能是某个便携程序的组成文件，也可能是软件卸载后的残留；不要仅凭"看起来像垃圾"就删除。</p>')
    [void]$sb.AppendLine('<table><thead><tr><th>文件名</th><th class="num">大小</th><th>架构</th><th>扩展名</th><th class="num">修改时间</th></tr></thead><tbody>')
    foreach ($s in ($suspicious | Sort-Object Name)) {
        $sArch = $s.Arch
        if ([string]::IsNullOrWhiteSpace($sArch)) { $sArch = '-' }
        [void]$sb.AppendLine('<tr><td class="mono">' + (Encode-Html $s.Name) + '</td><td class="num">' + (Format-Size -Bytes $s.Size) + '</td><td class="mono">' + (Encode-Html $sArch) + '</td><td class="mono">' + (Encode-Html $s.Ext) + '</td><td class="num">' + $s.Modified.ToString('yyyy-MM-dd HH:mm') + '</td></tr>')
    }
    [void]$sb.AppendLine('</tbody></table>')
}

[void]$sb.AppendLine('<h2>建议动作</h2><ol>')
foreach ($a in $actions) { [void]$sb.AppendLine('<li>' + (Encode-Html $a) + '</li>') }
[void]$sb.AppendLine('</ol>')

[void]$sb.AppendLine('<footer>判定依据：卸载注册表 InstallLocation、文件版本信息（公司/产品/描述）、Authenticode 数字签名、PE 头架构识别，以及内置的公共组件对照表。置信度「高」= 安装路径直接命中；「中」= 产品名称命中；「低」= 仅厂商同源；「参考」= 命中公共组件库。报告由 ' + (Encode-Html $script:ToolName) + ' 生成，删除任何文件前请自行复核。</footer>')
[void]$sb.AppendLine('</main></body></html>')

try {
    $utf8 = New-Object System.Text.UTF8Encoding($true)
    [System.IO.File]::WriteAllText($htmlPath, $sb.ToString(), $utf8)
    Write-Host ''
    Write-Host ('  HTML 报告：' + $htmlPath) -ForegroundColor Green
} catch {
    Write-Host ('  报告写入失败：' + $_.Exception.Message) -ForegroundColor Red
    return
}

try {
    $jsonPath = [System.IO.Path]::ChangeExtension($htmlPath, '.json')
    $payload = [pscustomobject]@{
        Tool       = $script:ToolName
        ScannedAt  = (Get-Date).ToString('s')
        Target     = $target
        Recursive  = [bool]$Recurse
        FileCount  = $records.Count
        TotalBytes = $totalSize
        Signed     = [bool]$useSignature
        Unsigned   = $unsigned.Count
        Suspicious = $suspicious.Count
        Architectures = @($archGroups)
        Conclusions = @($conclusions)
        Actions     = @($actions)
        Groups      = @($groups)
        Files       = @($records | Select-Object Name, Dir, Ext, Arch, Size, Company, ProductName, Description, FileVersion, SignerName, SigStatus, Product, Confidence, Reason, Kind)
    }
    $json = $payload | ConvertTo-Json -Depth 6
    [System.IO.File]::WriteAllText($jsonPath, $json, (New-Object System.Text.UTF8Encoding($true)))
    Write-Host ('  JSON 数据：' + $jsonPath) -ForegroundColor DarkGray
} catch {
    Write-Host ('  JSON 写入失败：' + $_.Exception.Message) -ForegroundColor DarkYellow
}

try {
    $csvPath = [System.IO.Path]::ChangeExtension($htmlPath, '.csv')
    $csvRows = @($records | Sort-Object -Property @{ Expression = 'Kind' }, Name | Select-Object Name, Ext, Arch, @{ n = 'Size'; e = { $_.Size } }, Product, Confidence, Kind, Company, ProductName, Description, FileVersion, SignerName, SigStatus, @{ n = 'Modified'; e = { $_.Modified.ToString('yyyy-MM-dd HH:mm:ss') } }, Dir)
    $csvRows | Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host ('  CSV  数据：' + $csvPath) -ForegroundColor DarkGray
} catch {
    Write-Host ('  CSV 写入失败：' + $_.Exception.Message) -ForegroundColor DarkYellow
}

