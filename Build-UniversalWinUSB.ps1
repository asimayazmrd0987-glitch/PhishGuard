<#
.SYNOPSIS
  Universal Windows deployment USB toolkit (v2). One file, modular inside.

.DESCRIPTION
  MODULES (in file order)
    1. Shared code ........ logging, config parser/validator, answer-file generator (also embedded in the USB)
    2. Diagnostics ........ stage runner, native-command wrapper, build report, work-dir safety
    3. Preflight .......... admin, cmdlets, stale mounts, ADK discovery and ADK<->image build match
    4. Image Manager ...... ISO inspection (WIM / ESD / SWM), edition + architecture detection
    5. Driver Manager ..... INF validation at build time (runtime loader is in the payload)
    6. USB Builder ........ UEFI/GPT, BIOS/MBR, Hybrid profiles, boot files, verification
    7. Deployment Engine .. payload that runs in WinPE on the target PC (disk plan, rollback, answer file)
    8. Post-install ....... allowlisted (SHA-256) scripts + install report
    9. Self-test .......... offline tests, no disks touched

  ACTIONS
    -Action Inspect   Read-only: show what is inside an ISO (format, editions, architecture, build)
    -Action Build     Full pipeline (default). Add -DryRun to see the plan without touching the USB
    -Action SelfTest  Run built-in tests (no admin, no ISO, no USB needed)

  MODES ON THE TARGET PC  (-Mode)
    Interactive  normal Windows Setup, nothing automated
    SemiAuto     auto plan, but asks before every destructive step
    Unattended   auto plan + answer file (asks once if ConfirmBeforeChange=true)   [default]
    Technician   drops to a command prompt (diskpart, drvload, powershell) first

  STORAGE STRATEGIES  (-Strategy)
    UseFreeSpace    only uses blank disk / existing unallocated space
    ShrinkIfNeeded  also shrinks one NTFS volume (data kept)                        [default]
    CleanDisk       erases the WHOLE chosen disk - always needs a typed confirmation

  USB FOLDER LAYOUT (what -DriverPath expects)
    <DriverPath>\x64\storage\...   loaded in WinPE only if no disk is visible
    <DriverPath>\x64\network\...   loaded in WinPE if no network adapter is visible
    <DriverPath>\x64\<anything>    also passed to Setup (WinPE + installed OS)
    <DriverPath>\WinPE\...         injected into boot.wim at build time (optional)

.REQUIREMENTS (build PC)
  Windows 10/11, PowerShell 5.1+, run as Administrator, Windows ADK + matching WinPE add-on
  (x64 is installed with the ADK; ARM64 needs the ARM64 WinPE parts). Official Windows ISO + your licence.

.EXAMPLES
  .\Build-UniversalWinUSB.ps1 -Action SelfTest
  .\Build-UniversalWinUSB.ps1 -Action Inspect -IsoPath D:\Win11.iso
  .\Build-UniversalWinUSB.ps1 -IsoPath D:\Win11.iso -UsbDrive E -Edition "Windows 11 Pro" -DryRun
  .\Build-UniversalWinUSB.ps1 -IsoPath D:\Win11.iso -UsbDrive E -Edition "Windows 11 Pro" `
      -WindowsSizeGB 100 -BootProfile Hybrid -DriverPath D:\Drivers -PostInstallPath D:\PostInstall
#>
[CmdletBinding()]
param(
    [ValidateSet('Build','Inspect','SelfTest')][string]$Action = 'Build',
    [string]$IsoPath,
    [string]$UsbDrive,
    [string]$Edition,
    [int]$ImageIndex = 0,
    [ValidateSet('Auto','x64','arm64','x86')][string]$Architecture = 'Auto',
    [ValidateSet('UEFI','BIOS','Hybrid')][string]$BootProfile = 'UEFI',
    [ValidateSet('Interactive','SemiAuto','Unattended','Technician')][string]$Mode = 'Unattended',
    [ValidateSet('UseFreeSpace','ShrinkIfNeeded','CleanDisk')][string]$Strategy = 'ShrinkIfNeeded',
    [int]$WindowsSizeGB = 100,
    [string]$Language = 'en-US',
    [string]$TimeZone = '',
    [string]$ProductKey = '',
    [string]$TargetDisk = 'Auto',
    [bool]$ConfirmBeforeChange = $true,
    [string]$ConfigFile,
    [string]$DriverPath,
    [string]$PostInstallPath,
    [switch]$DryRun,
    [switch]$DeployDryRun,
    [switch]$AllowAdkMismatch,
    [string]$WorkRoot = $env:TEMP,
    [string]$LogDir
)

$ErrorActionPreference = 'Stop'
$script:Version  = '2.0.0'
$script:Bound    = $PSBoundParameters
$script:LogFile  = $null
$script:Stages   = New-Object System.Collections.Generic.List[object]
$script:Notes    = New-Object System.Collections.Generic.List[string]
$ctx = @{}

# ======================================================================================
#  MODULE 1 - SHARED CODE  (executed here AND embedded in the WinPE payload)
# ======================================================================================
$CommonCode = @'
function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO')
    $line = '{0}  [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    if ($script:LogFile) { try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch {} }
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'DEBUG' { }
        default { Write-Host $line }
    }
}

function ConvertTo-ArchName {
    param($Value)
    switch -Regex ("$Value") {
        '^(0|x86)$'          { return 'x86' }
        '^(5|arm)$'          { return 'arm' }
        '^(9|amd64|x64)$'    { return 'x64' }
        '^(12|arm64)$'       { return 'arm64' }
        default              { return "unknown($Value)" }
    }
}

function Get-ProcArch {
    param([string]$Arch)
    switch ($Arch) { 'x64' { return 'amd64' } 'arm64' { return 'arm64' } 'x86' { return 'x86' } default { return $Arch } }
}

function Get-ConfigDefaults {
    return @{
        'General.Mode' = 'Unattended'; 'General.Language' = 'en-US'; 'General.TimeZone' = ''
        'General.ConfirmBeforeChange' = 'true'; 'General.DryRun' = 'false'
        'Windows.Edition' = ''; 'Windows.ImageIndex' = ''; 'Windows.Architecture' = 'x64'; 'Windows.ProductKey' = ''
        'Storage.BootMode' = 'UEFI'; 'Storage.Strategy' = 'ShrinkIfNeeded'; 'Storage.WindowsSizeGB' = '100'
        'Storage.TargetDisk' = 'Auto'; 'Storage.VolumeLabel' = 'Windows'; 'Storage.ShrinkHeadroomGB' = '5'
        'Drivers.Enable' = 'true'
        'Security.RequireSecureBoot' = 'false'; 'Security.BitLockerPolicy' = 'Warn'
        'Recovery.LogToUsb' = 'true'; 'Recovery.OnError' = 'Manual'
        'PostInstall.Enable' = 'false'
    }
}

function Read-IniText {
    param([string[]]$Lines)
    $cfg = @{}
    $section = ''
    foreach ($raw in $Lines) {
        $l = "$raw".Trim()
        if ($l -eq '' -or $l.StartsWith('#') -or $l.StartsWith(';')) { continue }
        if ($l -match '^\[(.+)\]$') { $section = $Matches[1].Trim(); continue }
        if ($l -match '^([^=]+?)\s*=\s*(.*)$') { $cfg["$section.$($Matches[1].Trim())"] = $Matches[2].Trim() }
    }
    return $cfg
}

function Merge-Config {
    param([hashtable]$Loaded)
    $c = Get-ConfigDefaults
    foreach ($k in @($Loaded.Keys)) { $c[$k] = $Loaded[$k] }
    return $c
}

function ConvertTo-IniText {
    param([hashtable]$C)
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('# Universal Windows Installer configuration. Edit freely; it is validated before any change is made.')
    $last = ''
    foreach ($k in ($C.Keys | Sort-Object)) {
        $parts = $k.Split('.', 2)
        if ($parts[0] -ne $last) { [void]$sb.AppendLine(''); [void]$sb.AppendLine("[$($parts[0])]"); $last = $parts[0] }
        [void]$sb.AppendLine("$($parts[1])=$($C[$k])")
    }
    return $sb.ToString()
}

function Test-DeployConfig {
    param([hashtable]$C)
    $e = New-Object System.Collections.Generic.List[string]
    $w = New-Object System.Collections.Generic.List[string]
    $enum = @{
        'General.Mode'             = @('Interactive','SemiAuto','Unattended','Technician')
        'Windows.Architecture'     = @('x64','arm64','x86')
        'Storage.BootMode'         = @('UEFI','BIOS','Auto')
        'Storage.Strategy'         = @('UseFreeSpace','ShrinkIfNeeded','CleanDisk')
        'Security.BitLockerPolicy' = @('Warn','Abort')
        'Recovery.OnError'         = @('Manual','Technician','Halt')
    }
    foreach ($k in $enum.Keys) {
        if ($enum[$k] -notcontains $C[$k]) { $e.Add("$k = '$($C[$k])' is invalid. Allowed: $($enum[$k] -join ', ')") }
    }
    foreach ($k in 'General.ConfirmBeforeChange','General.DryRun','Drivers.Enable','Security.RequireSecureBoot','Recovery.LogToUsb','PostInstall.Enable') {
        if (@('true','false') -notcontains $C[$k]) { $e.Add("$k must be true or false (got '$($C[$k])')") }
    }
    $gb = 0
    if (-not [int]::TryParse([string]$C['Storage.WindowsSizeGB'], [ref]$gb) -or $gb -lt 20 -or $gb -gt 4096) {
        $e.Add('Storage.WindowsSizeGB must be a whole number between 20 and 4096')
    } elseif ($gb -lt 64) {
        $w.Add("Storage.WindowsSizeGB=$gb is below the 64 GB Windows 11 minimum.")
    }
    $hr = 0
    if (-not [int]::TryParse([string]$C['Storage.ShrinkHeadroomGB'], [ref]$hr) -or $hr -lt 1 -or $hr -gt 500) {
        $e.Add('Storage.ShrinkHeadroomGB must be a whole number between 1 and 500')
    }
    if ($C['General.Language'] -notmatch '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$') { $e.Add("General.Language '$($C['General.Language'])' is not a valid language tag (example: en-US)") }
    if ($C['General.TimeZone'] -ne '' -and $C['General.TimeZone'] -notmatch '^[A-Za-z0-9 ()+.,_/-]{3,64}$') { $e.Add('General.TimeZone contains invalid characters') }
    if ($C['Windows.Edition'] -eq '' -and $C['Windows.ImageIndex'] -eq '') { $e.Add('Set Windows.Edition or Windows.ImageIndex') }
    if ($C['Windows.ImageIndex'] -ne '' -and $C['Windows.ImageIndex'] -notmatch '^\d{1,3}$') { $e.Add('Windows.ImageIndex must be a number') }
    if ($C['Windows.ProductKey'] -ne '' -and $C['Windows.ProductKey'] -notmatch '^([A-Z0-9]{5}-){4}[A-Z0-9]{5}$') { $e.Add('Windows.ProductKey must look like XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (or be empty)') }
    if ($C['Storage.TargetDisk'] -notmatch '^(Auto|Number:\d{1,3}|Serial:\S.*|Model:\S.*)$') { $e.Add('Storage.TargetDisk must be Auto, Number:<n>, Serial:<text> or Model:<text>') }
    if ($C['Storage.VolumeLabel'] -notmatch '^[A-Za-z0-9 _-]{1,32}$') { $e.Add('Storage.VolumeLabel: 1-32 characters, letters/digits/space/_/- only') }
    $arch = $C['Windows.Architecture']; $bm = $C['Storage.BootMode']
    if ($arch -eq 'arm64' -and $bm -eq 'BIOS') { $e.Add('arm64 supports UEFI only (BootMode cannot be BIOS)') }
    if ($arch -eq 'x86' -and $bm -eq 'UEFI')   { $e.Add('x86 media is only supported with BootMode BIOS or Auto') }
    if ($C['Storage.Strategy'] -eq 'CleanDisk') { $w.Add('Strategy=CleanDisk erases a whole disk. A typed confirmation is always required.') }
    if ($C['Windows.ProductKey'] -ne '') { $w.Add('A product key is stored in plain text on the USB. Remove it from config.ini if you share the stick.') }
    return [pscustomobject]@{ Errors = @($e); Warnings = @($w) }
}

function Escape-Xml {
    param([string]$s)
    return [System.Security.SecurityElement]::Escape($s)
}

function New-AnswerFileXml {
    param([hashtable]$C, [int]$DiskId, [int]$PartitionId, [string[]]$DriverPaths = @())
    $arch = Get-ProcArch $C['Windows.Architecture']
    $lang = Escape-Xml $C['General.Language']
    if ($C['Windows.Edition'] -ne '') { $selKey = '/IMAGE/NAME';  $selVal = Escape-Xml $C['Windows.Edition'] }
    else                              { $selKey = '/IMAGE/INDEX'; $selVal = Escape-Xml $C['Windows.ImageIndex'] }
    $pk = ''
    if ($C['Windows.ProductKey'] -ne '') { $pk = '<ProductKey><Key>' + (Escape-Xml $C['Windows.ProductKey']) + '</Key></ProductKey>' }
    $tz = ''
    if ($C['General.TimeZone'] -ne '') { $tz = '<TimeZone>' + (Escape-Xml $C['General.TimeZone']) + '</TimeZone>' }

    $drvPE = ''; $drvOff = ''
    if ($DriverPaths.Count -gt 0) {
        $items = ''; $i = 1
        foreach ($p in $DriverPaths) {
            $items += ('<PathAndCredentials wcm:action="add" wcm:keyValue="{0}"><Path>{1}</Path></PathAndCredentials>' -f $i, (Escape-Xml $p))
            $i++
        }
        $drvPE = ('<component name="Microsoft-Windows-PnpCustomizationsWinPE" processorArchitecture="{0}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><DriverPaths>{1}</DriverPaths></component>' -f $arch, $items)
        $drvOff = ('<settings pass="offlineServicing"><component name="Microsoft-Windows-PnpCustomizationsNonWinPE" processorArchitecture="{0}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS"><DriverPaths>{1}</DriverPaths></component></settings>' -f $arch, $items)
    }

    $xml = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="$arch" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>$lang</UILanguage></SetupUILanguage>
      <InputLocale>$lang</InputLocale>
      <SystemLocale>$lang</SystemLocale>
      <UILanguage>$lang</UILanguage>
      <UserLocale>$lang</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="$arch" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ImageInstall>
        <OSImage>
          <InstallTo><DiskID>$DiskId</DiskID><PartitionID>$PartitionId</PartitionID></InstallTo>
          <InstallFrom><MetaData wcm:action="add"><Key>$selKey</Key><Value>$selVal</Value></MetaData></InstallFrom>
        </OSImage>
      </ImageInstall>
      <UserData>$pk<AcceptEula>true</AcceptEula></UserData>
    </component>
    $drvPE
  </settings>
  $drvOff
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="$arch" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>$lang</InputLocale>
      <SystemLocale>$lang</SystemLocale>
      <UILanguage>$lang</UILanguage>
      <UserLocale>$lang</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="$arch" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE><HideEULAPage>true</HideEULAPage></OOBE>
      $tz
    </component>
  </settings>
</unattend>
"@

    # Validate: must be well-formed and contain the nodes Setup needs.
    $doc = New-Object System.Xml.XmlDocument
    $doc.LoadXml($xml)
    $ns = New-Object System.Xml.XmlNamespaceManager($doc.NameTable)
    $ns.AddNamespace('u', 'urn:schemas-microsoft-com:unattend')
    foreach ($xp in '//u:InstallTo/u:DiskID', '//u:InstallTo/u:PartitionID', '//u:MetaData/u:Key', '//u:MetaData/u:Value') {
        if (-not $doc.SelectSingleNode($xp, $ns)) { throw "Answer file validation failed: missing $xp" }
    }
    return $xml
}
'@
Invoke-Expression $CommonCode

# ======================================================================================
#  MODULE 2 - DIAGNOSTICS
# ======================================================================================
function Initialize-Logging {
    if (-not $LogDir) { $script:LogDirResolved = Join-Path ([Environment]::GetFolderPath('MyDocuments')) 'AutoWinUSB\logs' }
    else              { $script:LogDirResolved = $LogDir }
    New-Item -ItemType Directory -Path $script:LogDirResolved -Force | Out-Null
    $script:LogFile = Join-Path $script:LogDirResolved ("{0}-{1}.log" -f $Action.ToLower(), (Get-Date -Format 'yyyyMMdd-HHmmss'))
    Write-Log "Universal Windows USB toolkit v$script:Version, action=$Action"
}

function Invoke-Stage {
    param([string]$Name, [scriptblock]$Body, [switch]$NonCritical)
    Write-Host "`n==> $Name" -ForegroundColor Cyan
    Write-Log "STAGE START: $Name"
    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        & $Body
        $script:Stages.Add([pscustomobject]@{ Name = $Name; Status = 'OK'; Detail = ''; Secs = [int]$sw.Elapsed.TotalSeconds })
        Write-Log "STAGE OK: $Name"
    } catch {
        $msg = $_.Exception.Message
        $status = if ($NonCritical) { 'WARN' } else { 'FAILED' }
        $script:Stages.Add([pscustomobject]@{ Name = $Name; Status = $status; Detail = $msg; Secs = [int]$sw.Elapsed.TotalSeconds })
        Write-Log "STAGE ${status}: $Name - $msg" 'ERROR'
        if (-not $NonCritical) { throw }
    }
}

function Invoke-Native {
    param([string]$File, [string[]]$Arguments, [int[]]$OkCodes = @(0))
    Write-Log "RUN: $File $($Arguments -join ' ')" 'DEBUG'
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $out = & $File @Arguments 2>&1; $code = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
    foreach ($l in @($out)) { Write-Log "$l" 'DEBUG' }
    if ($OkCodes -notcontains $code) { throw "$File failed with exit code $code (see log: $script:LogFile)" }
}

function Add-Note { param([string]$Text) $script:Notes.Add($Text); Write-Log $Text 'WARN' }

function Show-Report {
    Write-Host "`n================ BUILD REPORT ================" -ForegroundColor Cyan
    foreach ($s in $script:Stages) {
        $col = switch ($s.Status) { 'OK' { 'Green' } 'WARN' { 'Yellow' } default { 'Red' } }
        Write-Host ('  [{0,-6}] {1}  ({2}s) {3}' -f $s.Status, $s.Name, $s.Secs, $s.Detail) -ForegroundColor $col
    }
    if ($script:Notes.Count -gt 0) {
        Write-Host "`nNeeds attention:" -ForegroundColor Yellow
        foreach ($n in $script:Notes) { Write-Host "  - $n" -ForegroundColor Yellow }
    }
    $failed = @($script:Stages | Where-Object { $_.Status -eq 'FAILED' }).Count
    Write-Host ''
    if ($failed -gt 0) { Write-Host 'RESULT: BUILD FAILED. The USB is NOT ready.' -ForegroundColor Red }
    else               { Write-Host 'RESULT: finished without critical failures.' -ForegroundColor Green }
    Write-Host "Log: $script:LogFile"
    try { Copy-Item $script:LogFile ($script:LogFile -replace '\.log$', '.report-copy.log') -Force } catch {}
}

function New-WorkDir {
    $dir = Join-Path $WorkRoot ('AutoWinUSB-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $dir | Out-Null
    Set-Content -LiteralPath (Join-Path $dir '.autowinusb-workdir') -Value $script:Version
    return $dir
}

function Remove-WorkDir {
    param([string]$Dir)
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir)) { return }
    if (-not (Test-Path -LiteralPath (Join-Path $Dir '.autowinusb-workdir'))) {
        Write-Log "Not deleting $Dir : it was not created by this tool." 'WARN'; return
    }
    try {
        Get-WindowsImage -Mounted -ErrorAction SilentlyContinue | Where-Object { $_.Path -like "$Dir*" } |
            ForEach-Object { Dismount-WindowsImage -Path $_.Path -Discard -ErrorAction SilentlyContinue | Out-Null }
    } catch {}
    Remove-Item -LiteralPath $Dir -Recurse -Force -ErrorAction SilentlyContinue
}

# ======================================================================================
#  MODULE 3 - PREFLIGHT
# ======================================================================================
function Test-Preflight {
    if ($PSVersionTable.PSVersion -lt [version]'5.1') { throw 'PowerShell 5.1 or newer is required.' }
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this script from an elevated (Administrator) PowerShell.'
    }
    foreach ($c in 'Get-WindowsImage','Mount-WindowsImage','Add-WindowsPackage','Mount-DiskImage','Get-Disk','Format-Volume') {
        if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { throw "Required cmdlet missing: $c" }
    }
    foreach ($x in 'dism.exe','robocopy.exe') {
        if (-not (Get-Command $x -ErrorAction SilentlyContinue)) { throw "Required program missing: $x" }
    }
    Get-WindowsImage -Mounted -ErrorAction SilentlyContinue | Where-Object { $_.Path -like '*\AutoWinUSB-*' } | ForEach-Object {
        Write-Log "Discarding stale mount from an interrupted build: $($_.Path)" 'WARN'
        Dismount-WindowsImage -Path $_.Path -Discard | Out-Null
    }
    Write-Log 'Preflight OK'
}

function Get-BuildFamily {
    param([int]$Build)
    if ($Build -ge 26100) { return '26100' }
    if ($Build -ge 22621) { return '22621' }
    if ($Build -ge 22000) { return '22000' }
    if ($Build -ge 19041) { return '19041' }
    return "$Build"
}

function Get-AdkInfo {
    param([string]$Arch)
    $folder = @{ x64 = 'amd64'; arm64 = 'arm64'; x86 = 'x86' }[$Arch]
    $base = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment'
    $oc = Join-Path $base "$folder\WinPE_OCs"
    if (-not (Test-Path $oc)) {
        throw "WinPE components for $Arch not found. Install the Windows ADK and the matching 'WinPE add-on'. Expected: $oc"
    }
    $build = $null
    $winpe = Join-Path $base "$folder\en-us\winpe.wim"
    if (Test-Path $winpe) { $build = ([version](Get-WindowsImage -ImagePath $winpe -Index 1).Version).Build }
    return [pscustomobject]@{ OCPath = $oc; Build = $build }
}

# ======================================================================================
#  MODULE 4 - IMAGE MANAGER
# ======================================================================================
function Get-IsoInfo {
    param([string]$Path)
    $full = (Resolve-Path -LiteralPath $Path).Path
    $img = Mount-DiskImage -ImagePath $full -PassThru
    $ctx.IsoPath = $full
    $letter = ($img | Get-Volume).DriveLetter
    if (-not $letter) { throw 'ISO mounted but has no drive letter.' }
    $root = "${letter}:\"
    $src = Join-Path $root 'sources'
    $fmt = $null; $file = $null
    if     (Test-Path "$src\install.wim") { $fmt = 'WIM'; $file = "$src\install.wim" }
    elseif (Test-Path "$src\install.esd") { $fmt = 'ESD'; $file = "$src\install.esd" }
    elseif (Test-Path "$src\install.swm") { $fmt = 'SWM'; $file = "$src\install.swm" }
    else { throw 'No sources\install.wim / install.esd / install.swm in this ISO (multi-architecture or unsupported layout).' }
    if (-not (Test-Path "$src\boot.wim")) { throw 'sources\boot.wim is missing from the ISO.' }

    $editions = @()
    if ($fmt -ne 'SWM') {
        $editions = @(Get-WindowsImage -ImagePath $file | ForEach-Object { Get-WindowsImage -ImagePath $file -Index $_.ImageIndex })
    }
    $efi = @{ x64 = 'efi\boot\bootx64.efi'; arm64 = 'efi\boot\bootaa64.efi'; x86 = 'efi\boot\bootia32.efi' }
    $efiArch = @($efi.Keys | Where-Object { Test-Path (Join-Path $root $efi[$_]) })
    $arch = $null; $build = 0; $ver = ''
    if ($editions.Count -gt 0) {
        $archs = @($editions | ForEach-Object { ConvertTo-ArchName $_.Architecture } | Sort-Object -Unique)
        if ($archs.Count -gt 1) { throw "Image contains mixed architectures: $($archs -join ', ')" }
        $arch = $archs[0]
        $ver = "$($editions[0].Version)"
        $build = ([version]$ver).Build
    } elseif ($efiArch.Count -eq 1) { $arch = $efiArch[0] }
    $bootInfo = Get-WindowsImage -ImagePath "$src\boot.wim" -Index 2 -ErrorAction Stop
    return [pscustomobject]@{
        Path = $full; Root = $root; Format = $fmt; File = $file; Editions = $editions
        Arch = $arch; Build = $build; Version = $ver
        HasEfi = ($efiArch -contains $arch); HasBios = ((Test-Path "$root\bootmgr") -and (Test-Path "$root\boot\bootsect.exe"))
        BootWim = "$src\boot.wim"; BootSetupName = $bootInfo.ImageName
        SizeBytes = (Get-Item -LiteralPath $full).Length
        ImageBytes = (Get-Item -LiteralPath $file).Length
    }
}

function Show-IsoInfo {
    param($Iso)
    Write-Host "`nISO: $($Iso.Path)"
    Write-Host ("  Format: {0}   Architecture: {1}   Windows version: {2}" -f $Iso.Format, $Iso.Arch, $Iso.Version)
    Write-Host ("  UEFI boot files: {0}   Legacy BIOS boot files: {1}" -f $Iso.HasEfi, $Iso.HasBios)
    if ($Iso.Editions.Count -gt 0) {
        Write-Host '  Editions:'
        foreach ($e in $Iso.Editions) { Write-Host ("    [{0}] {1}  ({2} GB)" -f $e.ImageIndex, $e.ImageName, [math]::Round($e.ImageSize / 1GB, 1)) }
    } else { Write-Host '  Editions: cannot be listed for split (.swm) images' }
}

function Select-Edition {
    param($Editions, [string]$Name, [int]$Index, [switch]$NoPrompt)
    $list = @($Editions)
    if ($list.Count -eq 0) { return $null }
    $avail = ($list | ForEach-Object { '{0}={1}' -f $_.ImageIndex, $_.ImageName }) -join '; '
    if ($Index -gt 0) {
        $m = @($list | Where-Object { $_.ImageIndex -eq $Index })
        if ($m.Count -eq 1) { return $m[0] }
        throw "Image index $Index not found. Available: $avail"
    }
    if ($Name) {
        $m = @($list | Where-Object { $_.ImageName -eq $Name })
        if ($m.Count -ge 1) { return $m[0] }
        throw "Edition '$Name' not found. Available: $avail"
    }
    if ($list.Count -eq 1) { return $list[0] }
    if (-not $NoPrompt -and [Environment]::UserInteractive) {
        foreach ($e in $list) { Write-Host ("  [{0}] {1}" -f $e.ImageIndex, $e.ImageName) }
        $n = 0
        if ([int]::TryParse((Read-Host 'Edition index'), [ref]$n)) {
            $m = @($list | Where-Object { $_.ImageIndex -eq $n })
            if ($m.Count -eq 1) { return $m[0] }
        }
    }
    throw "Several editions are available; pass -Edition or -ImageIndex. Available: $avail"
}

# ======================================================================================
#  MODULE 5 - DRIVER MANAGER (build time)
# ======================================================================================
function Test-InfCompatible {
    param([string]$Path, [string]$Arch)
    $txt = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    if ($txt -notmatch '(?im)^\s*\[Version\]') { return [pscustomobject]@{ Compatible = $false; Reason = 'not a driver INF (no [Version] section)'; Warning = '' } }
    $target = Get-ProcArch $Arch
    $tokens = @([regex]::Matches($txt, '(?i)NT(amd64|arm64|x86)') | ForEach-Object { $_.Groups[1].Value.ToLower() } | Sort-Object -Unique)
    if ($tokens.Count -gt 0 -and $tokens -notcontains $target) {
        return [pscustomobject]@{ Compatible = $false; Reason = "built for $($tokens -join '/'), target is $target"; Warning = '' }
    }
    $warn = ''
    if ($txt -notmatch '(?im)^\s*CatalogFile(\.NT\w+)?\s*=') { $warn = 'no CatalogFile entry (driver is probably unsigned; Windows may refuse it)' }
    return [pscustomobject]@{ Compatible = $true; Reason = ''; Warning = $warn }
}

function Get-DriverPlan {
    param([string]$Root, [string]$Arch)
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) { throw "DriverPath not found: $Root" }
    $archDir = Join-Path $Root $Arch
    $inc = New-Object System.Collections.Generic.List[string]
    $skp = New-Object System.Collections.Generic.List[string]
    if (Test-Path -LiteralPath $archDir) {
        $groups = Get-ChildItem -LiteralPath $archDir -Filter *.inf -Recurse | Group-Object DirectoryName
        foreach ($g in $groups) {
            $good = $false; $why = @()
            foreach ($f in $g.Group) {
                $r = Test-InfCompatible $f.FullName $Arch
                if ($r.Compatible) { $good = $true } else { $why += "$($f.Name): $($r.Reason)" }
                if ($r.Warning) { Write-Log "$($f.FullName): $($r.Warning)" 'WARN' }
            }
            if ($good) { $inc.Add($g.Name) } else { $skp.Add("$($g.Name) -> $($why -join '; ')") }
        }
    } else { Write-Log "No '$Arch' sub-folder in $Root; no setup drivers will be added." 'WARN' }
    return [pscustomobject]@{ Root = $Root; ArchDir = $archDir; WinPEDir = (Join-Path $Root 'WinPE'); Included = @($inc); Skipped = @($skp) }
}

# ======================================================================================
#  MODULE 8 - POST-INSTALL (build-time planning)
# ======================================================================================
function Get-PostInstallPlan {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "PostInstallPath is not a folder: $Path" }
    $items = foreach ($f in (Get-ChildItem -LiteralPath $Path -File | Sort-Object Name)) {
        if (@('.ps1', '.cmd', '.msi') -notcontains $f.Extension.ToLower()) { Write-Log "Ignoring $($f.Name): only .ps1 .cmd .msi are allowed" 'WARN'; continue }
        [pscustomobject]@{ File = $f.Name; Sha256 = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash; Path = $f.FullName }
    }
    return @($items)
}

$PostInstallRunner = @'
$dir = Join-Path $env:SystemDrive 'AutoInstall\PostInstall'
$rep = Join-Path $env:SystemDrive 'AutoInstall\install-report.txt'
function R([string]$m) { Add-Content -Path $rep -Value ('{0}  {1}' -f (Get-Date -Format s), $m) }
R 'Post-install start'
try { $os = Get-CimInstance Win32_OperatingSystem; R ("OS: {0} build {1} {2}" -f $os.Caption, $os.BuildNumber, $os.OSArchitecture) } catch {}
$list = Get-Content (Join-Path $dir 'allowlist.json') -Raw | ConvertFrom-Json
foreach ($it in @($list.items)) {
    $f = Join-Path $dir $it.file
    if (-not (Test-Path -LiteralPath $f)) { R "MISSING $($it.file)"; continue }
    $h = (Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash
    if ($h -ne $it.sha256) { R "HASH MISMATCH, skipped: $($it.file)"; continue }
    try {
        $c = 'unsupported'
        switch ([IO.Path]::GetExtension($f).ToLower()) {
            '.ps1' { & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $f; $c = $LASTEXITCODE }
            '.cmd' { & cmd.exe /c "`"$f`""; $c = $LASTEXITCODE }
            '.msi' { $p = Start-Process msiexec.exe -ArgumentList '/i', "`"$f`"", '/qn', '/norestart' -Wait -PassThru; $c = $p.ExitCode }
        }
        R "RAN $($it.file) exit=$c"
    } catch { R "ERROR $($it.file): $($_.Exception.Message)" }
}
R 'Post-install end'
'@

# ======================================================================================
#  MODULE 7 - DEPLOYMENT ENGINE  (runs inside WinPE on the target PC)
# ======================================================================================
$RuntimeCode = @'
$ErrorActionPreference = 'Stop'
$script:LogFile = 'X:\auto\auto.log'
$script:UsbRoot = $null
$script:Cfg = $null

function Copy-LogToUsb {
    if ($script:UsbRoot -and $script:Cfg -and $script:Cfg['Recovery.LogToUsb'] -eq 'true') {
        try {
            $d = Join-Path $script:UsbRoot 'AutoInstall\Logs'
            New-Item -ItemType Directory -Path $d -Force | Out-Null
            Copy-Item $script:LogFile (Join-Path $d ('{0}-{1}.log' -f $env:COMPUTERNAME, (Get-Date -Format 'yyyyMMdd-HHmmss'))) -Force
        } catch {}
    }
}

function Start-ManualSetup {
    param([string]$Why)
    Write-Log "Manual setup: $Why" 'WARN'
    Write-Host "`n>>> $Why" -ForegroundColor Yellow
    Write-Host '>>> Starting normal Windows Setup. Nothing more will be changed automatically.' -ForegroundColor Yellow
    Copy-LogToUsb
    Start-Sleep 4
    Start-Process 'X:\sources\setup.exe' -Wait
    exit
}

function Start-Technician {
    Write-Log 'Technician shell opened'
    Write-Host "`nTechnician mode. Useful: diskpart, powershell, drvload <inf>, notepad. Type EXIT to go on to Windows Setup." -ForegroundColor Cyan
    Start-Process 'cmd.exe' -ArgumentList '/k', 'title Technician shell' -Wait
    Start-ManualSetup 'Technician shell closed.'
}

function Stop-WithError {
    param([string]$Why)
    Write-Log $Why 'ERROR'
    $how = 'Manual'
    if ($script:Cfg) { $how = $script:Cfg['Recovery.OnError'] }
    switch ($how) {
        'Technician' { Start-Technician }
        'Halt' {
            Write-Host "`n>>> $Why" -ForegroundColor Red
            Copy-LogToUsb
            [void](Read-Host 'Press Enter to restart the computer')
            Start-Process 'wpeutil.exe' -ArgumentList 'reboot' -Wait
            Start-Sleep 60; exit
        }
        default { Start-ManualSetup $Why }
    }
}

function Get-PEArch {
    switch ($env:PROCESSOR_ARCHITECTURE) { 'AMD64' { return 'x64' } 'ARM64' { return 'arm64' } 'x86' { return 'x86' } default { return "$($env:PROCESSOR_ARCHITECTURE)" } }
}
function Get-FirmwareMode {
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control').PEFirmwareType -eq 2) { return 'UEFI' } else { return 'BIOS' }
}
function Get-SecureBootState {
    try { return [bool](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' -ErrorAction Stop).UEFISecureBootEnabled } catch { return $false }
}

# ---------- Driver Manager (runtime) ----------
function Write-HardwareReport {
    try {
        $cs = Get-CimInstance Win32_ComputerSystem
        $bios = Get-CimInstance Win32_BIOS
        $ram = [math]::Round($cs.TotalPhysicalMemory / 1GB, 1)
        Write-Log ("Hardware: {0} {1} | BIOS {2} | RAM {3} GB" -f $cs.Manufacturer, $cs.Model, $bios.SMBIOSBIOSVersion, $ram)
        if ($ram -lt 4) { Write-Log 'Compatibility: less than 4 GB RAM (Windows 11 minimum is 4 GB).' 'WARN' }
        try {
            $tpm = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
            Write-Log ("TPM present: {0}, spec {1}" -f [bool]$tpm, $tpm.SpecVersion)
        } catch { Write-Log 'Compatibility: TPM could not be read in WinPE (Windows 11 needs TPM 2.0).' 'WARN' }
        foreach ($b in @(Get-CimInstance Win32_PnPEntity | Where-Object { $_.ConfigManagerErrorCode -ne 0 })) {
            Write-Log ("Device without working driver: {0} [{1}] code {2}" -f $b.Name, $b.PNPDeviceID, $b.ConfigManagerErrorCode) 'WARN'
        }
        $nic = @(Get-CimInstance Win32_NetworkAdapter -Filter 'PhysicalAdapter=TRUE')
        Write-Log "Network adapters detected: $($nic.Count)"
        return $nic.Count
    } catch { Write-Log "Hardware report failed: $($_.Exception.Message)" 'WARN'; return 0 }
}

function Import-Drivers {
    param([string]$Category)
    $root = Join-Path $script:UsbRoot ('AutoInstall\Drivers\' + $script:Cfg['Windows.Architecture'])
    $dir = Join-Path $root $Category
    if (-not (Test-Path $dir)) { Write-Log "No driver folder: $dir" 'WARN'; return 0 }
    $ok = 0
    foreach ($inf in Get-ChildItem $dir -Filter *.inf -Recurse) {
        $out = & drvload.exe $inf.FullName 2>&1
        if ($LASTEXITCODE -eq 0) { $ok++; Write-Log "Driver loaded: $($inf.FullName)" }
        else { Write-Log "Driver FAILED to load: $($inf.FullName) -> $out" 'WARN' }
    }
    Write-Log "Drivers loaded from ${dir}: $ok"
    return $ok
}

# ---------- Storage ----------
function Get-CandidateDisks {
    param([int64]$MinBytes, [int[]]$ExcludeNumbers)
    return @(Get-Disk | Where-Object { $_.BusType -ne 'USB' -and ($ExcludeNumbers -notcontains $_.Number) -and (-not $_.IsReadOnly) -and $_.Size -ge $MinBytes })
}

function Show-DiskLayout {
    param($d)
    Write-Host ("`n  Disk {0}: {1} | {2} GB | {3} | {4} | Serial: {5}" -f $d.Number, $d.FriendlyName, [math]::Round($d.Size / 1GB, 1), $d.PartitionStyle, $d.BusType, "$($d.SerialNumber)".Trim())
    $ps = @(Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue)
    if ($ps.Count -eq 0) { Write-Host '     (no partitions)' }
    foreach ($p in $ps) {
        $v = Get-Volume -Partition $p -ErrorAction SilentlyContinue
        Write-Host ('     #{0}  {1,8} GB  {2,-9} {3,-6} {4} {5}' -f $p.PartitionNumber, [math]::Round($p.Size / 1GB, 1), $p.Type, $v.FileSystem, $v.FileSystemLabel, $p.DriveLetter)
    }
    Write-Host ('     Largest unallocated block: {0} GB' -f [math]::Round($d.LargestFreeExtent / 1GB, 1))
}

function Select-TargetDisk {
    param($Disks, [string]$Spec, [switch]$ForceMenu)
    $list = @($Disks)
    if ($Spec -match '^Number:(\d+)$') { $n = [int]$Matches[1]; return (@($list | Where-Object { $_.Number -eq $n }) | Select-Object -First 1) }
    if ($Spec -match '^Serial:(.+)$')  { $s = $Matches[1].Trim(); $m = @($list | Where-Object { "$($_.SerialNumber)".Trim() -eq $s }); if ($m.Count -eq 1) { return $m[0] } else { return $null } }
    if ($Spec -match '^Model:(.+)$')   { $s = $Matches[1].Trim(); $m = @($list | Where-Object { $_.FriendlyName -like "*$s*" }); if ($m.Count -eq 1) { return $m[0] } else { return $null } }
    if ($list.Count -eq 1 -and -not $ForceMenu) { return $list[0] }
    Write-Host "`nSeveral possible target disks (or an explicit choice is required):" -ForegroundColor Yellow
    foreach ($d in $list) { Show-DiskLayout $d }
    $n = Read-Host "`nType the disk NUMBER to use (Enter = manual Setup)"
    if ($n -notmatch '^\d+$') { return $null }
    return (@($list | Where-Object { $_.Number -eq [int]$n }) | Select-Object -First 1)
}

function New-DeployPlan {
    param($Disk, [hashtable]$C, [string]$Layout)
    $need = [int64]$C['Storage.WindowsSizeGB'] * 1GB
    $headroom = [int64]$C['Storage.ShrinkHeadroomGB'] * 1GB
    $parts = @(Get-Partition -DiskNumber $Disk.Number -ErrorAction SilentlyContinue)
    $plan = [pscustomobject]@{ Disk = $Disk; Layout = $Layout; Action = ''; Shrink = $null; NeedEsp = $false; NeedBytes = $need; TotalBytes = $need; Description = ''; Warnings = @() }
    $strategy = $C['Storage.Strategy']
    $warn = New-Object System.Collections.Generic.List[string]

    # possibly-encrypted / unreadable data partitions
    foreach ($p in $parts) {
        if (@('Basic', 'IFS', 'Logical', 'Unknown') -notcontains "$($p.Type)") { continue }
        if ($p.Size -lt 1GB) { continue }
        $v = Get-Volume -Partition $p -ErrorAction SilentlyContinue
        if (-not $v -or -not $v.FileSystem) { $warn.Add("Partition #$($p.PartitionNumber) cannot be read (BitLocker-locked, RAW or unformatted). It will not be touched.") }
    }
    if ($warn.Count -gt 0 -and $C['Security.BitLockerPolicy'] -eq 'Abort') { throw 'Unreadable (possibly BitLocker-encrypted) partitions exist and Security.BitLockerPolicy=Abort.' }

    if ($strategy -eq 'CleanDisk') {
        $plan.Action = 'Clean'; $plan.NeedEsp = $true
        $plan.TotalBytes = $need + 600MB
        $plan.Description = "ERASE EVERYTHING on disk $($Disk.Number) and install Windows ($($C['Storage.WindowsSizeGB']) GB partition)."
        $plan.Warnings = @($warn)
        return $plan
    }

    $blank = ($Disk.PartitionStyle -eq 'RAW') -or ($parts.Count -eq 0)
    $wantStyle = 'GPT'; if ($Layout -eq 'BIOS') { $wantStyle = 'MBR' }
    if (-not $blank -and $Disk.PartitionStyle -ne $wantStyle) {
        throw "Disk $($Disk.Number) is $($Disk.PartitionStyle) but this PC booted in $Layout mode (needs $wantStyle). Not converting automatically because that would destroy data."
    }
    $extra = 0
    if ($Layout -eq 'UEFI') {
        $hasEsp = @($parts | Where-Object { "$($_.GptType)" -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' }).Count -gt 0
        if (-not $hasEsp) { $plan.NeedEsp = $true; $extra = 300MB }
    } else {
        if ($parts.Count -ge 4) { throw 'MBR disk already has 4 partitions; cannot add another primary partition.' }
        $hasActive = @($parts | Where-Object { $_.IsActive }).Count -gt 0
        if (-not $hasActive) { $plan.NeedEsp = $true; $extra = 600MB }
    }
    $plan.TotalBytes = $need + $extra

    if ($blank) {
        if ($Disk.Size -lt $plan.TotalBytes) { throw 'Disk is too small for the requested size.' }
        $plan.Action = 'Blank'
        $plan.Description = "Disk $($Disk.Number) is empty: create boot partitions + a $($C['Storage.WindowsSizeGB']) GB Windows partition."
    }
    elseif ($Disk.LargestFreeExtent -ge $plan.TotalBytes) {
        $plan.Action = 'Free'
        $plan.Description = "Use existing unallocated space on disk $($Disk.Number) for a $($C['Storage.WindowsSizeGB']) GB Windows partition. Existing partitions are not modified."
    }
    elseif ($strategy -eq 'ShrinkIfNeeded') {
        $best = $null; $bestRoom = 0
        foreach ($p in $parts) {
            if (-not $p.DriveLetter) { continue }
            $v = Get-Volume -Partition $p -ErrorAction SilentlyContinue
            if (-not $v -or $v.FileSystem -ne 'NTFS') { continue }
            $sup = Get-PartitionSupportedSize -DriveLetter $p.DriveLetter -ErrorAction SilentlyContinue
            if (-not $sup) { continue }
            $room = $p.Size - $sup.SizeMin - $headroom
            if ($room -ge $plan.TotalBytes -and $room -gt $bestRoom) { $best = $p; $bestRoom = $room }
        }
        if (-not $best) { throw "Not enough unallocated space for $($C['Storage.WindowsSizeGB']) GB and no NTFS volume can be shrunk safely." }
        $plan.Action = 'Shrink'; $plan.Shrink = $best
        $plan.Description = "SHRINK drive $($best.DriveLetter): by $([math]::Round($plan.TotalBytes / 1GB, 1)) GB (files are kept) and create the Windows partition in the freed space."
    }
    else { throw "Not enough unallocated space for $($C['Storage.WindowsSizeGB']) GB and Strategy=UseFreeSpace forbids shrinking." }
    $plan.Warnings = @($warn)
    return $plan
}

function Invoke-DeployPlan {
    param($Plan, [hashtable]$C)
    $d = $Plan.Disk
    $created = New-Object System.Collections.Generic.List[object]
    $shrunk = $null
    $espGuid = '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'
    $msrGuid = '{e3c9e316-0b5c-4db8-817d-f92df00215ae}'
    $style = 'GPT'; if ($Plan.Layout -eq 'BIOS') { $style = 'MBR' }
    try {
        if ($Plan.Action -eq 'Clean') {
            Write-Log "Clearing disk $($d.Number)" 'WARN'
            Clear-Disk -Number $d.Number -RemoveData -RemoveOEM -Confirm:$false
        }
        $cur = Get-Disk -Number $d.Number
        if ($Plan.Action -eq 'Blank' -and $cur.PartitionStyle -ne 'RAW' -and $cur.PartitionStyle -ne $style) {
            Clear-Disk -Number $d.Number -RemoveData -Confirm:$false     # disk has no partitions; only the label style changes
            $cur = Get-Disk -Number $d.Number
        }
        if ($cur.PartitionStyle -eq 'RAW') { Initialize-Disk -Number $d.Number -PartitionStyle $style }

        if ($Plan.Action -eq 'Shrink') {
            $p = $Plan.Shrink
            $orig = $p.Size
            Resize-Partition -DriveLetter $p.DriveLetter -Size ($orig - $Plan.TotalBytes)
            $shrunk = @{ Letter = $p.DriveLetter; Size = $orig }
            Write-Log "Shrunk $($p.DriveLetter): from $orig bytes"
        }
        if ($Plan.NeedEsp) {
            if ($Plan.Layout -eq 'UEFI') {
                $esp = New-Partition -DiskNumber $d.Number -Size 260MB -GptType $espGuid
                $created.Add($esp)
                Format-Volume -Partition $esp -FileSystem FAT32 -NewFileSystemLabel 'System' -Confirm:$false | Out-Null
                $msr = New-Partition -DiskNumber $d.Number -Size 16MB -GptType $msrGuid
                $created.Add($msr)
            } else {
                $sr = New-Partition -DiskNumber $d.Number -Size 500MB -IsActive
                $created.Add($sr)
                Format-Volume -Partition $sr -FileSystem NTFS -NewFileSystemLabel 'System Reserved' -Confirm:$false | Out-Null
            }
        }
        if ((Get-Disk -Number $d.Number).LargestFreeExtent -lt $Plan.NeedBytes) { throw 'Free-space check failed after preparation.' }
        $wp = New-Partition -DiskNumber $d.Number -Size $Plan.NeedBytes
        $created.Add($wp)
        Format-Volume -Partition $wp -FileSystem NTFS -NewFileSystemLabel $C['Storage.VolumeLabel'] -Confirm:$false | Out-Null
        Write-Log "Windows partition ready: disk $($d.Number) partition $($wp.PartitionNumber)"
        return $wp
    } catch {
        Write-Log "Partitioning failed: $($_.Exception.Message) - rolling back" 'ERROR'
        foreach ($p in @($created | Sort-Object PartitionNumber -Descending)) {
            try { Remove-Partition -DiskNumber $d.Number -PartitionNumber $p.PartitionNumber -Confirm:$false -ErrorAction Stop; Write-Log "Rollback: removed partition $($p.PartitionNumber)" }
            catch { Write-Log "Rollback could not remove partition $($p.PartitionNumber): $($_.Exception.Message)" 'WARN' }
        }
        if ($shrunk) {
            try { $max = (Get-PartitionSupportedSize -DriveLetter $shrunk.Letter).SizeMax; Resize-Partition -DriveLetter $shrunk.Letter -Size $max; Write-Log "Rollback: re-extended $($shrunk.Letter):" }
            catch { Write-Log "Rollback could not re-extend $($shrunk.Letter): $($_.Exception.Message)" 'WARN' }
        }
        throw
    }
}

function Test-MediaImage {
    param([hashtable]$C)
    $wim = Join-Path $script:UsbRoot 'sources\install.wim'
    if (-not (Test-Path $wim)) { Write-Log 'Install image is split or not a .wim; skipping edition check.' 'WARN'; return }
    $imgs = @(Get-WindowsImage -ImagePath $wim)
    if ($C['Windows.Edition'] -ne '' -and -not ($imgs | Where-Object { $_.ImageName -eq $C['Windows.Edition'] })) { throw "Edition '$($C['Windows.Edition'])' is not in the install image." }
    if ($C['Windows.Edition'] -eq '' -and -not ($imgs | Where-Object { $_.ImageIndex -eq [int]$C['Windows.ImageIndex'] })) { throw "Image index $($C['Windows.ImageIndex']) is not in the install image." }
    $info = Get-WindowsImage -ImagePath $wim -Index $imgs[0].ImageIndex
    $a = ConvertTo-ArchName $info.Architecture
    if ($a -ne $C['Windows.Architecture']) { throw "Install image is $a but config says $($C['Windows.Architecture'])." }
}

# ---------- main ----------
try {
    Clear-Host
    Write-Host '=== Universal Windows Installer ===' -ForegroundColor Cyan

    $cv = Get-Volume | Where-Object { $_.DriveLetter -and (Test-Path "$($_.DriveLetter):\AutoInstall\config.ini") } | Select-Object -First 1
    if (-not $cv) { Start-ManualSetup 'AutoInstall\config.ini not found on any volume.' }
    $script:UsbRoot = "$($cv.DriveLetter):\"
    $C = Merge-Config (Read-IniText (Get-Content (Join-Path $script:UsbRoot 'AutoInstall\config.ini')))
    $script:Cfg = $C
    $chk = Test-DeployConfig $C
    foreach ($w in $chk.Warnings) { Write-Log $w 'WARN' }
    if ($chk.Errors.Count -gt 0) {
        foreach ($x in $chk.Errors) { Write-Log "CONFIG: $x" 'ERROR' }
        Stop-WithError 'config.ini is invalid. Nothing was changed.'
    }

    switch ($C['General.Mode']) {
        'Interactive' { Start-ManualSetup 'Mode=Interactive' }
        'Technician'  { Start-Technician }
    }

    $peArch = Get-PEArch
    if ($peArch -ne $C['Windows.Architecture']) { Stop-WithError "Media is built for $($C['Windows.Architecture']) but this environment is $peArch." }
    $fw = Get-FirmwareMode
    if ($C['Storage.BootMode'] -ne 'Auto' -and $C['Storage.BootMode'] -ne $fw) { Stop-WithError "config says BootMode=$($C['Storage.BootMode']) but this PC booted in $fw mode." }
    if ($C['Windows.Architecture'] -eq 'x86' -and $fw -eq 'UEFI') { Stop-WithError 'x86 media is not supported on UEFI-booted PCs.' }
    $layout = $fw
    if ($C['Security.RequireSecureBoot'] -eq 'true' -and $fw -eq 'UEFI' -and -not (Get-SecureBootState)) { Stop-WithError 'Secure Boot is required by config but is not enabled.' }
    Write-Log "Firmware: $fw, WinPE arch: $peArch"

    try { Test-MediaImage $C } catch { Stop-WithError "Install image check failed: $($_.Exception.Message)" }

    $nicCount = Write-HardwareReport

    Get-Disk | Where-Object { $_.IsOffline } | ForEach-Object { try { Set-Disk -Number $_.Number -IsOffline $false } catch {} }
    $usbNums = @()
    try { $usbNums += (Get-Partition -DriveLetter $cv.DriveLetter).DiskNumber } catch {}
    $minBytes = [int64]$C['Storage.WindowsSizeGB'] * 1GB + 1GB
    $disks = @(Get-CandidateDisks -MinBytes $minBytes -ExcludeNumbers $usbNums)
    if ($disks.Count -eq 0 -and $C['Drivers.Enable'] -eq 'true') {
        Write-Log 'No usable internal disk visible: trying storage drivers from the USB' 'WARN'
        [void](Import-Drivers 'storage')
        Start-Sleep 3
        try { Update-HostStorageCache } catch {}
        $disks = @(Get-CandidateDisks -MinBytes $minBytes -ExcludeNumbers $usbNums)
    }
    if ($nicCount -eq 0 -and $C['Drivers.Enable'] -eq 'true') { [void](Import-Drivers 'network') }
    if ($disks.Count -eq 0) { Stop-WithError "No usable internal disk (at least $($C['Storage.WindowsSizeGB']) GB + 1 GB) was found. A storage driver may be missing." }

    $force = ($C['Storage.Strategy'] -eq 'CleanDisk')
    $target = Select-TargetDisk -Disks $disks -Spec $C['Storage.TargetDisk'] -ForceMenu:$force
    if (-not $target) { Stop-WithError 'Target disk could not be identified unambiguously. Nothing was changed.' }
    Show-DiskLayout $target
    Write-Log ("Target disk: #{0} {1} serial {2} id {3} size {4}" -f $target.Number, $target.FriendlyName, "$($target.SerialNumber)".Trim(), $target.UniqueId, $target.Size)

    $plan = New-DeployPlan -Disk $target -C $C -Layout $layout
    Write-Host "`nPLAN: $($plan.Description)" -ForegroundColor Green
    foreach ($w in $plan.Warnings) { Write-Host "  ! $w" -ForegroundColor Yellow; Write-Log $w 'WARN' }
    Write-Host ("Edition: {0}   Layout: {1}   Mode: {2}`n" -f $C['Windows.Edition'], $layout, $C['General.Mode'])
    Write-Log "PLAN: $($plan.Description)"

    if ($C['General.DryRun'] -eq 'true') {
        Write-Host 'DRY RUN: nothing has been changed.' -ForegroundColor Cyan
        [void](Read-Host 'Press Enter to continue to normal Windows Setup')
        Start-ManualSetup 'Dry run finished.'
    }

    if ($plan.Action -eq 'Clean') {
        $expect = "ERASE $($target.Number)"
        if ((Read-Host "This ERASES disk $($target.Number) ($($target.FriendlyName)). Type '$expect' to continue") -cne $expect) { Start-ManualSetup 'Erase not confirmed.' }
    }
    elseif ($C['General.Mode'] -eq 'SemiAuto' -or $C['General.ConfirmBeforeChange'] -eq 'true') {
        if ((Read-Host 'Type YES to apply this plan, or just press Enter for manual Setup') -ne 'YES') { Start-ManualSetup 'Plan not confirmed.' }
    }

    $fresh = Get-Disk -Number $target.Number
    if ($fresh.UniqueId -ne $target.UniqueId -or $fresh.Size -ne $target.Size) { Stop-WithError 'Disk identity changed between plan and execution. Aborting without changes.' }

    $wp = Invoke-DeployPlan -Plan $plan -C $C

    $dp = @()
    $drvDir = Join-Path $script:UsbRoot ('AutoInstall\Drivers\' + $C['Windows.Architecture'])
    if ($C['Drivers.Enable'] -eq 'true' -and (Test-Path $drvDir) -and (Get-ChildItem $drvDir -Filter *.inf -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1)) { $dp = @($drvDir) }

    $xml = New-AnswerFileXml -C $C -DiskId $target.Number -PartitionId $wp.PartitionNumber -DriverPaths $dp
    Set-Content -Path 'X:\auto\autounattend.xml' -Value $xml -Encoding UTF8
    Write-Log 'Answer file generated and validated.'

    if ($C['General.Mode'] -eq 'SemiAuto') { [void](Read-Host 'Disk is ready. Press Enter to start Windows Setup') }
    Write-Log 'Starting Setup with answer file'
    Copy-LogToUsb
    Start-Process 'X:\sources\setup.exe' -ArgumentList '/unattend:X:\auto\autounattend.xml' -Wait
    Copy-LogToUsb
    exit
}
catch {
    Stop-WithError "Unexpected error: $($_.Exception.Message)"
}
'@

# ======================================================================================
#  MODULE 6 - USB BUILDER
# ======================================================================================
function Select-UsbDrive {
    $cands = @(Get-Disk | Where-Object { $_.BusType -eq 'USB' })
    if ($cands.Count -eq 0) { throw 'No USB disk found.' }
    foreach ($d in $cands) {
        $letters = (Get-Partition -DiskNumber $d.Number -ErrorAction SilentlyContinue | Where-Object { $_.DriveLetter } | ForEach-Object { "$($_.DriveLetter):" }) -join ' '
        Write-Host ("  Disk {0}: {1}  {2} GB  volumes: {3}" -f $d.Number, $d.FriendlyName, [math]::Round($d.Size / 1GB, 1), $letters)
    }
    $l = Read-Host 'Drive letter of the USB to ERASE'
    return $l.Trim().TrimEnd(':').ToUpper()
}

function New-BuildConfig {
    $c = Get-ConfigDefaults
    if ($ConfigFile) {
        if (-not (Test-Path -LiteralPath $ConfigFile)) { throw "ConfigFile not found: $ConfigFile" }
        $c = Merge-Config (Read-IniText (Get-Content -LiteralPath $ConfigFile))
    }
    $map = @{ Mode = 'General.Mode'; Language = 'General.Language'; TimeZone = 'General.TimeZone'; ProductKey = 'Windows.ProductKey'
              Strategy = 'Storage.Strategy'; WindowsSizeGB = 'Storage.WindowsSizeGB'; TargetDisk = 'Storage.TargetDisk' }
    foreach ($p in $map.Keys) {
        if ($script:Bound.ContainsKey($p)) { $c[$map[$p]] = [string](Get-Variable -Name $p -Scope Script -ValueOnly) }
    }
    if ($script:Bound.ContainsKey('ConfirmBeforeChange')) { $c['General.ConfirmBeforeChange'] = "$ConfirmBeforeChange".ToLower() }
    if ($DeployDryRun) { $c['General.DryRun'] = 'true' }
    $c['Windows.Architecture'] = $ctx.Arch
    if ($ctx.Edition) { $c['Windows.Edition'] = $ctx.Edition.ImageName; $c['Windows.ImageIndex'] = '' }
    elseif ($Edition) { $c['Windows.Edition'] = $Edition }
    elseif ($ImageIndex -gt 0) { $c['Windows.ImageIndex'] = "$ImageIndex" }
    $c['Storage.BootMode'] = switch ($BootProfile) { 'UEFI' { 'UEFI' } 'BIOS' { 'BIOS' } 'Hybrid' { 'Auto' } }
    return $c
}

function Test-UsbSpace {
    $iso = $ctx.Iso
    $need = $iso.SizeBytes + 1GB
    if ($iso.Format -eq 'ESD') { $need = [int64]($iso.ImageBytes * 1.8) + ($iso.SizeBytes - $iso.ImageBytes) + 1GB }
    $usable = [math]::Min($ctx.UsbDisk.Size, 32GB)
    if ($usable -lt $need) { throw ("USB is too small: need about {0} GB, usable {1} GB (FAT32 partitions are capped at 32 GB here)." -f [math]::Round($need / 1GB, 1), [math]::Round($usable / 1GB, 1)) }
    $qual = Split-Path -Qualifier $WorkRoot
    $free = ([IO.DriveInfo]::new($qual)).AvailableFreeSpace
    $work = 2GB
    if ($iso.Format -eq 'ESD') { $work = [int64]($iso.ImageBytes * 1.8) + 2GB }
    if ($free -lt $work) { throw ("Not enough free space for temporary files on {0} (need about {1} GB). Use -WorkRoot on another drive." -f $qual, [math]::Round($work / 1GB, 1)) }
}

function Initialize-Usb {
    $d = $ctx.UsbDisk
    $style = 'GPT'; if ($BootProfile -ne 'UEFI') { $style = 'MBR' }
    if ($d.PartitionStyle -ne 'RAW') { Clear-Disk -Number $d.Number -RemoveData -RemoveOEM -Confirm:$false }
    Initialize-Disk -Number $d.Number -PartitionStyle $style
    $np = @{ DiskNumber = $d.Number; DriveLetter = [char]$ctx.UsbLetter }
    if ($d.Size -gt 32GB) { $np.Size = 32GB } else { $np.UseMaximumSize = $true }
    if ($style -eq 'MBR') { $np.IsActive = $true }
    $p = New-Partition @np
    Format-Volume -Partition $p -FileSystem FAT32 -NewFileSystemLabel 'WINAUTO' -Confirm:$false | Out-Null
    if ($BootProfile -ne 'UEFI') {
        $bs = Join-Path $ctx.Iso.Root 'boot\bootsect.exe'
        if (-not (Test-Path $bs)) { throw 'boot\bootsect.exe not found in the ISO; cannot make legacy BIOS boot sector.' }
        Invoke-Native $bs @('/nt60', "$($ctx.UsbLetter):", '/force', '/mbr')
    }
}

function Copy-WindowsFiles {
    $iso = $ctx.Iso; $usb = "$($ctx.UsbLetter):\"
    Invoke-Native 'robocopy.exe' @($iso.Root, $usb, '/E', '/R:2', '/W:2', '/NFL', '/NDL', '/NJH', '/NJS', '/NP', '/XF', 'install.wim', 'install.esd', 'install.swm', 'install*.swm') -OkCodes (0..7)
}

function Copy-InstallImage {
    $iso = $ctx.Iso; $usb = "$($ctx.UsbLetter):\sources"
    $wim = $null
    switch ($iso.Format) {
        'SWM' { Copy-Item (Join-Path (Split-Path $iso.File) 'install*.swm') $usb; return }
        'ESD' {
            $idx = 1; if ($ctx.Edition) { $idx = $ctx.Edition.ImageIndex }
            $wim = Join-Path $ctx.Work 'install.wim'
            Write-Log "Converting ESD index $idx to WIM (slow, be patient)"
            Invoke-Native 'dism.exe' @('/Export-Image', "/SourceImageFile:$($iso.File)", "/SourceIndex:$idx", "/DestinationImageFile:$wim", '/Compress:max', '/CheckIntegrity')
            $ctx.ExportedSingle = $true
        }
        default { $wim = $iso.File }
    }
    $size = (Get-Item -LiteralPath $wim).Length
    if ($size -gt (4GB - 64MB)) {
        Write-Log 'install.wim is over the FAT32 file limit; splitting'
        Invoke-Native 'dism.exe' @('/Split-Image', "/ImageFile:$wim", "/SWMFile:$usb\install.swm", '/FileSize:3800')
    } else {
        Copy-Item -LiteralPath $wim "$usb\install.wim"
    }
}

function Test-PayloadSyntax {
    param([string]$Code)
    $t = $null; $e = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($Code, [ref]$t, [ref]$e)
    if ($e.Count -gt 0) { throw "Payload script has syntax errors: $($e[0].Message) (line $($e[0].Extent.StartLineNumber))" }
}

function Update-BootImage {
    $usb = "$($ctx.UsbLetter):\sources"
    $boot = Join-Path $ctx.Work 'boot.wim'
    Copy-Item "$usb\boot.wim" $boot
    Set-ItemProperty -LiteralPath $boot -Name IsReadOnly -Value $false
    $mnt = Join-Path $ctx.Work 'mount'
    New-Item -ItemType Directory -Path $mnt | Out-Null
    $payload = $CommonCode + "`r`n" + $RuntimeCode
    Test-PayloadSyntax $payload
    Mount-WindowsImage -ImagePath $boot -Index 2 -Path $mnt | Out-Null
    $saved = $false
    try {
        foreach ($c in 'WinPE-WMI', 'WinPE-NetFX', 'WinPE-Scripting', 'WinPE-PowerShell', 'WinPE-StorageWMI', 'WinPE-DismCmdlets') {
            $cab = Join-Path $ctx.Adk.OCPath "$c.cab"
            if (-not (Test-Path $cab)) { throw "ADK component missing: $cab" }
            Write-Log "Adding $c"
            Add-WindowsPackage -Path $mnt -PackagePath $cab | Out-Null
            $lang = Join-Path $ctx.Adk.OCPath "en-us\${c}_en-us.cab"
            if (Test-Path $lang) { Add-WindowsPackage -Path $mnt -PackagePath $lang | Out-Null }
        }
        if ($ctx.Drivers -and (Test-Path $ctx.Drivers.WinPEDir)) {
            try { Add-WindowsDriver -Path $mnt -Driver $ctx.Drivers.WinPEDir -Recurse | Out-Null; Write-Log 'WinPE drivers injected' }
            catch { Add-Note "WinPE driver injection failed: $($_.Exception.Message)" }
        }
        New-Item -ItemType Directory -Path "$mnt\auto" | Out-Null
        Set-Content -LiteralPath "$mnt\auto\auto-partition.ps1" -Value $payload -Encoding UTF8
        Set-Content -LiteralPath "$mnt\auto\run.cmd" -Encoding ASCII -Value @('@echo off', 'wpeinit', 'powershell -NoProfile -ExecutionPolicy Bypass -File X:\auto\auto-partition.ps1')
        Set-Content -LiteralPath "$mnt\Windows\System32\winpeshl.ini" -Encoding ASCII -Value @('[LaunchApps]', '%SYSTEMDRIVE%\auto\run.cmd')
        Dismount-WindowsImage -Path $mnt -Save | Out-Null
        $saved = $true
    } finally {
        if (-not $saved) { Dismount-WindowsImage -Path $mnt -Discard -ErrorAction SilentlyContinue | Out-Null }
    }
    Copy-Item $boot "$usb\boot.wim" -Force
}

function Write-UsbPayload {
    $usb = "$($ctx.UsbLetter):\"
    New-Item -ItemType Directory -Path "$usb`AutoInstall" -Force | Out-Null
    Set-Content -LiteralPath "$usb`AutoInstall\config.ini" -Value (ConvertTo-IniText $ctx.Config) -Encoding ASCII

    if ($ctx.Drivers -and $ctx.Drivers.Included.Count -gt 0) {
        $dest = Join-Path $usb "AutoInstall\Drivers\$($ctx.Arch)"
        foreach ($dir in $ctx.Drivers.Included) {
            $rel = $dir.Substring($ctx.Drivers.ArchDir.Length).TrimStart('\', '/')
            Invoke-Native 'robocopy.exe' @($dir, (Join-Path $dest $rel), '/E', '/R:2', '/W:2', '/NFL', '/NDL', '/NJH', '/NJS', '/NP') -OkCodes (0..7)
        }
        $manifest = $ctx.Drivers.Included | ForEach-Object { $_ }
        Set-Content -LiteralPath "$usb`AutoInstall\Drivers\drivers-included.txt" -Value $manifest -Encoding UTF8
    }
    if ($ctx.Post -and $ctx.Post.Count -gt 0) {
        $oem = Join-Path $usb 'sources\$OEM$'
        $pd = Join-Path $oem '$1\AutoInstall\PostInstall'
        $sc = Join-Path $oem '$$\Setup\Scripts'
        New-Item -ItemType Directory -Path $pd, $sc -Force | Out-Null
        foreach ($i in $ctx.Post) { Copy-Item -LiteralPath $i.Path (Join-Path $pd $i.File) }
        $json = [pscustomobject]@{ items = @($ctx.Post | ForEach-Object { [pscustomobject]@{ file = $_.File; sha256 = $_.Sha256 } }) } | ConvertTo-Json -Depth 4
        Set-Content -LiteralPath (Join-Path $pd 'allowlist.json') -Value $json -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $pd 'run.ps1') -Value $PostInstallRunner -Encoding UTF8
        Set-Content -LiteralPath (Join-Path $sc 'SetupComplete.cmd') -Encoding ASCII -Value @('@echo off', 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SystemDrive%\AutoInstall\PostInstall\run.ps1"')
    }
}

function Test-FinalUsb {
    $usb = "$($ctx.UsbLetter):\"
    $need = @('sources\boot.wim', 'AutoInstall\config.ini', 'setup.exe')
    if ($BootProfile -ne 'BIOS') { $need += $ctx.EfiFile }
    if ($BootProfile -ne 'UEFI') { $need += 'bootmgr' }
    foreach ($f in $need) { if (-not (Test-Path (Join-Path $usb $f))) { throw "Verification failed: $f is missing on the USB." } }
    if (-not ((Test-Path "$usb`sources\install.wim") -or (Test-Path "$usb`sources\install.swm"))) { throw 'Verification failed: no install image on the USB.' }
    if ($BootProfile -ne 'UEFI') {
        $p = Get-Partition -DriveLetter $ctx.UsbLetter
        if (-not $p.IsActive) { throw 'Verification failed: USB partition is not marked active (legacy BIOS boot would fail).' }
    }
    $back = Merge-Config (Read-IniText (Get-Content "$usb`AutoInstall\config.ini"))
    $chk = Test-DeployConfig $back
    if ($chk.Errors.Count -gt 0) { throw "Verification failed: config.ini on the USB is invalid: $($chk.Errors -join '; ')" }
    $mnt = Join-Path $ctx.Work 'verify'
    New-Item -ItemType Directory -Path $mnt | Out-Null
    Mount-WindowsImage -ImagePath "$usb`sources\boot.wim" -Index 2 -Path $mnt -ReadOnly | Out-Null
    try {
        foreach ($f in 'auto\auto-partition.ps1', 'auto\run.cmd', 'Windows\System32\winpeshl.ini', 'Windows\System32\WindowsPowerShell\v1.0\powershell.exe') {
            if (-not (Test-Path (Join-Path $mnt $f))) { throw "Verification failed: boot.wim lacks $f" }
        }
    } finally { Dismount-WindowsImage -Path $mnt -Discard | Out-Null }
    $hash = (Get-FileHash "$usb`sources\boot.wim" -Algorithm SHA256).Hash
    Write-Log "boot.wim SHA-256: $hash"
    Write-Log 'Final verification passed'
}

# ======================================================================================
#  MODULE 9 - SELF-TEST (no disks, no ISO, no admin needed)
# ======================================================================================
function Invoke-SelfTest {
    $script:tPass = 0; $script:tFail = 0
    function T {
        param([string]$Name, [scriptblock]$Test)
        try { if (& $Test) { $script:tPass++; Write-Host "  PASS  $Name" -ForegroundColor Green } else { $script:tFail++; Write-Host "  FAIL  $Name" -ForegroundColor Red } }
        catch { $script:tFail++; Write-Host "  FAIL  $Name  ($($_.Exception.Message))" -ForegroundColor Red }
    }
    Write-Host "`nSelf-test`n"
    $ok = Get-ConfigDefaults; $ok['Windows.Edition'] = 'Windows 11 Pro'
    T 'defaults without edition are rejected'      { (Test-DeployConfig (Get-ConfigDefaults)).Errors.Count -ge 1 }
    T 'valid config passes'                        { (Test-DeployConfig $ok).Errors.Count -eq 0 }
    T 'bad Mode rejected'                          { $c = $ok.Clone(); $c['General.Mode'] = 'Foo'; (Test-DeployConfig $c).Errors.Count -ge 1 }
    T 'non-numeric size rejected'                  { $c = $ok.Clone(); $c['Storage.WindowsSizeGB'] = 'abc'; (Test-DeployConfig $c).Errors.Count -ge 1 }
    T 'malformed product key rejected'             { $c = $ok.Clone(); $c['Windows.ProductKey'] = 'ABC'; (Test-DeployConfig $c).Errors.Count -ge 1 }
    T 'bad TargetDisk rejected'                    { $c = $ok.Clone(); $c['Storage.TargetDisk'] = 'whatever'; (Test-DeployConfig $c).Errors.Count -ge 1 }
    T 'arm64 + BIOS rejected'                      { $c = $ok.Clone(); $c['Windows.Architecture'] = 'arm64'; $c['Storage.BootMode'] = 'BIOS'; (Test-DeployConfig $c).Errors.Count -ge 1 }
    T 'x86 + UEFI rejected'                        { $c = $ok.Clone(); $c['Windows.Architecture'] = 'x86'; $c['Storage.BootMode'] = 'UEFI'; (Test-DeployConfig $c).Errors.Count -ge 1 }
    T 'CleanDisk produces a warning'               { $c = $ok.Clone(); $c['Storage.Strategy'] = 'CleanDisk'; (Test-DeployConfig $c).Warnings.Count -ge 1 }
    T 'INI round trip keeps values'                { $c = $ok.Clone(); $c['Storage.WindowsSizeGB'] = '150'; $b = Merge-Config (Read-IniText ((ConvertTo-IniText $c) -split "`n")); $b['Storage.WindowsSizeGB'] -eq '150' -and $b['Windows.Edition'] -eq 'Windows 11 Pro' }
    T 'answer file x64 is valid XML'               { $x = [xml](New-AnswerFileXml -C $ok -DiskId 0 -PartitionId 3); $x.unattend.settings.Count -ge 2 }
    T 'answer file carries arm64 architecture'     { $c = $ok.Clone(); $c['Windows.Architecture'] = 'arm64'; (New-AnswerFileXml -C $c -DiskId 0 -PartitionId 3) -match 'processorArchitecture="arm64"' }
    T 'answer file escapes XML in edition name'    { $c = $ok.Clone(); $c['Windows.Edition'] = 'Pro & <Test>'; $x = [xml](New-AnswerFileXml -C $c -DiskId 1 -PartitionId 2); $x.OuterXml -like '*Pro &amp; &lt;Test&gt;*' }
    T 'answer file driver paths added'             { (New-AnswerFileXml -C $ok -DiskId 0 -PartitionId 3 -DriverPaths @('E:\AutoInstall\Drivers\x64')) -match 'PnpCustomizationsNonWinPE' }
    T 'answer file uses index when no edition'     { $c = $ok.Clone(); $c['Windows.Edition'] = ''; $c['Windows.ImageIndex'] = '6'; (New-AnswerFileXml -C $c -DiskId 0 -PartitionId 3) -match '/IMAGE/INDEX' }
    $eds = @([pscustomobject]@{ ImageIndex = 1; ImageName = 'Windows 11 Home' }, [pscustomobject]@{ ImageIndex = 6; ImageName = 'Windows 11 Pro' })
    T 'edition chosen by name'                     { (Select-Edition -Editions $eds -Name 'Windows 11 Pro' -NoPrompt).ImageIndex -eq 6 }
    T 'edition chosen by index'                    { (Select-Edition -Editions $eds -Index 1 -NoPrompt).ImageName -eq 'Windows 11 Home' }
    T 'unknown edition throws'                     { try { Select-Edition -Editions $eds -Name 'Nope' -NoPrompt | Out-Null; $false } catch { $true } }
    T 'ambiguous edition throws without prompt'    { try { Select-Edition -Editions $eds -NoPrompt | Out-Null; $false } catch { $true } }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('awu-selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 6))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        Set-Content "$tmp\x64.inf"     "[Version]`nSignature=`"`$Windows NT`$`"`nCatalogFile=a.cat`n[Manufacturer]`n%V%=S,NTamd64`n"
        Set-Content "$tmp\arm.inf"     "[Version]`nSignature=`"`$Windows NT`$`"`nCatalogFile=a.cat`n[Manufacturer]`n%V%=S,NTarm64`n"
        Set-Content "$tmp\neutral.inf" "[Version]`nSignature=`"`$Windows NT`$`"`nCatalogFile=a.cat`n"
        Set-Content "$tmp\nocat.inf"   "[Version]`nSignature=`"`$Windows NT`$`"`n[Manufacturer]`n%V%=S,NTamd64`n"
        Set-Content "$tmp\junk.inf"    "hello"
        T 'INF built for x64 accepted on x64'      { (Test-InfCompatible "$tmp\x64.inf" 'x64').Compatible }
        T 'INF built for x64 rejected on arm64'    { -not (Test-InfCompatible "$tmp\x64.inf" 'arm64').Compatible }
        T 'INF built for arm64 rejected on x64'    { -not (Test-InfCompatible "$tmp\arm.inf" 'x64').Compatible }
        T 'arch-neutral INF accepted'              { (Test-InfCompatible "$tmp\neutral.inf" 'x64').Compatible }
        T 'INF without catalog gives a warning'    { (Test-InfCompatible "$tmp\nocat.inf" 'x64').Warning -ne '' }
        T 'non-INF text rejected'                  { -not (Test-InfCompatible "$tmp\junk.inf" 'x64').Compatible }
    } finally { Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue }
    T 'WinPE payload parses without errors'        { Test-PayloadSyntax ($CommonCode + "`r`n" + $RuntimeCode); $true }
    T 'post-install runner parses without errors'  { Test-PayloadSyntax $PostInstallRunner; $true }
    T 'ADK build family mapping'                   { (Get-BuildFamily 26200) -eq '26100' -and (Get-BuildFamily 22631) -eq '22621' -and (Get-BuildFamily 19045) -eq '19041' }
    T 'architecture name mapping'                  { (ConvertTo-ArchName 9) -eq 'x64' -and (ConvertTo-ArchName 12) -eq 'arm64' -and (ConvertTo-ArchName 0) -eq 'x86' }
    Write-Host ("`n{0} passed, {1} failed" -f $script:tPass, $script:tFail) -ForegroundColor $(if ($script:tFail -eq 0) { 'Green' } else { 'Red' })
    if ($script:tFail -gt 0) { throw 'Self-test failed.' }
}

# ======================================================================================
#  MODULE 0 - MAIN ENTRY POINT
# ======================================================================================
$exitCode = 0
try {
    Initialize-Logging

    if ($Action -eq 'SelfTest') { Invoke-SelfTest; return }

    if ($Action -eq 'Inspect') {
        if (-not $IsoPath) { throw '-IsoPath is required.' }
        Invoke-Stage 'Preflight checks' { Test-Preflight }
        Invoke-Stage 'ISO inspection' { $ctx.Iso = Get-IsoInfo $IsoPath; Show-IsoInfo $ctx.Iso }
        return
    }

    # ----- Build pipeline -----
    if (-not $IsoPath) { throw '-IsoPath is required.' }

    Invoke-Stage '1. Preflight checks' { Test-Preflight }

    Invoke-Stage '2. ISO inspection' { $ctx.Iso = Get-IsoInfo $IsoPath; Show-IsoInfo $ctx.Iso }

    Invoke-Stage '3. Configuration validation' {
        $iso = $ctx.Iso
        $ctx.Arch = if ($Architecture -eq 'Auto') { $iso.Arch } else { $Architecture }
        if (-not $ctx.Arch) { throw 'Could not detect the image architecture; pass -Architecture.' }
        if ($iso.Arch -and $ctx.Arch -ne $iso.Arch) { throw "-Architecture $Architecture does not match the ISO ($($iso.Arch))." }
        if ($ctx.Arch -eq 'arm64' -and $BootProfile -ne 'UEFI') { throw 'arm64 supports only -BootProfile UEFI.' }
        if ($ctx.Arch -eq 'x86' -and $BootProfile -eq 'UEFI') { throw 'x86 supports only -BootProfile BIOS (or Hybrid).' }
        if ($BootProfile -ne 'BIOS') {
            $efiName = @{ x64 = 'efi\boot\bootx64.efi'; arm64 = 'efi\boot\bootaa64.efi'; x86 = 'efi\boot\bootia32.efi' }[$ctx.Arch]
            if (-not (Test-Path (Join-Path $iso.Root $efiName))) { throw "ISO has no UEFI boot file ($efiName); cannot build a $BootProfile profile." }
            $ctx.EfiFile = $efiName
        }
        if ($BootProfile -ne 'UEFI' -and -not $iso.HasBios) { throw 'ISO lacks bootmgr / boot\bootsect.exe; cannot build a legacy BIOS profile.' }
        if ($BootProfile -ne 'UEFI') { Add-Note 'BIOS/Hybrid profiles are written to follow Microsoft''s documented method but need testing on your own hardware.' }

        $ctx.Edition = Select-Edition -Editions $iso.Editions -Name $Edition -Index $ImageIndex
        if (-not $ctx.Edition -and -not $Edition -and $ImageIndex -le 0) { throw 'Split (.swm) image: editions cannot be listed, so pass -Edition or -ImageIndex.' }
        Write-Log ("Edition: {0}" -f $(if ($ctx.Edition) { "[$($ctx.Edition.ImageIndex)] $($ctx.Edition.ImageName)" } else { 'as supplied' }))

        $ctx.Adk = Get-AdkInfo $ctx.Arch
        $setupBuild = ([version](Get-WindowsImage -ImagePath $iso.BootWim -Index 2).Version).Build
        if ($ctx.Adk.Build) {
            if ((Get-BuildFamily $ctx.Adk.Build) -ne (Get-BuildFamily $setupBuild)) {
                $m = "ADK WinPE build $($ctx.Adk.Build) does not match the ISO's Setup image build $setupBuild. Install the ADK that matches this Windows release."
                if ($AllowAdkMismatch) { Add-Note "$m (continuing because -AllowAdkMismatch was given)" } else { throw $m }
            }
        } else { Add-Note 'Could not read the ADK WinPE build; version match not verified.' }

        $ctx.Config = New-BuildConfig
        $chk = Test-DeployConfig $ctx.Config
        foreach ($w in $chk.Warnings) { Add-Note $w }
        if ($chk.Errors.Count -gt 0) { throw ("Configuration invalid:`n  - " + ($chk.Errors -join "`n  - ")) }
    }

    Invoke-Stage '4. Driver and post-install validation' {
        $ctx.Drivers = $null; $ctx.Post = $null
        if ($DriverPath) {
            $ctx.Drivers = Get-DriverPlan -Root $DriverPath -Arch $ctx.Arch
            Write-Host ("  Drivers: {0} folder(s) accepted, {1} rejected" -f $ctx.Drivers.Included.Count, $ctx.Drivers.Skipped.Count)
            foreach ($s in $ctx.Drivers.Skipped) { Add-Note "Driver folder skipped: $s" }
        }
        $ctx.Config['Drivers.Enable'] = if ($ctx.Drivers -and $ctx.Drivers.Included.Count -gt 0) { 'true' } else { 'false' }
        if ($PostInstallPath) {
            $ctx.Post = Get-PostInstallPlan -Path $PostInstallPath
            Write-Host '  Post-install actions (only these exact files, verified by SHA-256, will run):'
            foreach ($i in $ctx.Post) { Write-Host ("    {0}  {1}" -f $i.Sha256.Substring(0, 12), $i.File) }
            Add-Note 'Post-install uses SetupComplete.cmd, which Windows skips for some OEM-key installs.'
        }
        $ctx.Config['PostInstall.Enable'] = if ($ctx.Post -and $ctx.Post.Count -gt 0) { 'true' } else { 'false' }
        $chk = Test-DeployConfig $ctx.Config
        if ($chk.Errors.Count -gt 0) { throw ($chk.Errors -join '; ') }
    }

    Invoke-Stage '5. USB identification and confirmation' {
        if (-not $UsbDrive) { $ctx.UsbLetter = Select-UsbDrive } else { $ctx.UsbLetter = $UsbDrive.Trim().TrimEnd(':').ToUpper() }
        $part = Get-Partition -DriveLetter $ctx.UsbLetter -ErrorAction Stop
        $ctx.UsbDisk = Get-Disk -Number $part.DiskNumber
        $d = $ctx.UsbDisk
        if ($d.BusType -ne 'USB') { throw "Drive $($ctx.UsbLetter): is on a $($d.BusType) disk, not USB. Refusing." }
        if ($d.IsBoot -or $d.IsSystem) { throw 'That disk holds the running Windows system. Refusing.' }
        Test-UsbSpace
        $ctx.Work = New-WorkDir

        $iso = $ctx.Iso
        Write-Host "`n------------------ BUILD PLAN ------------------" -ForegroundColor Cyan
        Write-Host ("  ISO       : {0}  [{1}, {2}, build {3}]" -f $iso.Path, $iso.Format, $iso.Arch, $iso.Build)
        Write-Host ("  Edition   : {0}" -f $ctx.Config['Windows.Edition'])
        Write-Host ("  Profile   : {0}  |  Target mode: {1}  |  Strategy: {2}  |  Windows size: {3} GB" -f $BootProfile, $ctx.Config['General.Mode'], $ctx.Config['Storage.Strategy'], $ctx.Config['Storage.WindowsSizeGB'])
        $delivery = switch ($iso.Format) { 'WIM' { 'copy (split automatically if > 4 GB)' } 'ESD' { 'convert selected edition ESD -> WIM, then split if needed' } 'SWM' { 'copy split files as-is' } }
        Write-Host ("  Image     : {0}" -f $delivery)
        Write-Host ("  Drivers   : {0}   Post-install: {1}" -f $(if ($ctx.Drivers) { "$($ctx.Drivers.Included.Count) folder(s)" } else { 'none' }), $(if ($ctx.Post) { "$($ctx.Post.Count) item(s)" } else { 'none' }))
        Write-Host ("  USB       : Disk {0} - {1} - {2} GB - drive {3}:  >>> WILL BE COMPLETELY ERASED <<<" -f $d.Number, $d.FriendlyName, [math]::Round($d.Size / 1GB, 1), $ctx.UsbLetter) -ForegroundColor Red
        Write-Host '------------------------------------------------'
        if ($DryRun) { Write-Host "`nDRY RUN: all checks passed, the USB was NOT touched." -ForegroundColor Green; $ctx.DryRunDone = $true; return }
        $want = "ERASE $($d.Number)"
        if ((Read-Host "Type '$want' to continue") -cne $want) { throw 'Not confirmed by the user. Nothing was changed.' }
    }
    if ($ctx.DryRunDone) { return }

    Invoke-Stage '6. USB preparation'               { Initialize-Usb }
    Invoke-Stage '7. Windows image preparation'     { Copy-WindowsFiles; Copy-InstallImage }
    Invoke-Stage '8. WinPE customization'           { Update-BootImage }
    Invoke-Stage '9. Configuration and payload'     { Write-UsbPayload }
    Invoke-Stage '10. Final USB verification'       { Test-FinalUsb }

    Write-Host "`nUSB $($ctx.UsbLetter): is ready. Boot the target PC from it." -ForegroundColor Green
}
catch {
    $exitCode = 1
    Write-Log "FATAL: $($_.Exception.Message)" 'ERROR'
}
finally {
    if ($Action -ne 'SelfTest' -and $script:Stages.Count -gt 0) { Show-Report }
    if ($ctx.IsoPath) { Dismount-DiskImage -ImagePath $ctx.IsoPath -ErrorAction SilentlyContinue | Out-Null }
    if ($ctx.Work) { Remove-WorkDir $ctx.Work }
}
exit $exitCode
