#requires -Version 3
<#
    remove-antiscam-hardened.ps1
    Field removal for AnyTech365 "AntiScam" tech-support-scam software.
    Built from the dnSpy decompile of the whole suite (see ANALYSIS_from_decompile.md).

    RUNS AS SYSTEM, LIVE, NO-REBOOT -- for REMOTE / WiFi support where Safe Mode isn't an option.

    Threat model handled (all confirmed in the decompile):
      * antiscam.check.exe (scheduled task 'antiscam.check', every 60s, SYSTEM) is a GUARDIAN:
        it RESUMES a suspended antiscam.service/antiscam.dns, and RE-RUNS antiscam.installer.exe
        if the service is disabled (Start!=2/Type!=16) or its key is deleted. => it is killed FIRST.
      * antiscam.service.exe runs two WMI watchdogs: registry self-heal (rewrites Start/Type/
        ImagePath) + Win32_ProcessStartTrace process-killer (kills ScreenConnect/Support.com tools).
        => NT-suspended so both freeze without the SCM auto-restarting the (still-alive) process.
      * Service key + \Security + IFEO + task keys owned by the service SID, Admin/SYSTEM DENIED.
        => take-ownership + ACL reset (works cleanly as SYSTEM).
      * Install dir raised to System integrity via chml ("no-write-up"). => SYSTEM (System
        integrity) can relabel/delete; chml -rl + takeown + icacls as backup.
      * Local DNS hijack (127.0.0.1) + Panorama9 RMM + "AntiScam Update Service" => all removed.

    Escalation: self-elevates via UAC, then relaunches itself as SYSTEM via a one-shot scheduled
    task (no external tools). Use -AsAdmin to stay at admin/High integrity (fallback if SYSTEM task
    creation is blocked -- less reliable against integrity-locked files). Use -EvadeName if AntiScam
    has IFEO-hijacked/blocklisted powershell.exe itself.

    USAGE (from your remote shell):  powershell -ExecutionPolicy Bypass -File .\remove-antiscam-hardened.ps1
#>
[CmdletBinding()]
param(
    [switch]$AsAdmin,          # do the work at admin/High integrity instead of escalating to SYSTEM
    [switch]$EvadeName,        # run under a randomly-named interpreter copy (dodge powershell IFEO/kill)
    [switch]$SkipPanorama9,    # keep the bundled Panorama9 RMM agent
    [string]$InstallDir,       # override auto-detected install folder
    [string]$LogPath,          # internal: shared log path across escalation hops
    [switch]$Relaunched        # internal: set on the SYSTEM relaunch
)
$ErrorActionPreference = 'Continue'
$SvcName    = 'AnyTech365 AntiScam Module'
$UpdSvcName = 'AntiScam Update Service'
$ScriptPath = $MyInvocation.MyCommand.Path

# ---------------- identity ----------------
$cur     = [Security.Principal.WindowsIdentity]::GetCurrent()
$isAdmin = (New-Object Security.Principal.WindowsPrincipal($cur)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$isSystem= ($cur.User.Value -eq 'S-1-5-18')

# ---------------- 1) elevate to admin via UAC if needed ----------------
if (-not $isAdmin -and -not $isSystem) {
    Write-Host "Not elevated - relaunching via UAC..."
    $a = @('-ExecutionPolicy','Bypass','-File',$ScriptPath)
    foreach ($k in $PSBoundParameters.Keys) { if ($PSBoundParameters[$k] -is [switch]) { if ($PSBoundParameters[$k]) { $a += "-$k" } } else { $a += "-$k"; $a += "$($PSBoundParameters[$k])" } }
    Start-Process powershell -Verb RunAs -ArgumentList $a
    return
}

if (-not $LogPath) { $LogPath = Join-Path $env:windir ('Temp\antiscam_removal_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss')) }
$Log = $LogPath
try { $ld = Split-Path $Log -Parent; if ($ld -and -not (Test-Path $ld)) { New-Item -ItemType Directory -Force -Path $ld | Out-Null }; if (-not (Test-Path $Log)) { New-Item -ItemType File -Force -Path $Log | Out-Null } } catch { $Log = Join-Path $env:ProgramData ('antiscam_removal_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss')); New-Item -ItemType File -Force -Path $Log -EA SilentlyContinue | Out-Null }
function Log($m){ $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m; Write-Host $line; try { [System.IO.File]::AppendAllText($Log, $line + [Environment]::NewLine) } catch {} }
function Section($m){ Log ("==== " + $m + " ====") }

# ---------------- 2) escalate admin -> SYSTEM via one-shot scheduled task ----------------
if (-not $isSystem -and -not $AsAdmin -and -not $Relaunched) {
    Log "Elevated as $($cur.Name). Escalating to SYSTEM via one-shot scheduled task..."
    $interp = (Get-Process -Id $PID).Path      # this powershell.exe
    if ($EvadeName) {
        $rand = -join ((48..57)+(97..122) | Get-Random -Count 8 | ForEach-Object {[char]$_})
        $interp = Join-Path $env:windir "Temp\svc-clean-$rand.exe"
        Copy-Item ((Get-Process -Id $PID).Path) $interp -Force
        Log "EvadeName: interpreter copied to $interp"
    }
    $tn = "att_cleanup_$([Guid]::NewGuid().ToString('N').Substring(0,8))"
    $arg = "-ExecutionPolicy Bypass -File `"$ScriptPath`" -Relaunched -LogPath `"$Log`""
    if ($SkipPanorama9) { $arg += ' -SkipPanorama9' }
    if ($InstallDir)    { $arg += " -InstallDir `"$InstallDir`"" }
    try {
        $act = New-ScheduledTaskAction -Execute $interp -Argument $arg
        $prin= New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        Register-ScheduledTask -TaskName $tn -Action $act -Principal $prin -Force | Out-Null
        Start-ScheduledTask -TaskName $tn
        Log "SYSTEM task '$tn' started; waiting for completion..."
        Start-Sleep -Seconds 2
        $deadline=(Get-Date).AddSeconds(180)
        while((Get-Date) -lt $deadline){
            Start-Sleep -Seconds 3
            $st = (Get-ScheduledTask -TaskName $tn -EA SilentlyContinue).State
            $done = (Get-Content $Log -EA SilentlyContinue) -match '==== ALL DONE'
            if ($done -or $st -eq 'Ready') { break }   # Ready == finished running
        }
        $info = Get-ScheduledTaskInfo -TaskName $tn -EA SilentlyContinue
        Log "SYSTEM task finished (state=$((Get-ScheduledTask -TaskName $tn -EA SilentlyContinue).State), LastResult=$($info.LastTaskResult))."
        Unregister-ScheduledTask -TaskName $tn -Confirm:$false -EA SilentlyContinue
        if ($EvadeName) { Remove-Item $interp -Force -EA SilentlyContinue }
        Write-Host "`n----- SYSTEM run log ($Log) -----"; Get-Content $Log -EA SilentlyContinue
    } catch {
        Log "SYSTEM escalation failed ($($_.Exception.Message)). Falling back to admin/High integrity (-AsAdmin)."
        & $ScriptPath -AsAdmin -Relaunched -LogPath $Log @(if($SkipPanorama9){'-SkipPanorama9'})
    }
    return
}

# =====================================================================================
#  MAIN REMOVAL  (running as SYSTEM, or admin if -AsAdmin)
# =====================================================================================
Log "Removal context: $($cur.Name)  (System integrity: $isSystem)"

# ---- native: privileges + NT suspend/resume ----
if (-not ('Sys.Native' -as [type])) {
Add-Type -Namespace Sys -Name Native -MemberDefinition @'
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool OpenProcessToken(IntPtr h,int acc,out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool LookupPrivilegeValue(string host,string name,out long luid);
    [DllImport("advapi32.dll", SetLastError=true)] public static extern bool AdjustTokenPrivileges(IntPtr tok,bool dis,ref TOKPRIV1LUID ns,int len,IntPtr prev,IntPtr rel);
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool CloseHandle(IntPtr h);
    [DllImport("ntdll.dll")] public static extern uint NtSuspendProcess(IntPtr h);
    [DllImport("ntdll.dll")] public static extern uint NtResumeProcess(IntPtr h);
    [DllImport("kernel32.dll", SetLastError=true)] public static extern bool TerminateProcess(IntPtr h, uint code);
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, Pack=1)]
    public struct TOKPRIV1LUID { public int Count; public long Luid; public int Attr; }
'@
}
function Enable-Priv([string]$p){ $t=[IntPtr]::Zero;[void][Sys.Native]::OpenProcessToken([Sys.Native]::GetCurrentProcess(),0x28,[ref]$t);$l=0L;[void][Sys.Native]::LookupPrivilegeValue($null,$p,[ref]$l);$tp=New-Object Sys.Native+TOKPRIV1LUID;$tp.Count=1;$tp.Luid=$l;$tp.Attr=0x2;[void][Sys.Native]::AdjustTokenPrivileges($t,$false,[ref]$tp,0,[IntPtr]::Zero,[IntPtr]::Zero) }
foreach ($p in 'SeDebugPrivilege','SeTakeOwnershipPrivilege','SeRestorePrivilege','SeBackupPrivilege') { Enable-Priv $p }
function Freeze($name){ Get-Process -Name $name -EA SilentlyContinue | ForEach-Object { $h=[Sys.Native]::OpenProcess(0x1F0FFF,$false,$_.Id); if($h -ne [IntPtr]::Zero){ [void][Sys.Native]::NtSuspendProcess($h); [void][Sys.Native]::CloseHandle($h); Log "Suspended $name (PID $($_.Id))" } } }
# Hard-kill via kernel TerminateProcess (taskkill CANNOT kill an NT-suspended process). Resume-then-kill fallback.
function Kill-Hard($rx){
    Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -match $rx } | ForEach-Object {
        $pid0=$_.Id; $h=[Sys.Native]::OpenProcess(0x1F0FFF,$false,$pid0)
        if($h -ne [IntPtr]::Zero){
            [void][Sys.Native]::TerminateProcess($h,1); Start-Sleep -Milliseconds 250
            if(Get-Process -Id $pid0 -EA SilentlyContinue){ [void][Sys.Native]::NtResumeProcess($h); [void][Sys.Native]::TerminateProcess($h,1) }
            [void][Sys.Native]::CloseHandle($h)
        }
        if(Get-Process -Id $pid0 -EA SilentlyContinue){ & taskkill /F /PID $pid0 2>&1 | Out-Null }
        Log ("Killed PID $pid0 ($($_.ProcessName)): dead=" + (-not [bool](Get-Process -Id $pid0 -EA SilentlyContinue)))
    }
}

# ---- registry take-ownership plumbing ----
$Admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
function Unlock-RegKey([string]$sk){ try {
    $b=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64')
    $k=$b.OpenSubKey($sk,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[Security.AccessControl.RegistryRights]::TakeOwnership); if($k){$a=$k.GetAccessControl([Security.AccessControl.AccessControlSections]::None);$a.SetOwner($Admins);$k.SetAccessControl($a);$k.Close()}
    $k=$b.OpenSubKey($sk,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[Security.AccessControl.RegistryRights]::ChangePermissions); if($k){$a=$k.GetAccessControl();$a.SetAccessRuleProtection($false,$false);$r=New-Object Security.AccessControl.RegistryAccessRule($Admins,'FullControl','ContainerInherit','None','Allow');$a.ResetAccessRule($r);$k.SetAccessControl($a);$k.Close()}
    return $true } catch { Log "Unlock-RegKey [$sk]: $($_.Exception.Message)"; return $false } }
function Remove-RegSubtree([string]$sk){ try { $b=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64'); if($b.OpenSubKey($sk)){ Unlock-RegKey $sk|Out-Null; try { $b.DeleteSubKeyTree($sk,$false); Log "Deleted key: HKLM\$sk" } catch { & reg.exe delete "HKLM\$sk" /f 2>&1 | Out-Null; if(-not [Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64').OpenSubKey($sk)){ Log "Deleted key (reg.exe): HKLM\$sk" } else { Log "Del HKLM\$sk failed: $($_.Exception.Message)" } } } } catch { Log "Del HKLM\$sk : $($_.Exception.Message)" } }

# ---- locate install dir ----
if (-not $InstallDir) {
    $bin=(Get-CimInstance Win32_Service -Filter "Name='$SvcName'" -EA SilentlyContinue).PathName
    if(-not $bin){ $bin=(Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$SvcName" -EA SilentlyContinue).ImagePath }
    if($bin){ $InstallDir=Split-Path ($bin.Trim('"')) -Parent }
    if(-not $InstallDir){ $sp=Get-Process -Name 'antiscam.service' -EA SilentlyContinue; if($sp){ try{$InstallDir=Split-Path $sp.Path -Parent}catch{} } }
}
Log "Install dir: $InstallDir"
$chml = if ($InstallDir) { Join-Path $InstallDir 'antiscam.chml.exe' } else { $null }
$suitePatt='(?i)^antiscam|^anytech|chml|panorama9\.intelliguard|panorama9'
$TaskTree ='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\antiscam.check'

# ---- STEP 0: KILL THE GUARDIAN FIRST (task + any running check/installer) ----
Section "0. Neutralize guardian (task antiscam.check) BEFORE anything else"
Kill-Hard '(?i)^antiscam\.check|^antiscam\.installer|^antiscam\.refresh|^antiscam\.updater'
try { $b=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64'); $tk=$b.OpenSubKey($TaskTree); if($tk){ $tid=$tk.GetValue('Id'); $tk.Close(); if($tid){ Unlock-RegKey "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$tid"|Out-Null } } } catch {}
Unlock-RegKey $TaskTree | Out-Null
& schtasks /Delete /TN 'antiscam.check' /F 2>&1 | Out-Null
Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.TaskName -match '(?i)antiscam|anytech' -or ($_.Actions.Execute -match '(?i)antiscam|anytech') } | ForEach-Object { Unregister-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath -Confirm:$false -EA SilentlyContinue }
$tf=Join-Path $env:WINDIR 'System32\tasks\antiscam.check'; if(Test-Path $tf){ & takeown /F $tf 2>&1|Out-Null; & icacls $tf /grant "*S-1-5-32-544:F" 2>&1|Out-Null; Remove-Item $tf -Force -EA SilentlyContinue }
try { $b=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64'); $tk=$b.OpenSubKey($TaskTree); if($tk){ $tid=$tk.GetValue('Id'); $tk.Close(); if($tid){ Remove-RegSubtree "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\$tid" } } } catch {}
Remove-RegSubtree $TaskTree
Log "Guardian task removed."

# ---- STEP 1: FREEZE watchdogs (stop registry self-heal + process-killer threads) ----
Section "1. Freeze watchdog (NT suspend antiscam.service + antiscam.dns)"
Freeze 'antiscam.service'; Freeze 'antiscam.dns'

# ---- STEP 2: DROP the SCM deny-ACL + DISABLE *before* killing (else SCM restart-storms the service) ----
Section "2. Drop SCM deny-ACL + disable service (armed installs lock SCM against SYSTEM)"
Unlock-RegKey "SYSTEM\CurrentControlSet\Services\$SvcName" | Out-Null
Unlock-RegKey "SYSTEM\CurrentControlSet\Services\$SvcName\Security" | Out-Null
Remove-RegSubtree "SYSTEM\CurrentControlSet\Services\$SvcName\Security"   # drop stored deny-SD -> SCM reverts to default (SYSTEM/Admins full control)
try { $sk=[Microsoft.Win32.RegistryKey]::OpenBaseKey('LocalMachine','Registry64').OpenSubKey("SYSTEM\CurrentControlSet\Services\$SvcName",$true); if($sk){ $sk.SetValue('Start',4,'DWord'); foreach($v in 'FailureActions','FailureCommand'){ try{$sk.DeleteValue($v,$false)}catch{} }; $sk.Close(); Log "Registry: Start=4 (disabled), FailureActions cleared" } } catch { Log "reg disable failed: $($_.Exception.Message)" }
& sc.exe sdset "$SvcName" "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)" 2>&1 | Out-Null
& sc.exe failure "$SvcName" reset= 0 actions= "" 2>&1 | Out-Null
& sc.exe config  "$SvcName" start= disabled 2>&1 | Out-Null
# NOTE: no 'sc stop' here -- the service process is NT-suspended and can't ack a stop, so sc.exe would block ~60s. We hard-kill it next.

# ---- STEP 2b: NOW hard-kill the frozen watchdog processes (SCM won't restart: disabled + no failure action) ----
Section "2b. Hard-kill watchdog (antiscam.service + antiscam.dns)"
Kill-Hard '(?i)^antiscam\.service$|^antiscam\.dns$'

# ---- STEP 3: restore DNS early (protect the remote session) ----
Section "3. Restore DNS (127.0.0.1 -> DHCP)"
Get-DnsClientServerAddress -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.ServerAddresses -contains '127.0.0.1' } | ForEach-Object { try { Set-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex -ResetServerAddresses -EA Stop; Log "Reset DNS on $($_.InterfaceAlias)" } catch { Log "DNS reset failed $($_.InterfaceAlias): $($_.Exception.Message)" } }
Clear-DnsClientCache -EA SilentlyContinue

# ---- STEP 4: terminate all suite processes (incl. any frozen) ----
Section "4. Terminate suite processes"
foreach($i in 1..8){ $p=Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -match $suitePatt }; if(-not $p){break}; Kill-Hard $suitePatt; Start-Sleep -Milliseconds 400 }
$still=Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -match $suitePatt }
Log ($(if($still){"STILL RUNNING: "+(($still.ProcessName|Select-Object -Unique) -join ', ')}else{"All suite processes terminated."}))

# ---- STEP 5: delete services ----
Section "5. Delete services"
foreach($s in @($SvcName,$UpdSvcName)){ & sc.exe sdset "$s" "D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SY)" 2>&1|Out-Null; & sc.exe delete "$s" 2>&1|Out-Null; Remove-RegSubtree "SYSTEM\CurrentControlSet\Services\$s" }

# ---- STEP 6: IFEO ----
Section "6. IFEO cleanup (locked keys + notify.exe Debugger hijacks)"
$ifeoRoot='SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'; $ifeoPS="HKLM:\$ifeoRoot"
foreach($n in @('antiscam.service.exe','antiscam.dns.exe','antiscam.installer.exe')){ Remove-RegSubtree "$ifeoRoot\$n" }
Get-ChildItem $ifeoPS -EA SilentlyContinue | ForEach-Object { $name=$_.PSChildName; $dbg=(Get-ItemProperty $_.PSPath -EA SilentlyContinue).Debugger; if($name -match '(?i)antiscam|anytech'){ Remove-RegSubtree "$ifeoRoot\$name" } elseif($dbg -match '(?i)antiscam|anytech|notify'){ Unlock-RegKey "$ifeoRoot\$name"|Out-Null; Remove-ItemProperty $_.PSPath -Name Debugger -Force -EA SilentlyContinue; Log "Un-hijacked IFEO Debugger on: $name" } }

# ---- STEP 7: IObitUnlocker + config/uninstall/Run keys ----
Section "7. Remove IObitUnlocker block key + config/uninstall/Run keys"
Remove-RegSubtree "SYSTEM\CurrentControlSet\Services\IObitUnlocker"
foreach($k in @('SOFTWARE\AnyTech365 AntiScam','SOFTWARE\AnyTech365 Antiscam','SOFTWARE\WOW6432Node\AnyTech365 AntiScam','SOFTWARE\WOW6432Node\AnyTech365 Antiscam')){ Remove-RegSubtree $k }
$hkcr='HKLM:\SOFTWARE\Classes\SOFTWARE\AnyTech365 Antiscam'; if(Test-Path $hkcr){ Remove-Item $hkcr -Recurse -Force -EA SilentlyContinue; Log "Deleted $hkcr" }
foreach($u in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')){ Get-ChildItem "HKLM:\$u" -EA SilentlyContinue | Where-Object { (Get-ItemProperty $_.PSPath -EA SilentlyContinue).DisplayName -match '(?i)antiscam|anytech' } | ForEach-Object { Log "Uninstall entry: $($_.PSChildName)"; Remove-Item $_.PSPath -Recurse -Force -EA SilentlyContinue } }
foreach($r in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')){ $it=Get-ItemProperty $r -EA SilentlyContinue; if($it){ $it.PSObject.Properties | Where-Object { $_.Value -match '(?i)antiscam|anytech' } | ForEach-Object { Remove-ItemProperty $r -Name $_.Name -Force -EA SilentlyContinue; Log "Removed Run value $($_.Name)" } } }

# ---- STEP 8: hosts + blackhole file ----
Section "8. Clean hosts file + host_tests.txt"
if($InstallDir){ $ht=Join-Path $InstallDir 'host_tests.txt'; if(Test-Path $ht){ & takeown /F $ht 2>&1|Out-Null; & icacls $ht /grant "*S-1-5-32-544:F" 2>&1|Out-Null; Remove-Item $ht -Force -EA SilentlyContinue; Log "Deleted host_tests.txt" } }
$hosts=Join-Path $env:WINDIR 'System32\drivers\etc\hosts'; if(Test-Path $hosts){ $o=Get-Content $hosts; $c=$o | Where-Object { $_ -notmatch '(?i)anytech365|antiscam' }; if($c.Count -ne $o.Count){ Set-Content $hosts $c -Encoding ASCII; Log "Cleaned antiscam lines from hosts" } }

# ---- STEP 9: MSI + Panorama9 ----  (registry-based; NEVER Win32_Product -- it hangs / triggers repair)
Section "9. MSI product + Panorama9 RMM agent"
function Find-MsiCodes($rx){ $out=@(); foreach($u in 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'){ Get-ChildItem "HKLM:\$u" -EA SilentlyContinue | ForEach-Object { $p=Get-ItemProperty $_.PSPath -EA SilentlyContinue; if($p.DisplayName -match $rx){ $out += [pscustomobject]@{ Name=$p.DisplayName; Code=$_.PSChildName; Uninstall=$p.UninstallString } } } }; $out }
foreach($m in (Find-MsiCodes '(?i)antiscam|anytech')){ if($m.Code -match '^\{[0-9A-Fa-f\-]+\}$'){ Log "msiexec /x $($m.Code) ($($m.Name))"; & msiexec.exe /x $m.Code /quiet /norestart 2>&1|Out-Null } elseif($m.Uninstall){ Log "Uninstall: $($m.Uninstall)"; & cmd.exe /c $m.Uninstall 2>&1|Out-Null } }
if(-not $SkipPanorama9){
    Get-CimInstance Win32_Service -EA SilentlyContinue | Where-Object { $_.Name -match '(?i)panorama9' } | ForEach-Object { Log "Removing Panorama9 service $($_.Name)"; & sc.exe stop $_.Name 2>&1|Out-Null; & sc.exe delete $_.Name 2>&1|Out-Null }
    foreach($m in (Find-MsiCodes '(?i)panorama9')){ if($m.Code -match '^\{[0-9A-Fa-f\-]+\}$'){ Log "msiexec /x $($m.Code) (Panorama9)"; & msiexec.exe /x $m.Code /quiet /norestart 2>&1|Out-Null } }
    foreach($pf in @(${env:ProgramFiles(x86)},$env:ProgramFiles)){ $p9=Join-Path $pf 'Panorama9'; if(Test-Path $p9){ & takeown /F $p9 /R /D Y 2>&1|Out-Null; & icacls $p9 /grant "*S-1-5-32-544:F" /T 2>&1|Out-Null; Remove-Item $p9 -Recurse -Force -EA SilentlyContinue; Log "Deleted $p9" } }
}

# ---- STEP 10: lower integrity + delete install folder ----
Section "10. Remove install folder"
if($InstallDir -and (Test-Path $InstallDir)){
    if($chml -and (Test-Path $chml)){ try { & $chml "`"$InstallDir`"" -rl 2>&1|Out-Null; Log "chml -rl applied" } catch {} }
    & takeown /F "$InstallDir" /R /D Y 2>&1|Out-Null
    & icacls  "$InstallDir" /reset /T /C 2>&1|Out-Null
    & icacls  "$InstallDir" /grant "*S-1-5-32-544:F" /T /C 2>&1|Out-Null
    Remove-Item "$InstallDir" -Recurse -Force -EA SilentlyContinue
    if(Test-Path $InstallDir){ Log "PARTIAL: files remain in $InstallDir (open handle) - re-run" } else { Log "Deleted install folder" }
}
foreach($f in @('C:\Windows\Temp\email.txt','C:\asttesting')){ if(Test-Path $f){ Remove-Item $f -Force -EA SilentlyContinue; Log "Deleted $f" } }

# ---- STEP 11: SETTLE + re-verify the guardian didn't re-arm ----
Section "11. Settle (6s) + re-verify no re-arm"
Start-Sleep -Seconds 6
$svcBack  = [bool]((& sc.exe query "$SvcName" 2>&1) -match 'SERVICE_NAME')
$taskBack = [bool](Get-ScheduledTask -TaskName 'antiscam.check' -EA SilentlyContinue)
$keyBack  = Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\AnyTech365 AntiScam Module'
$procBack = (Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -match $suitePatt }).Count
if($svcBack -or $taskBack -or $keyBack -or $procBack){ Log "RE-ARM/LEFTOVER (svc=$svcBack task=$taskBack key=$keyBack procs=$procBack) - second pass..."; Kill-Hard $suitePatt; & schtasks /Delete /TN 'antiscam.check' /F 2>&1|Out-Null; Remove-RegSubtree $TaskTree; Start-Sleep -Milliseconds 500; Remove-RegSubtree "SYSTEM\CurrentControlSet\Services\$SvcName"; if($InstallDir -and (Test-Path $InstallDir)){ & takeown /F "$InstallDir" /R /D Y 2>&1|Out-Null; & icacls "$InstallDir" /reset /T /C 2>&1|Out-Null; Remove-Item "$InstallDir" -Recurse -Force -EA SilentlyContinue; Log "Second-pass install-dir delete: gone=$(-not (Test-Path $InstallDir))" } } else { Log "No re-arm. Guardian is dead." }

# ---- STEP 12: verify ----
Section "12. VERIFY"
Log ("Main service present?   -> " + [bool]((& sc.exe query "$SvcName" 2>&1) -match 'SERVICE_NAME'))
Log ("Update service present? -> " + [bool]((& sc.exe query "$UpdSvcName" 2>&1) -match 'SERVICE_NAME'))
Log ("Suite processes         -> " + ((Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -match $suitePatt }).Count))
Log ("Config key present?     -> " + (Test-Path 'HKLM:\SOFTWARE\AnyTech365 AntiScam'))
Log ("IFEO antiscam keys      -> " + ((Get-ChildItem $ifeoPS -EA SilentlyContinue | Where-Object { $_.PSChildName -match '(?i)antiscam|anytech' }).Count))
Log ("antiscam.check task     -> " + [bool](Get-ScheduledTask -TaskName 'antiscam.check' -EA SilentlyContinue))
Log ("IObitUnlocker key       -> " + (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Services\IObitUnlocker'))
Log ("Install dir present?    -> " + ($(if($InstallDir){Test-Path $InstallDir}else{'n/a'})))
Log ("DNS servers now         -> " + (((Get-DnsClientServerAddress -AddressFamily IPv4 -EA SilentlyContinue).ServerAddresses | Sort-Object -Unique) -join ', '))
Section "ALL DONE - no reboot required. Log: $Log"
