# AnyTech365 "AntiScam" — Decompiled behaviour (ground truth)

**Date:** 2026-07-07 · Source: dnSpyEx decompile of `antiscam.service.exe`, `antiscam.common.dll`, `antiscam.uninstaller.exe`, `antiscam.configure.exe`. Full C# in session scratchpad `decompiled\`.

## Why it never fully arms from a leaked sample (definitive)
`Service1.OnStart` → `httpWebRequest.getRESTApi(deviceId,"check",...)`. If the response contains **`INVALID_CHECK`** it logs *"Invalid Check on service start"*, `Thread.Sleep(30000)`, then **recursively calls `OnStart` again — forever**. An unregistered device (404 from server) yields `INVALID_CHECK - DOES_NOT_EXIST`, so `OnStart` never returns → SCM stays **START_PENDING**, and `Self_Protection()` (which runs *after* the check passes) never executes. This is why both the 2026-07-06 and 2026-07-07 runs parked at START_PENDING with no artifacts. **The sample cannot self-arm without a server-registered device_id.**

## OnStart sequence (when the server DOES bless it)
1. `check` REST call → JSON with keys: `active`, `process_watcher`, `process_timer`, `uninstall`, `blocklist`.
2. If `uninstall==true` → `Start_Uninstall()` (server can remotely uninstall).
3. If `process_watcher==true` → wire `Win32_ProcessStartTrace` + service-key `RegistryKeyChangeEvent` handlers.
4. If `active==true` → `Activate_Security()` ("Shield Enabled") else `Disable_Security()`.
5. **`Self_Protection()`** — deploys persistence + hardening (see below).
6. `SetDNStoLocal()` → sets every IPEnabled adapter's DNS to **`127.0.0.1,8.8.8.8`** (local `antiscam.dns.exe` intercepts).
7. Timers: `Check_Status` 15 min (re-poll server), `CheckDNSServer` 2 min (relaunch `antiscam.dns.exe` if killed), `TerminateProcess_Timer` 3 min (kill blocklisted procs).

## Self_Protection() — exact artifacts it creates
- `antiscam.chml.exe "<dir>\host_tests.txt" -ws:S:AI(ML;OICI;NWNRNX;;;SI)` → host_tests.txt to **System integrity, no read/write/execute-up**.
- `antiscam.chml.exe "<dir>" -ws:S:AI(ML;OICI;NW;;;SI)` → whole install dir to **System integrity, no-write-up** (can't modify/delete as Medium).
- `sc sdset "AnyTech365 AntiScam Module" "D:(D;;...;;;SY)(D;;...;;;BA)(D;;...;;;IU)(D;;...;;;SU)(D;;...;;;BU)(A;;LCDCRPRC;;;SY)...(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-4159801862-1222732778-3399482066-2108582498-1631141031)..."` → **DENY** stop/delete/change to SYSTEM, Administrators, Users; full control only to the service's own SID.
- `ChangeRegIOAcl` (owner = service SID `S-1-5-80-4159801862-1222732778-3399482066-2108582498-1631141031`, deny Admin write) on:
  - `HKLM\SYSTEM\CurrentControlSet\Services\AnyTech365 AntiScam Module` and `...\Security`
  - `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\antiscam.service.exe` / `antiscam.dns.exe` / `antiscam.installer.exe`
  - `HKLM\SYSTEM\CurrentControlSet\Services\IObitUnlocker` (creates + locks the key to **block the IObitUnlocker unlock tool**)
  - the `antiscam.check` task keys under `TaskCache\Tree` and `TaskCache\Tasks\{id}`
- `Create_Task()` → scheduled task **`antiscam.check`**: SYSTEM, Highest, Logon + Registration triggers, repeat every 1 min for 99 days, runs `antiscam.check.exe`.

## Watchdogs (self-heal / anti-tamper)
- **`registryServiceChange_EventArrived`** (WMI `RegistryKeyChangeEvent` on the service key): on any change, rewrites `Type=16`, `Start=2`, `ImagePath=<dir>\antiscam.service.exe`. Undoes `sc config start= disabled` in real time.
- **`processStartEvent_EventArrived`** (WMI `Win32_ProcessStartTrace`): kills any newly-started process that is Support.com-signed, matches the server `blocklist`, or is `ScreenConnect.ClientService.exe` not from AnyTech's relay — unless whitelisted / ANTECO-signed / cmdline contains `relay.anytech365.com`|`panorama9.com`. Pops `antiscam.notify.exe` scareware.
- **`BlockProcesses`**: sets IFEO `Debugger = <dir>\antiscam.notify.exe` for each blocklisted process name (so security tools launch the scareware instead).
- **DNS**: `antiscam.dns.exe` local server blackholes domains from `host_tests.txt` (`127.0.0.1 <domain>`); `CheckDNSServer` relaunches it every 2 min.

## Server-commanded uninstall (Start_Uninstall) — the "official" order
Disable security → delete task (`TaskCache\Tree\antiscam.check` + `%windir%\System32\tasks\antiscam.check`) → delete `HKLM\SOFTWARE\AnyTech365 AntiScam\` and `HKLM`/`HKCR\SOFTWARE\AnyTech365 Antiscam` → DNS back to `8.8.8.8,8.8.4.4` → kill GUI/dns/uninstaller → REST `delete` → `msiexec /quiet /uninstall <SecretKey>` (SecretKey = base64 in the Uninstall entry) → delete host_tests.txt → `sc delete "AntiScam Update Service"` → delete `Services\AnyTech365 AntiScam Module` subtree → `cmd /c echo AnyTech365 AntiScam Uninstalled && pause`.

## C2 / IOCs (from httpWebRequest.cs)
- Panel `http://antiscam-backup.panorama9.com` (GCP `35.205.187.208`); test `http://antiscam-testing.anytechcorp.com` (toggled by presence of `C:\asttesting`).
- API key `2d56039da4005355030c2f875f7b6d7f`. Endpoints `/api/v1/clients/{device_id}/{check|register|code|enable|disable|uninstall|alert|cancel_jobs|check_anydesk}`, `/api/v1/p9_details`, `/api/v1/version`.
- MSI `http://download.anytech365.com/antiscam/binary/AnyTech365-AntiScam.msi`. Email cache `C:\Windows\Temp\email.txt`. `ServerCertificateValidationCallback` returns **true** (accepts any cert).
- **8-digit code is server-validated only** (`disable`/`uninstall` POST `code=`, success == server returns `{}`). No local/offline validation — do not attempt to crack.

## Removal implications (drove remove-antiscam-hardened.ps1)
1. **Safe Mode** (auto-start `Start=2` won't run → both watchdogs + process-killer + DNS hijack dormant). This is the key enabler on armed machines.
2. **Take ownership + reset ACL** on the service key, its `\Security` subkey, the 3 IFEO keys, `IObitUnlocker`, and the task keys (Admin/SYSTEM are DENIED until owned).
3. **Lower integrity** on the install dir/files (`chml -rl` or `takeown`+`icacls`) before deleting.
4. Restore DNS to DHCP; delete `host_tests.txt`; un-hijack IFEO `Debugger`→notify entries; remove `antiscam.check` task; delete config keys (both casings, HKLM+HKCR+WOW6432Node); delete both services (`AnyTech365 AntiScam Module`, `AntiScam Update Service`); uninstall the MSI + **Panorama9** agent; remove Uninstall entries and `C:\Windows\Temp\email.txt` / `C:\asttesting`.
