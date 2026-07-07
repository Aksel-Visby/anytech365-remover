# AnyTech365 AntiScam Removal

A PowerShell tool that removes the "AnyTech365 AntiScam" software from Windows without the vendor deactivation code.

AnyTech365 AntiScam installs a LocalSystem service, a persistent scheduled task, and a bundled Panorama9 remote-management agent. It applies self-protection (locked service and registry ACLs, System integrity labels on its files, Image File Execution Options entries, a WMI process watcher, and a local DNS redirect) and normally requires an 8-digit code from the vendor to uninstall. That code is validated server-side and cannot be recovered locally, so this tool removes the software by hand instead.

## Requirements

- Windows 10 or 11
- Local administrator account
- PowerShell 3.0 or later

## Usage

Standard run:

```
powershell -ExecutionPolicy Bypass -File .\remove-antiscam-hardened.ps1
```

The script prompts for elevation (UAC), then escalates itself to SYSTEM and performs the removal. Progress is written to the console and to `C:\Windows\Temp\antiscam_removal_<timestamp>.log`. Review the VERIFY block at the end of the log.

Options:

- `-EvadeName` Run under a randomly named copy of the interpreter. Use this if the window closes immediately, which can happen if the software blocks `powershell.exe` by name.
- `-SkipPanorama9` Leave the bundled Panorama9 agent in place.
- `-InstallDir <path>` Set the install folder manually if auto-detection fails.
- `-AsAdmin` Run at administrator integrity instead of SYSTEM. Less reliable against integrity-locked files. Use only if SYSTEM escalation is blocked.
- `-SetSafeBootAndReboot` Set the boot configuration to Safe Mode and reboot.
- `-ClearSafeBoot` Clear the Safe Mode flag and reboot to normal.

## What it does

Running as SYSTEM, in order:

1. Deletes the `antiscam.check` scheduled task. This task is a guardian that resumes suspended components and re-runs the installer if the service is removed, so it is neutralized first.
2. Suspends the service process to stop its watchdogs (registry self-heal and process killer).
3. Removes the service deny-ACL by deleting the service Security subkey, then disables the service. This stops the Service Control Manager from restarting it.
4. Terminates all components with TerminateProcess.
5. Deletes the services, Image File Execution Options entries, the IObitUnlocker key, and the configuration keys, taking ownership of ACL-locked keys as needed.
6. Restores DNS to DHCP and removes the local blackhole hosts file.
7. Removes any MSI product entries and the Panorama9 agent.
8. Lowers the install folder integrity level and deletes it.
9. Waits and re-verifies that nothing has re-armed.

No reboot is required in the standard case.

## If removal is disrupted

Some installations resist removal. Try in this order:

1. Run the script again. A second pass clears anything re-armed during the first.
2. Run with `-EvadeName`.
3. Boot into Safe Mode (`-SetSafeBootAndReboot`) and run the script there, then `-ClearSafeBoot`. In Safe Mode the watchdogs do not run, so removal is reliable. Rebooting to Safe Mode ends any active remote session, so plan for that on remote support jobs.

## Verification

The log ends with a VERIFY block. On success:

- Main service present: False
- Update service present: False
- Suite processes: 0
- Config key present: False
- IFEO antiscam keys: 0
- antiscam.check task: False
- IObitUnlocker key: False
- Install dir present: False
- DNS servers: the normal gateway or DHCP value, not 127.0.0.1

## Indicators of compromise

Services:
- `AnyTech365 AntiScam Module` (LocalSystem, auto-start)
- `AntiScam Update Service`

Scheduled task:
- `antiscam.check`

Registry:
- `HKLM\SOFTWARE\AnyTech365 AntiScam`
- `HKLM\SYSTEM\CurrentControlSet\Services\IObitUnlocker`
- Image File Execution Options entries named `antiscam.*`

Files:
- Install folder containing `antiscam.*.exe` and `host_tests.txt`
- `C:\Windows\Temp\email.txt`

Network:
- `relay.anytech365.com`
- `antiscam-backup.panorama9.com`
- `panorama9.com`
- `download.anytech365.com`
- DNS set to `127.0.0.1` with a local resolver process (`antiscam.dns.exe`)

## Antivirus note

This script takes ownership of registry keys, terminates processes, edits Image File Execution Options, and creates a temporary SYSTEM scheduled task. Endpoint protection may flag these actions. Review the source before running.

## Disclaimer

Provided as is, without warranty of any kind. Intended for use by the system owner or an authorized technician on systems they are permitted to modify. Test on a recoverable system before production use.

## License

MIT. See LICENSE.
