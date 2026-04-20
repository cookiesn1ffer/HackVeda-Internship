# Sysmon Binaries

The Sysmon executables are not included in this repository because they are
Microsoft-owned binaries and are too large for git.

## Download

Download the Sysmon package from Microsoft Sysinternals:

**https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon**

Extract `Sysmon64.exe` into this `Sysmon/` directory, then run the install
command from the project root:

```powershell
# Run as Administrator
cd Sysmon
.\Sysmon64.exe -accepteula -i
.\Sysmon64.exe -c ..\sysmon_config.xml
```

Verify it is running:

```powershell
Get-Service Sysmon64   # Should show: Running
```
