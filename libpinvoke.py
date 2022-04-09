PINVOKE = {
   "CreateThread": """
     [DllImport("kernel32")]
     private static extern IntPtr CreateThread( UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
   """,
   "CreateProcess": """
      [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
      static extern bool CreateProcess( string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
   """,
  "GetProcAddress":"""
     [DllImport("kernel32")]
     public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
  """,
  
  "LoadLibrary":"""
     [DllImport("kernel32")]
     public static extern IntPtr LoadLibrary(string name);
   """,
  
  "NtCreateSection":"""
    [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
    public static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, SectionAccess DesiredAccess, IntPtr ObjectAttributes, ref UInt64 MaximumSize, MemoryProtection SectionPageProtection,	MappingAttributes AllocationAttributes, IntPtr FileHandle);
  """,
  
  "VirtualAlloc": """
     [DllImport("kernel32")]
     private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
  """,
  
  "NtClose":"""
     [DllImport("ntdll.dll", ExactSpelling=true, SetLastError=false)]
     static extern int NtClose(IntPtr hObject);
  """,
  
  "NtUnmapViewOfSection":"""
     [DllImport("ntdll.dll", SetLastError=true)]
     static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);
  """,
  
  "NtCreateSection": """
     [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
     public static extern UInt32 NtCreateSection(ref IntPtr SectionHandle, SectionAccess DesiredAccess, IntPtr ObjectAttributes, ref UInt64 MaximumSize, MemoryProtection SectionPageProtection, MappingAttributes AllocationAttributes, IntPtr FileHandle);
  """,
  
  "NtMapViewOfSection": """
     [DllImport("ntdll.dll", SetLastError = true)]
     public static extern UInt32 NtMapViewOfSection(IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress, UIntPtr ZeroBits, UIntPtr CommitSize, ref UInt64 SectionOffset, ref UInt64 ViewSize, uint InheritDisposition, UInt32 AllocationType, MemoryProtection Win32Protect);
  """,

  "RtlCreateUserThread": """
     [DllImport("ntdll.dll", SetLastError = true)]
     public static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, CLIENT_ID clientId);
  
  """,
  
  "VirtualProtect":"""
     [DllImport("kernel32")]
     public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
  """,

  "MoveMemory":"""
     [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
     static extern void MoveMemory(IntPtr dest, IntPtr src, int size);
  """,

  "WaitForSingleObject": """
     [DllImport("kernel32")]
     private static extern UInt32 WaitForSingleObject( IntPtr hHandle, UInt32 dwMilliseconds);
  """,
  
  "Sleep": """
    [DllImport("kernel32.dll")]
    static extern void Sleep(uint dwMilliseconds);
  """,
  
  "VirtualAllocEx": """
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
  """,
  
  "VirtualAllocEx2": """
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, AllocationProtect flProtect);
  """,
  
  "VirtualAllocExNuma": """
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
  """,
  
  "GetCurrentProcess": """
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetCurrentProcess();
  """,
  
  "FlsAlloc": """
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern UInt32 FlsAlloc(IntPtr callback);
  """,
  
  "CreateRemoteThread": """
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
  """,
  
  "CreateRemoteThread2": """
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
  """,
  
  "WriteProcessMemory": """
    [DllImport("kernel32.dll")]
    static extern bool WriteProcessMemory( IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
  """,
  
  "OpenProcess": """
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
   """,
  
  "ZwQueryInformationProcess":"""
     [DllImport("ntdll.dll", SetLastError = true)]
     static extern UInt32 ZwQueryInformationProcess( IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen);
   """,
  
  "ReadProcessMemory":"""
     [DllImport("kernel32.dll", SetLastError = true)]
     static extern bool ReadProcessMemory( IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
   """,
   
  "WriteProcessMemory": """
     [DllImport("kernel32.dll")]
     static extern bool WriteProcessMemory( IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
   """,
   
  "ResumeThread": """
     [DllImport("kernel32.dll", SetLastError = true)]
     static extern uint ResumeThread(IntPtr hThread);
   """,
  
  "QueueUserAPC": """
     [DllImport("kernel32.dll", SetLastError = true)]
     public static extern UInt32 QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, UInt32 dwData);
   """,
  
  "CloseHandle": """
     [DllImport("kernel32.dll", SetLastError = true)]
     [return: MarshalAs(UnmanagedType.Bool)]
     public static extern bool CloseHandle(IntPtr hObject);
   """,
  
  "NtWriteVirtualMemory": """
     [DllImport("ntdll.dll", SetLastError = true)]
     public static extern NTSTATUS NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] buffer, UInt32 nSize, ref UInt32 lpNumberOfBytesWritten);
   """,
  
  "RtlZeroMemory": """
     [DllImport("kernel32.dll")]
     public static extern void RtlZeroMemory(IntPtr pBuffer, int length);
   """,
}
