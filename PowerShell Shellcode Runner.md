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
$Win32 = @"using System;using System.Runtime.InteropServices;public class Win32 {
[DllImport("kernel32.dll")]public static extern IntPtr **VirtualAlloc**(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll",CharSet=CharSet.Ansi)]public static extern IntPtr **CreateThread**(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
[DllImport("kernel32.dll")]public static extern bool **VirtualProtect**(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
[DllImport("kernel32.dll", SetLastError=true)] public static extern UInt32 **WaitForSingleObject**(IntPtr hHandle, UInt32 dwMilliseconds);} 
"@

