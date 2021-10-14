# Microsoft Office Client Side Code Executtion
## Staged vs Non-staged Payloads
一般來說平常使用相關 Payload 框架，都會搭配可以使用弱點，也就是說弱點是拿來突破防禦機制，Payload可以說是維持存取的一種手段，維持存取的類型Payload分為以下meterpreter為例:
### Non-staged Payload (無階段性)
直接在記憶體中呼叫 執行完整的Payload
通常送過去的Payload 大小較大
Ex: windows/meterpreter_reverse_tcp
### Staged Payload (有階段性)
只送一小段 Payload 做接應
較穩定，且有其他功能
Ex: windows/meterpreter/reverse_tcp
