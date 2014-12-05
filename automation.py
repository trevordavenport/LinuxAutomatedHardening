#Python Script for BERK1337
#Author: Trevor Davenport

'''
	Python Script to Automate the hardening of a Linux System.
	Updates IP Tables (Firewall) based on processes.
	Scans for vulnerabilities in the underlying system

	Algorithm:
		(1) Scan For Vulnerable Services --> Parse Services Returned --> Update / Harden Accodingly (Determine version, check against latest update)
		(2) Run nmap in the background, wait for results to return 
		(3) Update IP Tables based on (1) + Main Service Machine is to be Hosting
		(4) Determine users logged in, report any abnormalities
		(5) Parse etc/passwd, determine abnormalities
		(6) Disable ALL Unknown / Most Vulnerable Services 
		(7) Netstat current connections, again, report inconsistencies/suspicious activity
		(8) Change all Default passwords for Services / User Account



	______________VULNERABILITY SCANNER______________
		1. Scans for most vulnerable services, reports which are present
			Resource: http://www.softpanorama.info/Commercial_linuxes/Security/top_vulnerabilities.shtml
			--> [ssh, BIND, Java, OpenSSL, RPC, SNMP, Sendmail, Apache]

'''

'''
RPC Fix

	(1) Terminal Command: 'rpcinfo'

	Most Vuln: 
		RPC Service	RPC Program Number
		rpc.ttdbserverd	100083
		rpc.cmsd	100068
		rpc.statd	100024
		rpc.mountd	100005
		rpc.walld	100008
		rpc.yppasswdd	100009
		rpc.nisd	100300
		sadmind	100232
		cachefsd	100235
		snmpXdmid	100249

	(2) Block the RPC portmapper, port 111 (TCP and UDP) and Windows RPC, port 135 (TCP and UDP), at the border router or firewall.
		Block the RPC "loopback" ports, 32770-32789 (TCP and UDP).

	(3) Enable a non-executable stack on those operating systems that support this feature. 
		While a non-executable stack will not protect against all buffer overflows,
		It can hinder the exploitation of some standard buffer overflow exploits publicly available on the Internet.

'''

'''
Clear-Text Services Fix (Services that lack encryption / send data in plain-text)
	(1) Services to Check for:
			Service Port
			-------------
			FTP		21,20	
			TFTP	69	
			telnet	23	
			SMTP	25	
			POP3	110	
			IMAP	143	
			rlogin	513	
			rsh		514	
			HTTP	80

	(2) Implementation of Vuln. Test
			(2.1)	'tcpdump -X -s 1600' //Detects any cleartext communications over TCP 
			(2.2)	'ngrep assword' //Searches for Specific Patterns in network communications containing "password"
			(2.3)	'/usr/sbin/dsniff' //Detects & Prints all username-passwords detected on network services (FTP, POP3, etc.)
					(DSNIFF http://www.monkey.org/~dugsong/dsniff/)

	(3) Securing Services
			POP3 --> POP3S (Secure-Encrypted Version)
			FTP --> SFTP || SCP 
			SSH --> OpenSSH

	(4) Example Fix (SSH Tunneling to make Secure Connections):
			Here is how one can tunnel POP3 over SSH connection. The POP3 server needs to be also running the SSH server. 
			First run this on the client machine:
				# ssh -L 110:pop3.mail.server.com:110 username@pop3.mail.server.com

			Now, point your email client to localhost, TCP port 110 (unlike the usual 'pop3.mail.server.com', port 110). 
			All communication between your machine and the POP3 mail server will be tunneled over SSH and thus encrypted.

'''

'''
	Sendmail Fix

	(1) Check: 'echo \$Z | /usr/lib/sendmail -bt -d0'
	_______________________________________________________________________________________________________

	SNMP Fix

	(1) Determine if running through port scanner 
	(2) Filter SNMP (port 161 TCP/UDP and 162 TCP/UDP) at the ingress points to your networks unless it is absolutely necessary to poll or manage devices externally
	_______________________________________________________________________________________________________

	SSH Version Detection

	(1) Port Scanner || '# ssh -V'
	(2) Check if outdated SSH version.
	_______________________________________________________________________________________________________

	OpenSSL 

	(1) '# openssl version' if version isnt > 0.9.7a, vulnerable.


'''

'''

	MOST VULNERABLE PORTS 
	_______________________________________________________________________________________________________

	Name	Port	Protocol	Description
	Small services	<20	tcp/udp	small services
	FTP	21	tcp	file transfer
	SSH	22	tcp	login service
	TELNET	23	tcp	login service
	SMTP	25	tcp	mail
	TIME	37	tcp/udp	time synchronization
	WINS	42	tcp/udp	WINS replication
	DNS	53	udp	naming services
	DNS zone transfers	53	tcp	naming services
	DHCP server	67	tcp/udp	host configuration
	DHCP client	68	tcp/udp	host configuration
	TFTP	69	udp	miscellaneous
	GOPHER	70	tcp	old WWW-like service
	FINGER	79	tcp	miscellaneous
	HTTP	80	tcp	web
	alternate HTTP port	81	tcp	web
	alternate HTTP port	88	tcp	web (sometimes Kerberos)
	LINUXCONF	98	tcp	host configuration
	POP2	109	tcp	mail
	POP3	110	tcp	mail
	PORTMAP/RPCBIND	111	tcp/udp	RPC portmapper
	NNTP	119	tcp	network news service
	NTP	123	udp	time synchronization
	NetBIOS	135	tcp/udp	DCE-RPC endpoint mapper
	NetBIOS	137	udp	NetBIOS name service
	NetBIOS	138	udp	NetBIOS datagram service
	NetBIOS/SAMBA	139	tcp	file sharing & login service
	IMAP	143	tcp	mail
	SNMP	161	tcp/udp	miscellaneous
	SNMP	162	tcp/udp	miscellaneous
	XDMCP	177	udp	X display manager protocol
	BGP	179	tcp	miscellaneous
	FW1-secureremote	256	tcp	CheckPoint FireWall-1 mgmt
	FW1-secureremote	264	tcp	CheckPoint FireWall-1 mgmt
	LDAP	389	tcp/udp	naming services
	HTTPS	443	tcp	web
	Windows 2000 NetBIOS	445	tcp/udp	SMB over IP (Microsoft-DS)
	ISAKMP	500	udp	IPSEC Internet Key Exchange
	REXEC	512	tcp	} the three
	RLOGIN	513	tcp	} Berkeley r-services
	RSHELL	514	tcp	} (used for remote login)
	RWHO	513	udp	miscellaneous
	SYSLOG	514	udp	miscellaneous
	LPD	515	tcp	remote printing
	TALK	517	udp	miscellaneous
	RIP	520	udp	routing protocol
	UUCP	540	tcp/udp	file transfer
	HTTP RPC-EPMAP	593	tcp	HTTP DCE-RPC endpoint mapper
	IPP	631	tcp	remote printing
	LDAP over SSL	636	tcp	LDAP over SSL
	Sun Mgmt Console	898	tcp	remote administration
	SAMBA-SWAT	901	tcp	remote administration
	Windows RPC programs	1025	tcp/udp	} often allocated
	Windows RPC programs	to	 	} by DCE-RPC portmapper
	Windows RPC programs	1039	tcp/udp	} on Windows hosts
	SOCKS	1080	tcp	miscellaneous
	LotusNotes	1352	tcp	database/groupware
	MS-SQL-S	1433	tcp	database
	MS-SQL-M	1434	udp	database
	CITRIX	1494	tcp	remote graphical display
	WINS replication	1512	tcp/udp	WINS replication
	ORACLE	1521	tcp	database
	NFS	2049	tcp/udp	NFS file sharing
	COMPAQDIAG	2301	tcp	Compaq remote administration
	COMPAQDIAG	2381	tcp	Compaq remote administration
	CVS	2401	tcp	collaborative file sharing
	SQUID	3128	tcp	web cache
	Global catalog LDAP	3268	tcp	Global catalog LDAP
	Global catalog LDAP SSL	3269	tcp	Global catalog LDAP SSL
	MYSQL	3306	tcp	database
	Microsoft Term. Svc.	3389	tcp	remote graphical display
	LOCKD	4045	tcp/udp	NFS file sharing
	Sun Mgmt Console	5987	tcp	remote administration
	PCANYWHERE	5631	tcp	remote administration
	PCANYWHERE	5632	tcp/udp	remote administration
	VNC	5800	tcp	remote administration
	VNC	5900	tcp	remote administration
	X11	6000-6255	tcp	X Windows server
	FONT-SERVICE	7100	tcp	X Windows font service
	alternate HTTP port	8000	tcp	web
	alternate HTTP port	8001	tcp	web
	alternate HTTP port	8002	tcp	web
	alternate HTTP port	8080	tcp	web
	alternate HTTP port	8081	tcp	web
	alternate HTTP port	8888	tcp	web
	Unix RPC programs	32770	tcp/udp	} often allocated
	Unix RPC programs	to	 	} by RPC portmapper
	Unix RPC programs	32899	tcp/udp	} on Solaris hosts
	COMPAQDIAG	49400	tcp	Compaq remote administration
	COMPAQDIAG	49401	tcp	Compaq remote administration
	PCANYWHERE	65301	tcp	remote administration
'''

from os import *
from sys import *
from subprocess import *

__copyright__ = 'BERK1337 Security Team'
__author__	  = 'Trevor Davenport'
__version__   = '1.3.3.7'

VULNERABLE_PORTS 	= [65301, 49401, 49400, 32899, 32770, 8000, 7100, 6000, 6255, 5900, 5800, 5632, 5631, 5987, 4045, 3389, 3306, 3269,
					   3268, 3128, 2401, 2381, 2301, 20, 21, 22, 23, 25, 37, 42, 53, 67, 68, 69, 70, 79, 80, 81, 88, 98, 109, 110, 111, 
					   119, 123, 135, 137, 138, 139, 143, 161, 162, 177, 179, 256, 264, 389, 500, 512, 513, 514, 515, 517, 520, 540, 593, 
					   631, 636, 898, 901, 1025, 1039, 1080, 1352, 1433, 1434, 1494, 1512, 1521, 2049]


CLEAR_TEXT_SERVICES = ['FTP', 'TFTP', 'telnet', 'SMTP', 'POP3', 'IMAP', 'rlogin', 'rsh', 'HTTP']
CLEAR_TEXT_PORTS	= [20,21,23,25,110,143,513,514,80]