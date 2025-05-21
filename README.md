# Project Andromeda (Penetration Test)

## Table of Contents
- [Project Overview](#project-overview)
- [Approach](#approach)
- [Scope](#scope)
- [Assessment Overview](#assessment-overview)
- [Key Findings](#key-findings)
  - [1. SSH_Login Exploit (High Risk)](#1-ssh_login-exploit-high-risk)
  - [2. EternalBlue Exploit (High Risk)](#2-eternalblue-exploit-high-risk)
- [Exploits and Attack Walkthrough](#exploits-and-attack-walkthrough)
  - [SSH_Login Exploit](#ssh_login-exploit)
  - [EternalBlue Exploit](#eternalblue-exploit)
- [Network Discovery](#network-discovery)
- [Remediation Recommendations](#remediation-recommendations)
  - [High Priority](#high-priority)
- [Conclusion](#conclusion)
- [References](#references)

---

## Project Overview

Project Andromeda is a gray-box penetration testing initiative aimed at evaluating the security posture of an internal network. The assessment focuses on identifying vulnerabilities, exploiting them to determine potential impacts, and providing remediation recommendations to enhance the organization's cybersecurity defenses.

## Approach

Opochtli used a **Gray Box** methodology. Testing was conducted **remotely** using a **provisioned host**. This was a **non-evasive** test focused on identifying misconfigurations and vulnerabilities without causing disruption.

## Scope

- One internal network range: `192.168.200.0/24`

## Assessment Overview

**Testing Methodology:** Gray Box, Remote, Non-evasive  
**Tools Used:** Metasploit Framework, Nmap, Password Brute Force Libraries  
**Hosts Identified:** 12 hosts found active during network scan  

**Critical Findings:** 2 exploits successfully demonstrated:  
- **SSH Login Brute Force (High Risk)**  
- **EternalBlue SMB Exploit (High Risk)**  

## Key Findings

### 1. SSH_Login Exploit (High Risk)

- **Vulnerable Host:** `192.168.200.10`  
- **Port:** `22/TCP` (SSH)  
- **Tool:** **Metasploit Framework** – `ssh_login` module  
- **Method:** Used a user/password dictionary to brute-force SSH credentials  
- **Outcome:** Successful brute-force attack granting access to `Ubuntu 18.04.5 LTS`  
- **Impact:** Unauthorized access achieved due to weak SSH credentials  
- **Risk Rating:** High  
- **Mitigation:** Enforce strong passwords and MFA (see Remediation Section).


### 2. EternalBlue Exploit (High Risk)

- **Vulnerable Host:** `192.168.200.163`  
- **Port:** `445/TCP` (SMB)  
- **Tool:** **Metasploit Framework** – `ms17_010_psexec` module  
- **Method:** Detected vulnerable SMB service with Nmap; exploited using EternalBlue module  
- **Outcome:** Successful remote code execution with **Meterpreter session** on Domain Controller  
- **Impact:** Full system compromise with administrative control over the target host  
- **Risk Rating:** High  
- **CVE Reference:** CVE-2017-0144 - A critical Microsoft SMBv1 vulnerability widely exploited by ransomware such as WannaCry.  
- **Mitigation:** Immediate patching with MS17-010, network segmentation, and system upgrades recommended.

## Exploits and Attack Walkthrough

### SSH_Login Exploit

- **Tool:** Metasploit Framework  
- **Method:** Used `ssh_login` module with user/password library  
- **Outcome:** Successful brute-force attack to gain access to `Ubuntu 18.04.5 LTS`  

### EternalBlue Exploit

- **Vulnerable Host:** `192.168.200.163`  
- **Port:** `445/TCP` (SMB)  
- **Tool:** Metasploit `ms17_010_psexec` module  
- **Outcome:** Successful exploitation resulting in a **Meterpreter session**  

---

## Network Discovery

Opochtli discovered **12 active hosts** on the `192.168.200.0/24` network range. Below are their details:

### Host: `192.168.200.10` (Ubuntu 18.04.5 LTS)

| Port | State | Service      | Version             |
|-------|-------|--------------|---------------------|
| 22    | Open  | SSH          | OpenSSH 7.6p1       |
| 80    | Open  | Apache HTTPD | Apache httpd 2.4.29 |
| 8080  | Open  | Tomcat       | Apache Tomcat 8.5.78|
| 8983  | Open  | Solr         | Apache SOLR         |

### Host: `192.168.200.15` (Windows Server 2008)

| Port  | State | Service       | Version                   |
|-------|-------|---------------|---------------------------|
| 135   | Open  | msrpc         | Microsoft Windows RPC     |
| 445   | Open  | microsoft-ds  | Windows Server 2008 R2 SP1|
| 49154 | Open  | unknown       | -                         |

### Host: `192.168.200.69`

| Port  | State | Service     | Version |
|-------|-------|-------------|---------|
| 45691 | Open  | SSL/Unknown | Unknown |

### Host: `192.168.200.84` (Linux)

| Port | State | Service | Version       |
|-------|-------|---------|---------------|
| 22    | Open  | SSH     | OpenSSH 7.6p1 |
| 3306  | Open  | MySQL   | MySQL         |

### Host: `192.168.200.163` (Windows Server DC)

| Port      | State | Service            | Version                    |
|-----------|-------|--------------------|----------------------------|
| 53        | Open  | Domain             | Simple DNS Plus            |
| 88        | Open  | Kerberos-sec       | MS Kerberos               |
| 135       | Open  | msrpc              | Microsoft Windows RPC     |
| 139       | Open  | netbios-ssn        | Microsoft netbios-ssn     |
| 389       | Open  | LDAP               | MS Active Directory LDAP  |
| 445       | Open  | microsoft-ds       | Windows Server 2008 R2-2012|
| 464       | Open  | kpasswd5?          | -                         |
| 593       | Open  | ncacn_http         | Windows RPC over HTTP     |
| 636       | Open  | tcpwrapped         | -                         |
| 3268      | Open  | LDAP               | MS AD LDAP                |
| 3269      | Open  | tcpwrapped         | -                         |
| 3389      | Open  | SSL/ms-wbt-server  | MS RPC                    |
| 49155-58  | Open  | msrpc              | Windows RPC               |

### Host: `192.168.200.228`

| Port  | State | Service     | Version |
|-------|-------|-------------|---------|
| 46413 | Open  | SSL/Unknown | Unknown |

### Host: `192.168.200.232` (Linux)

| Port   | State | Service     | Version       |
|--------|-------|-------------|---------------|
| 22     | Open  | SSH         | OpenSSH 7.9p1 |
| 80     | Open  | HTTP        | -             |
| 81     | Open  | HOSTS2-NS?  | -             |
| 1716   | Open  | XMSG?       | -             |
| 3050   | Open  | GDS_DB?     | -             |
| 3306   | Open  | MySQL       | MySQL         |
| 5000   | Open  | UPNP?       | -             |
| 33060  | Open  | MYSQLX?     | -             |

### Host: `192.168.200.234`

| Port | State | Service         | Version |
|-------|-------|-----------------|---------|
| 9292  | Open  | ARMTECHDAEMON?  | Unknown |

### Host: `192.168.200.239`

| Port  | State | Service     | Version |
|-------|-------|-------------|---------|
| 45921 | Open  | SSL/Unknown | Unknown |

### Host: `192.168.200.244`

| Port         | State | Service          | Version                 |
|--------------|-------|------------------|-------------------------|
| 135          | Open  | SSL/Unknown      | MS RPC                  |
| 139          | Open  | NETBIOS-SSN      | Microsoft netbios-ssn   |
| 445          | Open  | MICROSOFT-DS?    | -                       |
| 3389         | Open  | MS-WBT-SERVER    | MS Terminal Services    |
| 5040         | Open  | UNKNOWN          | -                       |
| 7680         | Open  | PANDO-PUB?       | -                       |
| 8000         | Open  | HTTP             | Splunkd httpd           |
| 8080         | Open  | HTTP-PROXY       | -                       |
| 8089         | Open  | SSL/HTTP         | -                       |
| 8191         | Open  | LIMNERPRESSURE?  | -                       |
| 9120         | Open  | Unknown          | -                       |
| 49664–49670  | Open  | MSRPC            | -                       |
| 59980        | Open  | MSRPC            | -                       |

### Host: `192.168.200.245`

| Port | State | Service           | Version          |
|-------|-------|-------------------|------------------|
| 81    | Open  | HTTP              | nginx 1.14.2     |
| 3050  | Open  | HADOOP-DATANODE   | Apache Hadoop    |
| 5000  | Open  | HTTP              | Docker Registry  |

### Host: `192.168.200.247` (Ubuntu 16)

| Port | State | Service      | Version                   |
|-------|-------|--------------|---------------------------|
| 25    | Open  | SMTP         | Postfix smtpd             |
| 80    | Open  | HTTP         | Apache 2.4.18 (Ubuntu)    |
| 139   | Open  | NETBIOS-SSN  | Samba 3.X - 4.X           |
| 445   | Open  | NETBIOS-SSN  | Samba 4.3.11-Ubuntu       |
| 3306  | Open  | MYSQL        | MySQL                     |
| 4000  | Open  | SSL/HTTP     | Greenbone Security Assistant |

---

## Remediation Recommendations

### High Priority

#### SSH_Login Exploit
- Enforce **strong password policies** across the domain.  
- Implement **account lockout policies** for failed login attempts.  
- Use **multi-factor authentication (MFA)** where applicable.

#### EternalBlue Exploit
- Ensure all systems, especially those running **Windows Server 2008 R2**, are patched with **MS17-010** and any related security updates.  
- Disable SMBv1 protocol if not required.  
- Employ **network segmentation** to isolate critical infrastructure such as domain controllers.  
- Use firewall rules to restrict SMB traffic.  
- Regularly scan for vulnerable hosts using automated tools.

---

## Conclusion

The penetration test identified critical vulnerabilities that could allow unauthorized access and complete system compromise. The SSH brute-force attack demonstrated weak credential usage, while the EternalBlue exploit revealed an unpatched, critical SMB vulnerability on a domain controller.

Immediate remediation should prioritize patching, hardening password policies, implementing MFA, and network segmentation to mitigate these risks and strengthen the security posture.

---

## References

- [MS17-010 Security Bulletin](https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010)  
- [Metasploit Framework Documentation](https://docs.metasploit.com/)  
- [Nmap Network Scanning](https://nmap.org/book/man.html)  
- [OWASP Brute Force Prevention](https://owasp.org/www-community/attacks/Brute_force_attack) 
