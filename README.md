![image](http://kodosaru.net/images/saku_robot__anton_yu_01.png)
NSS: *Nix Security Scanner
===========================
**NSS is a simple security scanner for Linux/Unix systems that serves two functions:**

1. Facilitates the hardening of a system by checking for proper configuration of:
    - SSH server
    - TCP Wrappers
    - Sudoers
    - Firewall
    - Selinux (Redhat only)
2. Aids the detection of intrusions by listing:
    - New, potentially unauthorized users
    - Suspicious logins
    - New open ports (TCP and/or UDP) indicating possible installation of malware
    - Suspicious reboots
    - Runtime load averages, indicator of possible malicious processes
    - Unauthorized sudo activity
     
<p>Can send warnings of suspicious activity or bad settings to email, pager or cellphone.</p>

**Sample Report**

    NSS Security Report for AETHER on 01/03/2014 at 00:14:51
    Up for 1 day(s) 12:57 hour(s) with 1, 5, & 15 minute load averages of 1.57, 1.62, 1.60
    
    *** Activity in the Last 24 Hours ***
    sudo by: none
    logins by: donj 
    reboots at time(s): none
    No new users found
    Warning: New TCP port(s) found:
    < 80/tcp    open  http

    *** System Configuration ***
    OK: SSHD is configured securely
    OK: TCP wrappers is enabled
    WARNING: File /etc/sudoers is insecurely configured: evilman	ALL=(ALL:ALL) ALL
    OK: Firewall is enabled and running
    
    Mailed alert to: kodosaru@gmail.com 
       
This utility has been used on Solaris, Redhat (CentOS and Fedora) and Ubuntu systems. Download the files to your local machine and execute `install.sh`.

**Happy Coding!**
