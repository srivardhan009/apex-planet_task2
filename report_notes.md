# Task 2 — Network Security & Scanning (ApexPlanet)

**Target:** Metasploitable (192.168.1.3)  
**Scanner:** GVM / OpenVAS  
**Files:** scan-report.pdf, report.xml

## Summary
A full OpenVAS scan of Metasploitable (192.168.1.3) discovered multiple high-severity services.  
Top issues include weak authentication and outdated network services.  
The host’s risk rating is High (CVSS 10.0 overall).


## Top Findings
1. **FTP (21/tcp)** — Severity: High — Anonymous login allowed, credentials can be intercepted.  
   *Fix:* Disable anonymous access or use SFTP/SSH with authentication.

2. **HTTP (80/tcp)** — Severity: High — Outdated Apache version vulnerable to remote code execution.  
   *Fix:* Update Apache to the latest stable release and patch CVEs.

3. **MySQL (3306/tcp)** — Severity: High — Default root account without password.  
   *Fix:* Set a strong root password and restrict external connections.

4. **PostgreSQL (5432/tcp)** — Severity: High — Database accessible from any host.  
   *Fix:* Limit access to localhost or trusted IPs in pg_hba.conf.

5. **VNC (5900/tcp)** — Severity: High — Unauthenticated remote desktop service exposed.  
   *Fix:* Disable or password-protect VNC and use SSH tunneling if needed.


## How I scanned
- Nmap: `nmap -A -oN nmap-output.txt 192.168.1.3`
- GVM: full scan, exported PDF & XML

## Artifacts in this folder
- scan-report-firstpart.txt (first 400 lines of PDF)
- report-xml-firstpart.txt (first 300 lines of XML)
- scan-report.pdf

## Nmap scan summary
- Target: 192.168.56.101
- Scan type: Full (-A, -sV, -Pn)
- Scan file: nmap-full-192.168.56.101.txt
- Key open services observed: ftp (21), ssh (22), telnet (23), http (80), smb (139/445), mysql (3306), postgresql (5432), vnc (5900), bindshell (1524), proftpd (2121), tomcat (8180).
- Note: Several services allow anonymous or weak access (e.g., anonymous FTP, open MySQL) — see report for details.


## Packet Analysis
- Capture file: capture.pcap (size: 242K, captured ~2546 packets)
- Tools used: tcpdump (capture) and tcpdump/tshark (analysis)
- Key observations (from capture):
  - ARP resolved 192.168.56.101 → 08:00:27:b0:b4:be.
  - Multiple SYNs from Kali (192.168.56.102) to many ports on target (typical Nmap service scan).
  - FTP (21), MySQL (3306), HTTP (80), SSH (22), PostgreSQL (5432), VNC (5900) and other service packets observed.
  - Anonymous FTP login and other plaintext or unauthenticated services likely present (see OpenVAS findings).
- Files added: capture.pcap, packet-analysis.txt, nmap-packet-test.txt

(You can add more detail here after reviewing packet-analysis.txt or opening capture.pcap in Wireshark.)

## Firewall Basics (iptables demo)
- **Goal:** Demonstrate basic outbound firewall control using iptables.
- **Rule Added:** Drop all outgoing TCP packets to 192.168.56.101:2121  
  (`sudo iptables -I OUTPUT -d 192.168.56.101 -p tcp --dport 2121 -j DROP`)
- **Result:** Nmap shows port 2121 as *open* before and *filtered* after the rule.
- **Files Created:** firewall-status.txt, iptables-before.txt, iptables-after.txt, iptables-restored.txt, before-block-2121.txt, after-block-2121.txt
