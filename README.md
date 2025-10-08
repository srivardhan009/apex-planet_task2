# apex-task_2
Task-2 —  Network Security &amp; Scanning

//INTERNSHIP TASK 2 OF NETWORK SECURITY  AND SCANNING

NAME:- Parvatham Sri Vardhan 
INTERN ID:- APSPL2519629
# Task 2 — Network Security & Scanning (Apex Planet)

## 🧩 Overview
This task demonstrates vulnerability scanning, network mapping, packet analysis, and basic firewall configuration using Kali Linux tools.

## ⚙️ Tools Used
- **Nmap** — Network discovery & service enumeration  
- **OpenVAS / GVM** — Vulnerability scanning  
- **Tcpdump / Wireshark** — Packet capture & analysis  
- **iptables** — Firewall basics  

## 📁 Files & Artifacts
| File | Description |
|------|--------------|
| `OpenVAS-GVM-results.pdf` | Full OpenVAS vulnerability scan report |
| `report.xml` | XML export from GVM |
| `report_notes.md` | Notes and summary of findings |
| `capture.pcap` | Packet capture from tcpdump |
| `packet-analysis.txt` | Human-readable analysis of first 200 packets |
| `nmap-full-192.168.56.101.txt` | Full Nmap service/version scan |
| `iptables-before.txt`, `iptables-after.txt`, `iptables-restored.txt` | Firewall test logs |
| `firewall-status.txt` | Summary of firewall changes |
| `ss/` | Folder containing screenshots of each step |

## 🧠 Key Findings
- Multiple **high-severity vulnerabilities** detected on Metasploitable2 target.  
- Services with weak authentication: FTP, MySQL, VNC.  
- Firewall rule successfully blocked outbound traffic to port 2121

