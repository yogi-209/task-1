network-port-scan-task Task 1: Local Network Port Scanning

Objective To perform a TCP SYN scan on the local network using Nmap and identify open ports and potential security risks.

Tools Used

Nmap
(Optional) Wireshark
IP Range Scanned 192.168.1.0/24

nmap -sS 192.168.1.0/24

Nmap scan report for 192.168.1.10 PORT STATE SERVICE 22/tcp open ssh 80/tcp open http

Nmap scan report for 192.168.1.15 PORT STATE SERVICE 445/tcp open microsoft-ds

Security Risks Identified Port 23 (Telnet) – Found open; transmits data unencrypted. Should be closed or replaced with SSH.

Port 445 (SMB) – Can be vulnerable to exploits like WannaCry if not patched.

Unnecessary ports open on printer/router interfaces.

Recommendations Close unused ports.

Use a firewall to restrict access.

Regularly scan local network.

Disable legacy services (e.g., Telnet, SMBv1).

Files Included scan_results.txt: Nmap scan output

services_risk_analysis.txt: Common service risks

wireshark_capture.png: (Optional) Screenshot from Wireshark

What is an open port? A network port that is actively accepting connections from remote clients.

How does Nmap perform a TCP SYN scan? It sends a SYN packet and waits for a SYN-ACK (open) or RST (closed) response. It's stealthy because it doesn't complete the handshake.

What risks are associated with open ports? They expose services that can be exploited if misconfigured, outdated, or unnecessary.

Explain TCP vs UDP scanning.

TCP scanning uses SYN/ACK handshakes.

UDP scanning sends a packet and waits for a response or ICMP error.

How can open ports be secured? Disable unused services, configure firewalls, use encryption, keep software updated.

What is a firewall’s role with ports? It allows or blocks traffic on specific ports based on rules.

Why do attackers perform port scans? To identify potential vulnerabilities in exposed services.

How does Wireshark complement port scanning? It visually shows the SYN, ACK, and RST packets — useful for understanding how scans work.
# task-1
