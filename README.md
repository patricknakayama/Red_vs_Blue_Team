# Red vs Blue Team

This document contains the following details:
- Description of Project
  - Scenario
  - Tasks
  - Summary of Engagement
- Tools and Technologies
- [Defensive Security Summary](DefensiveSummary.md)
- [Offensive Security Summary](OffensiveSummary.md)
- [Network Forensics Summary](NetworkSummary.md)

---

### Description of Project

The main purpose of this project is to simulate a SOC environment and demonstrate concepts in Defensive Security, Offensive Security, and Network Forensics.

  - Scenario
    - SOC Analysts have noticed some discrepancies with alerting in the Kibana system.
    - Monitor live traffic on the wire to detect any abnormalities that aren't reflected in the alerting system.
    - Report back your findings to the SOC manager and the Engineering Manager with appropriate analysis.

  - Tasks
    - Defensive Security: Implement the alerts and thresholds.
    - Offensive Security: Assess a vulnerable VM and verify that the kibana rules work as expected.
    - Network Forensics: Use Wireshark to analyze live malicious traffic on the wire.

  - Summary of Engagement
    - Configured `Kibana` alerts in `Elasticsearch Watcher` to monitor WordPress installation.
    - Scanned network with `netdiscover` to identify IP addresses of Targets.
    - Identified exposed ports and services with `Nmap`.
    - Enumerated site with `WPScan`, `Nikto`, and `Gobuster`.
    - Exploited vulnerable web server on Target 1 to obtain credentials from `MySQL` database and gain user shell via `SSH`.
    - Exploited PHPMailer Remote Code Execution vulnerability on Target 2 to open shell session using Ncat listener.
    - Performed network forensic analysis on live malicious traffic using `Wireshark` and `VirusTotal`.
    - Identified compromised machines and provided security recommendations.

---

### Tools and Technologies

- ELK (Elastic) Stack
  - Kibana
  - Elasticsearch Watcher
  - Filebeat
  - Metricbeat
  - Packetbeat
- Netdiscover
- Nmap
- WPScan
- Nikto
- Gobuster
- Ncat
- MySQL DB
- John
- SSH
- Searchsploit
- Wireshark
- Virustotal

---

### Defensive Security Summary

  - [DefensiveSummary.md](DefensiveSummary.md) contains the Blue Team Summary of Operations.

### Offensive Security Summary

  - [OffensiveSummary.md](OffensiveSummary.md) contains the Red Team Summary of Operations.

### Network Forensics Summary

  - [NetworkSummary.md](NetworkSummary.md) contains the Network Forensic Analysis Report.