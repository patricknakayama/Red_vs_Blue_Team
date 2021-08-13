# Network Forensic Analysis Report

## Table of Contents
- Overview
- Time Thieves
- Vulnerable Windows Machines
- Illegal Downloads

## Overview
You are working as a Security Engineer for X-CORP, supporting the SOC infrastructure. The SOC analysts have noticed some discrepancies with alerting in the Kibana system and the manager has asked the Security Engineering team to investigate. You will monitor live traffic on the wire to detect any abnormalities that aren't reflected in the alerting system. You are to report back all your findings to both the SOC manager and the Engineering Manager with appropriate analysis.

The Security team requested this analysis because they have evidence that people are misusing the network. Specifically, they've received tips about:

- "Time thieves" spotted watching YouTube during work hours.
- At least one Windows host infected with a virus.
- Illegal downloads.

A number of machines from foreign subnets are sending traffic to this network. Your task is to collect evidence confirming the Security team's intelligence.

---

## Time Thieves 

At least two users on the network have been wasting time on YouTube. Usually, IT wouldn't pay much mind to this behavior, but it seems these people have created their own web server on the corporate network. So far, Security knows the following about these time thieves:
- They have set up an Active Directory network.
- They are constantly watching videos on YouTube.
- Their IP addresses are somewhere in the range `10.6.12.0/24`.

Wireshark Filters Used:
- Domain of custom site: `ip.addr == 10.6.12.0/24`
- Active Directory DC IP Address: `ip.addr == 10.6.12.0/24`
- Traffic Inspection: `ip.addr == 10.6.12.12`
- Traffic Inspection: `ip.addr == 10.6.12.203`
- Malware Name: `ip.addr == 10.16.12.203 and http.request.method==GET`

You must inspect your traffic capture to answer the following questions:

1. What is the domain name of the users' custom site?
    - **Frank-n-Ted-DC.frank-n-ted.com**
    - Wireshark Filter: `ip.addr == 10.6.12.0/24`

![Time Thieves Domain](Images/TT_domain.png)

2. What is the IP address of the Domain Controller (DC) of the AD network?
    - **10.6.12.12**
    - Wireshark Filter: `ip.addr == 10.6.12.0/24`

![Time Thieves Domain](Images/TT_ip.png)

3. What is the name of the malware downloaded to the 10.6.12.203 machine?
    - **june11.dll**
    - Wireshark Filter: `ip.addr==10.16.12.203 and http.request.method==GET`

![Time Thieves Domain](Images/TT_malware.png)

4. Upload the file to [VirusTotal.com](https://www.virustotal.com/gui/). 
    - Exporting file to Kali:
        - Open File Tab.
        - Export Objects.
        - Select HTTP.
        - Add text filter ".dll".
        - Save june11.dll.
        - Upload to virustotal.

![Time Thieves Domain](Images/TT_download.png)

5. What kind of malware is this classified as?
    - This is a **trojan**.

![Time Thieves Domain](Images/TT_virustotal.png)

---

## Vulnerable Windows Machine

The Security team received reports of an infected Windows host on the network. They know the following:
- Machines in the network live in the range `172.16.4.0/24`.
- The domain mind-hammer.net is associated with the infected computer.
- The DC for this network lives at `172.16.4.4` and is named Mind-Hammer-DC.
- The network has standard gateway and broadcast addresses.

Wireshark Filters Used:
- Host Name, IP Address, MAC Address: `ip.addr == 172.16.4.0/24`
- Traffic Inspection: `ip.src == 172.16.4.4 && kerberos.CNameString`
- Username: `ip.src == 172.16.4.205 && kerberos.CNameString`
- Malicious Traffic: `ip.addr == 172.16.4.205 && ip.addr == 185.243.115.84`

Inspect your traffic to answer the following questions in your network report:

1. Find the following information about the infected Windows machine:
    - **Host name**: Rotterdam-PC
    - **IP address**: 172.16.4.205
    - **MAC address**: 00:59:07:b0:63:a4
    - **Wireshark Filter**: `ip.addr == 172.16.4.0/24`

![Vulnerable Windows Machines IP](Images/VWM_ip.png)

![Vulnerable Windows Machines MAC](Images/VWM_mac.png)

2. What is the username of the Windows user whose computer is infected?
    - **matthijs.devries**
    - Wireshark Filter: `ip.src == 172.16.4.205 && kerberos.CNameString`

![Vulnerable Windows Machines Username](Images/VWM_username.png)

3. What are the IP addresses used in the actual infection traffic?
    - **172.16.4.205 | 185.243.115.84 | 166.62.11.64**
    - Finding the IP addresses:
        - Open Statistics Tab.
        - Click Conversations.
        - Select IPv4.
        - Sort Packets high to low.

![Vulnerable Windows Machines Infection Traffic 1](Images/VWM_infection_traffic1.png)

- Additional Traffic from 185.243.115.84 to infected host 172.16.4.205:

![Vulnerable Windows Machines Infection Traffic 2](Images/VWM_infection_traffic2.png)

---

## Illegal Downloads

IT was informed that some users are torrenting on the network. The Security team does not forbid the use of torrents for legitimate purposes, such as downloading operating systems. However, they have a strict policy against copyright infringement.

IT shared the following about the torrent activity:

- The machines using torrents live in the range `10.0.0.0/24` and are clients of an AD domain.
- The DC of this domain lives at `10.0.0.2` and is named DogOfTheYear-DC.
- The DC is associated with the domain dogoftheyear.net.

Wireshark Filters Used:
- MAC Address: `ip.addr == 10.0.0.201 && dhcp`
- Username: `ip.src == 10.0.0.201 && kerberos.CNameString`
- Operating System: `ip.addr == 10.0.0.201 && http.request`
- Torrent Download: `ip.addr == 10.0.0.201 && http.request.method == "GET"`

Your task is to isolate torrent traffic and answer the following questions in your Network Report:

1. Find the following information about the machine with IP address `10.0.0.201`:
    - **MAC address**: 00:16:17:18:66:c8
    - **Windows username**: elmer.blanco
    - **OS version**: Windows NT 10.0, x64
- Wireshark Filter for MAC: `ip.addr == 10.0.0.201 && dhcp`

![Illegal Downloads MAC](Images/ID_mac.png)

- Wireshark Filter for Username: `ip.src == 10.0.0.201 && kerberos.CNameString`

![Illegal Downloads Username](Images/ID_username.png)

- Wireshark Filter for OS: `ip.addr == 10.0.0.201 && http.request`

![Illegal Downloads OS](Images/ID_os.png)

2. Which torrent file did the user download?
    - **Betty_Boop_Rhythm_on_the_Reservation.avi.torrent**
    - Wireshark Filter: `ip.addr == 10.0.0.201 && http.request.method == "GET"`
    - Finding the torrent:
        - Apply the Wireshark Filter above.
        - Sort the packets by the Destination `files.publicdomaintorrents.com` (168.215.194.14).
        - Look for Download request.

![Illegal Downloads Torrent](Images/ID_torrent.png)