# app/utils.py
import pandas as pd
import os
import time
import requests

def generate_firewall_rules(open_ports, action, filter_ip, os_type):
    firewall_rules = []

    for port in open_ports:
        firewall_rule = generate_firewall_rule(port, action, filter_ip, os_type)
        firewall_rules.append(firewall_rule)

    return firewall_rules

def generate_firewall_rule(port, action, filter_ip, os_type):
    if os_type.lower() == 'linux':
        if action.lower() == 'allow':
            return f"iptables -A INPUT -p tcp --dport {port} -j ACCEPT"
        elif action.lower() == 'block':
            return f"iptables -A INPUT -p tcp --dport {port} -j DROP"
        elif action.lower() == 'filter' and filter_ip:
            return f"iptables -A INPUT -p tcp --dport {port} -s {filter_ip} -j ACCEPT"
        else:
            return 'Unsupported action'
    elif os_type.lower() == 'windows':
        if action.lower() == 'allow':
            return f"netsh advfirewall firewall add rule name='Allow Port {port}' dir=in action=allow protocol=TCP localport={port}"
        elif action.lower() == 'block':
            return f"netsh advfirewall firewall add rule name='Block Port {port}' dir=in action=block protocol=TCP localport={port}"
        elif action.lower() == 'filter' and filter_ip:
            return f"netsh advfirewall firewall add rule name='Filter Port {port}' dir=in action=allow protocol=TCP localport={port} remoteip={filter_ip}"
        else:
            return 'Unsupported action'
    elif os_type.lower() == 'osx':
        if action.lower() == 'allow':
            return f"pass in proto tcp from any to any port {port}"
        elif action.lower() == 'block':
            return f"block in proto tcp from any to any port {port}"
        elif action.lower() == 'filter' and filter_ip:
            return f"pass in proto tcp from {filter_ip} to any port {port}"
        else:
            return 'Unsupported action'
    else:
        return 'Unsupported operating system'
    

def fill_data_for_cve(cve_id, year):
    csv_file_path = f'output_cve_{year}.csv'
    if os.path.exists(csv_file_path):
        csv_data = pd.read_csv(csv_file_path)
        if cve_id in csv_data['ID'].values:
            csv_row = csv_data[csv_data['ID'] == cve_id].iloc[0]
        new_data = pd.DataFrame({
            'ID': [cve_id],
            'Version': [csv_row['Version']],
            'AccessVector': [csv_row['AccessVector']],
            'AccessComplexity': [csv_row['AccessComplexity']],
            'Authentication': [csv_row['Authentication']],
            'ConfidentialityImpact': [csv_row['ConfidentialityImpact']],
            'IntegrityImpact': [csv_row['IntegrityImpact']],
            'AvailabilityImpact': [csv_row['AvailabilityImpact']],
            'BaseScore': [csv_row['BaseScore']],
            'Severity': [csv_row['Severity']],
            'ExploitabilityScore': [csv_row['ExploitabilityScore']],
            'ImpactScore': [csv_row['ImpactScore']],
            'ACInsufInfo': [csv_row['ACInsufInfo']],
            'ObtainAllPrivilege': [csv_row['ObtainAllPrivilege']],
            'ObtainUserPrivilege': [csv_row['ObtainUserPrivilege']],
            'ObtainOtherPrivilege': [csv_row['ObtainOtherPrivilege']],
            'UserInteractionRequired': [csv_row['UserInteractionRequired']]
        })
        return new_data
    else:
        return pd.DataFrame()
        
def clean_data_for_serialization(data):
    # Exclude any non-serializable keys from the data
    return {key: value for key, value in data.items() if not callable(value)}

def get_cve_info_list(host_info):
    cve_info_list = []
    if 'vulns' in host_info:
        for cve in host_info['vulns']:
            print(f"Sleeping before request for CVE {cve}")
            time.sleep(1)
            response = requests.get(f'https://services.nvd.nist.gov/rest/json/cve/1.0/{cve}?api_key={NVD_API_KEY}')
            if response.status_code == 200:
                cve_info_data = fill_data_for_cve(cve)
                cve_info_data['HostInfo'] = clean_data_for_serialization(host_info)
                cve_info_data['NVDData'] = response.json()
                cve_info_list.append(cve_info_data.to_dict())
            else:
                cve_info_list.append({"Error": "Error Retrieving the data from NIST"})
    return cve_info_list




common_ports = {
    1: "TCPMUX (TCP Port Service Multiplexer) - Used for TCP multiplexing service.",
    5: "Remote Job Entry - Used for Remote Job Entry.",
    7: "Echo Protocol - Used for Echo Protocol.",
    9: "Discard Protocol - Used for Discard Protocol.",
    11: "SYSTAT Service - Used for Active Users.",
    13: "Daytime Protocol - Used for Daytime Protocol.",
    17: "Quote of the Day - Used for Quote of the Day.",
    18: "Message Send Protocol - Used for Message Send Protocol.",
    19: "Character Generator Protocol - Used for Character Generator Protocol.",
    20: "FTP (File Transfer Protocol) - Used for FTP Data Transfer.",
    21: "FTP (File Transfer Protocol) - Used for FTP Control.",
    22: "SSH (Secure Shell) - Used for Secure Shell.",
    23: "Telnet - Used for Telnet.",
    25: "SMTP (Simple Mail Transfer Protocol) - Used for SMTP.",
    37: "Time Protocol - Used for Time Protocol.",
    39: "RLP (Resource Location Protocol) - Used for RLP.",
    42: "Host Name Server Protocol - Used for Host Name Server.",
    43: "WHOIS Protocol - Used for WHOIS.",
    49: "TACACS Login Host Protocol - Used for TACACS.",
    50: "Remote Mail Checking Protocol - Used for Remote Mail Checking.",
    53: "DNS (Domain Name System) - Used for DNS.",
    63: "WHOIS++ Protocol - Used for WHOIS++.",
    67: "Boot Protocol - Used for Bootstrap Protocol.",
    68: "Boot Protocol - Used for Bootstrap Protocol.",
    69: "TFTP (Trivial File Transfer Protocol) - Used for TFTP.",
    70: "Gopher Protocol - Used for Gopher.",
    79: "Finger Protocol - Used for Finger.",
    80: "HTTP (Hypertext Transfer Protocol) - Used for HTTP.",
    87: "LINK Protocol - Used for LINK.",
    88: "Kerberos - Used for Kerberos.",
    95: "SUPDUP (Telnet protocol extension) - Used for SUPDUP.",
    101: "NIC Host Name Server Protocol - Used for NIC Host Name Server.",
    102: "ISO-TSAP Protocol - Used for ISO-TSAP.",
    105: "CSNET-NS Protocol - Used for CSNET-NS.",
    107: "Remote Telnet Service Protocol - Used for Remote Telnet Service.",
    109: "POP2 (Post Office Protocol version 2) - Used for POP2.",
    110: "POP3 (Post Office Protocol version 3) - Used for POP3.",
    111: "SUN Remote Procedure Call - Used for SUN RPC.",
    113: "Ident Protocol - Used for Ident.",
    115: "SFTP (Simple File Transfer Protocol) - Used for SFTP.",
    117: "UUCP Path Service Protocol - Used for UUCP Path Service.",
    119: "NNTP (Network News Transfer Protocol) - Used for NNTP.",
    123: "NTP (Network Time Protocol) - Used for NTP.",
    137: "NETBIOS Name Service Protocol - Used for NETBIOS Name Service.",
    138: "NETBIOS Datagram Service Protocol - Used for NETBIOS Datagram Service.",
    139: "NETBIOS Session Service Protocol - Used for NETBIOS Session Service.",
    143: "IMAP (Internet Message Access Protocol) - Used for IMAP.",
    152: "BFTP (Background File Transfer Protocol) - Used for BFTP.",
    153: "SGMP (Simple Gateway Monitoring Protocol) - Used for SGMP.",
    156: "SQL Service Protocol - Used for SQL Service.",
    158: "PCMail Server Protocol - Used for PCMail Server.",
    161: "SNMP (Simple Network Management Protocol) - Used for SNMP.",
    162: "SNMP Trap - Used for SNMP Trap.",
    163: "CMIP/TCP Manager - Used for CMIP/TCP Manager.",
    164: "CMIP/TCP Agent - Used for CMIP/TCP Agent.",
    174: "MAILQ Protocol - Used for MAILQ.",
    177: "XDMCP (X Display Manager Control Protocol) - Used for XDMCP.",
    178: "NextStep Window Server - Used for NextStep Window Server.",
    179: "BGP (Border Gateway Protocol) - Used for BGP.",
    180: "Intergraph - Used for Intergraph.",
    194: "IRC (Internet Relay Chat) - Used for IRC.",
    199: "SMUX (SNMP Unix Multiplexer) - Used for SNMP Unix Multiplexer.",
    201: "AppleTalk Routing Maintenance - Used for AppleTalk Routing Maintenance.",
    209: "The Quick Mail Transfer Protocol - Used for The Quick Mail Transfer Protocol.",
    210: "ANSI Z39.50 Protocol - Used for ANSI Z39.50 Protocol.",
    213: "IPX - Used for IPX.",
    218: "MTS - Used for MTS.",
    220: "IMAP (Internet Message Access Protocol) - Used for IMAP.",
    259: "ESRO (Efficient Short Remote Operations) - Used for ESRO.",
    262: "ARCnet - Used for ARCnet.",
    264: "BGMP (Border Gateway Multicast Protocol) - Used for BGMP.",
    280: "HTTP-MGMT - Used for HTTP-MGMT.",
    308: "Novastor Backup - Used for Novastor Backup.",
    311: "Mac OS X Server Admin - Used for Mac OS X Server Admin.",
    318: "PKIX TimeStamp - Used for PKIX TimeStamp.",
    323: "IMMP (Internet Message Mapping Protocol) - Used for IMMP.",
    366: "ODMR (On-Demand Mail Relay) - Used for ODMR.",
    369: "RPC2PORTMAP - Used for RPC2PORTMAP.",
    370: "codaauth2 - Used for codaauth2.",
    372: "ListProcessor - Used for ListProcessor.",
    389: "LDAP (Lightweight Directory Access Protocol) - Used for LDAP.",
    406: "Interactive Mail Support Protocol - Used for Interactive Mail Support Protocol.",
    427: "SLP (Service Location Protocol) - Used for SLP.",
    443: "HTTPS (HTTP Secure) - Used for HTTPS.",
    444: "SNPP (Simple Network Paging Protocol) - Used for SNPP.",
    445: "Microsoft-DS - Used for Microsoft-DS.",
    464: "Kerberos Change/Set Password - Used for Kerberos Change/Set Password.",
    465: "SMTPS (SMTP Secure) - Used for SMTPS.",
    475: "tcpnethaspsrv - Used for tcpnethas",
    500: "ISAKMP (Internet Security Association and Key Management Protocol) - Used for VPN establishment.",
    512: "Biff Protocol - Used for mail notification.",
    513: "rlogin (Remote Login) - Used for remote login.",
    514: "syslog (Syslog Protocol) - Used for system logging.",
    515: "Line Printer Daemon Protocol - Used for printing over a network.",
    520: "RIP (Routing Information Protocol) - Used for routing information exchange.",
    521: "RIPng (Next Generation Routing Information Protocol) - Used for IPv6 routing information exchange.",
    523: "IBM-DB2 - Used for IBM DB2 database communication.",
    524: "NetWare Core Protocol - Used for Novell NetWare communication.",
    525: "Time Protocol - Used for time synchronization.",
    530: "RPC - Used for Remote Procedure Call communication.",
    531: "IRC (Internet Relay Chat) - Used for IRC.",
    532: "NetNews - Used for Usenet news transfer.",
    540: "UUCP (Unix-to-Unix Copy Protocol) - Used for Unix file sharing.",
    546: "DHCPv6 Client - Used for DHCPv6 client requests.",
    547: "DHCPv6 Server - Used for DHCPv6 server responses.",
    548: "AFP (Apple Filing Protocol) - Used for Mac file sharing.",
    549: "IDFP (IDFP Protocol) - Used for remote filesystem access.",
    554: "RTSP (Real Time Streaming Protocol) - Used for streaming media delivery.",
    556: "Remotefs - Used for file system mounting.",
    563: "NNTPS (NNTP Secure) - Used for secure NNTP communication.",
    587: "Submission (Email Submission) - Used for email submission.",
    591: "FileMaker - Used for FileMaker database communication.",
    593: "Microsoft DCOM - Used for Distributed Component Object Model communication.",
    601: "syslog-conn (Reliable Syslog Service) - Used for reliable syslog transmission.",
    636: "LDAPS (LDAP Secure) - Used for secure LDAP communication.",
    666: "Doom - Used for Doom multiplayer gaming.",
    691: "MS Exchange Routing - Used for Microsoft Exchange routing.",
    989: "FTP (File Transfer Protocol) Data over TLS/SSL - Used for secure FTP data transfer.",
    990: "FTP (File Transfer Protocol) Control over TLS/SSL - Used for secure FTP control.",
    993: "IMAPS (IMAP Secure) - Used for secure IMAP communication.",
    995: "POP3S (POP3 Secure) - Used for secure POP3 communication.",
    1080: "SOCKS Proxy - Used for proxy services.",
    1194: "OpenVPN - Used for VPN communication.",
    1234: "Hotline Protocol - Used for Hotline server communication.",
    1433: "MSSQL - Used for Microsoft SQL Server database communication.",
    1434: "MS SQL Monitor - Used for Microsoft SQL Server monitoring.",
    1512: "Wins (Windows Internet Naming Service) - Used for Windows networking.",
    1521: "Oracle SQL - Used for Oracle database communication.",
    1723: "PPTP (Point-to-Point Tunneling Protocol) - Used for VPN tunneling.",
    1725: "Steam - Used for Steam gaming platform.",
    1812: "RADIUS - Used for remote authentication.",
    1813: "RADIUS Accounting - Used for remote authentication accounting.",
    2049: "NFS (Network File System) - Used for file sharing.",
    2082: "cPanel - Used for web hosting control panel.",
    2083: "cPanel SSL - Used for secure web hosting control panel.",
    2086: "WHM (Web Host Manager) - Used for web hosting management.",
    2087: "WHM SSL (Web Host Manager SSL) - Used for secure web hosting management.",
    2100: "Oracle XDB - Used for Oracle XML DB communication.",
    2222: "DirectAdmin - Used for web hosting control panel.",
    2375: "Docker REST API - Used for Docker container management.",
    2376: "Docker - Used for Docker container management over TLS.",
    3128: "Squid Proxy - Used for caching proxy services.",
    3306: "MySQL - Used for MySQL database communication.",
    3389: "RDP (Remote Desktop Protocol) - Used for remote desktop access.",
    3690: "SVN (Subversion) - Used for version control system.",
    4040: "CUPS (Common Unix Printing System) - Used for printer sharing.",
    4333: "mSQL - Used for Mini SQL database communication.",
    4353: "F5 iQuery - Used for F5 BIG-IP iQuery communication.",
    44818: "EtherNet/IP Explicit Messaging - Used for industrial control systems.",
    4500: "IPsec NAT Traversal - Used for IPsec VPN NAT traversal.",
    4567:"Sinatra default server port in development mode (HTTP)",
    5000: "UPnP (Universal Plug and Play) - Used for device discovery and control.",
    5432: "PostgreSQL - Used for PostgreSQL database communication.",
    5433: "Bouwsoft File Server - Used for Bouwsoft file sharing.",
    5500: "VNC (Virtual Network Computing) - Used for remote desktop access.",
    5800: "VNC HTTP - Used for VNC over HTTP.",
    5900: "VNC (Virtual Network Computing) - Used for remote desktop access.",
    6000: "X11 - Used for remote graphical user interface.",
    6543: "PostgreSQL - Used for PostgreSQL database communication.",
    6660: "IRC (Internet Relay Chat) - Used for IRC.",
    6661: "IRC (Internet Relay Chat) - Used for IRC.",
    6662: "IRC (Internet Relay Chat) - Used for IRC.",
    6663: "IRC (Internet Relay Chat) - Used for IRC.",
    6664: "IRC (Internet Relay Chat) - Used for IRC.",
    6665: "IRC (Internet Relay Chat) - Used for IRC.",
    6666: "IRC (Internet Relay Chat) - Used for IRC.",
    6667: "IRC (Internet Relay Chat) - Used for IRC.",
    6668: "IRC (Internet Relay Chat) - Used for IRC.",
    6669: "IRC (Internet Relay Chat) - Used for IRC.",
    6679: "IRC SSL (Internet Relay Chat Secure) - Used for secure IRC communication.",
    6697: "IRC SSL (Internet Relay Chat Secure) - Used for secure IRC communication.",
    6881: "BitTorrent - Used for BitTorrent file sharing.",
    6969: "BitTorrent Tracker - Used for BitTorrent tracker communication.",
    7000: "IRC (Internet Relay Chat) - Used for IRC.",
    7001: "IBM WebSphere Administration - Used for IBM WebSphere administration.",
    7070: "RealServer - Used for RealServer media streaming.",
    8000: "HTTP (Hypertext Transfer Protocol) - Alternate port for web servers.",
    8008: "HTTP Alternate - Alternate port for HTTP web servers.",
    8080: "HTTP Alternate - Alternate port for web servers.",
    8087: "Hosting Accelerator Control Panel - Used for hosting control panels.",
    8443: "HTTPS (HTTP Secure) Alternate - Alternate port for secure web servers.",
    8444: "Bitmessage p2p encrypted communication protocol uses this port by default",
    8888: "HTTP Alternate - Alternate port for web servers.",
    9000: "CSlistener - Used for ColdFusion server.",
    9001: "Tor Network - Used for Tor network control.",
    9100: "Printer Spooler - Used for printer spooling.",
    9999: "Telnet Alternate - Alternate port for Telnet.",
    10000: "Webmin - Used for web-based server administration.",
    11371: "OpenPGP HTTP Keyserver - Used for OpenPGP keyserver communication.",
    13720: "NetBackup - Used for NetBackup software.",
    19226: "Admin Server - Used for Admin Server management.",
    20000: "DNP (Distributed Network Protocol) - Used for DNP3 communication.",
    22125: "GSRemote - Used for Goldengate remote.",
    22273: "wnn6 - Used for wnn6 Japanese input.",
    24554: "BINKP - Used for Binkp Fidonet mailer.",
    27374: "SubSeven - Used for SubSeven trojan horse.",
    29891: "Barracuda - Used for Barracuda administration.",
    30000: "Bind Shell - Used for remote command execution.",
    30718: "RealServer - Used for RealServer media streaming.",
    31337: "Back Orifice - Used for Back Orifice trojan horse.",
    32768: "Filenet RMI - Used for FileNet content engine communication.",
    32769: "Filenet RPC - Used for FileNet RPC communication.",
    32770: "Filenet PCH - Used for FileNet PCH communication.",
    32771: "Filenet NCH - Used for FileNet NCH communication.",
    32772: "Filenet TNOS Service - Used for FileNet TNOS service.",
    32773: "Filenet RMI IIOP - Used for FileNet RMI IIOP communication.",
    32774: "Filenet Web Manager - Used for FileNet web manager communication.",
    32775: "Filenet Process Analyzer - Used for FileNet process analyzer communication.",
    32776: "Filenet BPM - Used for FileNet BPM communication.",
    33434: "Traceroute - Used for traceroute tool.",
    33445: "Traceroute - Used for traceroute tool.",
    36865: "KastenX Pipe - Used for KastenX pipe server.",
    55055: "VNC HTTP - Used for VNC over HTTP.",
    65205: "ESRI SDE Instance - Used for ESRI SDE instance.",
}

