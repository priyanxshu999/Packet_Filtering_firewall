Custom Firewall and Packet Sender
Overview
```                                                                 
   ad88 88                                                     88 88  
  d8"   ""                                                     88 88  
  88                                                           88 88  
MM88MMM 88 8b,dPPYba,  ,adPPYba, 8b      db      d8 ,adPPYYba, 88 88  
  88    88 88P'   "Y8 a8P_____88 `8b    d88b    d8' ""     `Y8 88 88  
  88    88 88         8PP"""""""  `8b  d8'`8b  d8'  ,adPPPPP88 88 88  
  88    88 88         "8b,   ,aa   `8bd8'  `8bd8'   88,    ,88 88 88  
  88    88 88          `"Ybbd8"'     YP      YP     `"8bbdP"Y8 88 88

```

This project has two main components: a firewall that blocks or allows network traffic based on rules you set, and a packet sender that can send custom TCP and UDP packets. The firewall uses raw sockets to capture and analyze incoming packets, allowing you to block traffic based on IPs, subnets, and ports.
Features

    Easy Blocking: Add IPs, subnets, and ports to block.
    Supports Multiple Protocols: Works with ICMP, TCP, and UDP.
    Dynamic Blocking: Block or unblock IPs and ports anytime.
    Packet Logging: Logs the details of every packet.
    Packet Sender: Send custom TCP and UDP packets.

Prerequisites

    Python 3.x
    Admin privileges (required for raw sockets)

Setup
Clone the Repository

bash

git clone https://github.com/yourusername/custom-firewall-packet-sender.git
cd custom-firewall-packet-sender

Install Dependencies

No additional dependencies are needed.
Firewall Usage
Configuration

Edit the BLOCKED_IPS, BLOCKED_SUBNETS, and BLOCKED_PORTS lists in the script to specify what you want to block.
Run the Firewall

bash

sudo python3 firewall.py

Dynamic Blocking

You can block or unblock IPs and ports while the firewall is running by using these functions:

python

block_ip("192.168.1.10")
unblock_ip("192.168.1.10")
block_port(8080)
unblock_port(8080)

Raw Packet Sender Usage
Example Packets

The script includes example TCP and UDP packets that you can modify or use as they are.
Send Packets

    Set the destination IP address:

    python

destination_ip = '172.16.27.105'  # Replace with the correct IP

Send the TCP and UDP packets:

bash

    sudo python3 packet_sender.py

Logging

Packet details are saved in packet_log.txt in the following format:

ruby

YYYY-MM-DD HH:MM:SS - Action packet: source_ip:source_port -> dest_ip:dest_port, Protocol: protocol_name

Example Output

plaintext

2024-08-08 10:00:00 - Blocked packet: 192.168.1.10:8080 -> 192.168.1.11:80, Protocol: TCP
2024-08-08 10:00:01 - Allowed packet: 192.168.1.12:53 -> 192.168.1.13:53, Protocol
