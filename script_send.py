import socket

def send_raw_packet(raw_data, dest_ip):
    try:
        # Create a raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        # Define the destination address
        dest_addr = (dest_ip, 0)  # Port is not used for raw packets

        # Send the raw packet data
        sock.sendto(raw_data, dest_addr)
        print(f"Packet sent successfully to {dest_ip}.")
    except socket.error as e:
        print(f"Socket error: {e}")

# Example raw packet data (in bytes)
tcp_packets = [
    bytes.fromhex("45000034 1c46 4000 4006 b1e6 c0a80001 c0a800c8 0050 0045 0000 0000 0000 0000 5002 20ff 52f0 0000 0204 05b4 0402 080a 5c5d d0ff 0000 0000 0103 0300"),
    bytes.fromhex("4500003c 1c47 4000 4006 b1e6 c0a80002 c0a800c9 0050 00c8 0000 0000 0000 0000 5002 20ff 8a00 0000 0204 05b4 0402 080a 5c5d d1ff 0000 0000 0103 0300"),
    bytes.fromhex("45000034 1c48 4000 4006 b1e6 c0a80003 c0a800ca 0050 0046 0000 0000 0000 0000 5002 20ff 53f0 0000 0204 05b4 0402 080a 5c5d d2ff 0000 0000 0103 0300"),
    bytes.fromhex("45000034 1c49 4000 4006 b1e6 c0a80004 c0a800cb 0050 0047 0000 0000 0000 0000 5002 20ff 54f0 0000 0204 05b4 0402 080a 5c5d d3ff 0000 0000 0103 0300"),
    bytes.fromhex("45000034 1c4a 4000 4006 b1e6 c0a80005 c0a800cc 0050 0048 0000 0000 0000 0000 5002 20ff 55f0 0000 0204 05b4 0402 080a 5c5d d4ff 0000 0000 0103 0300"),
    bytes.fromhex("45000034 1c4b 4000 4006 b1e6 c0a80006 c0a800cd 0050 0049 0000 0000 0000 0000 5002 20ff 56f0 0000 0204 05b4 0402 080a 5c5d d5ff 0000 0000 0103 0300"),
    bytes.fromhex("45000034 1c4c 4000 4006 b1e6 c0a80007 c0a800ce 0050 004a 0000 0000 0000 0000 5002 20ff 57f0 0000 0204 05b4 0402 080a 5c5d d6ff 0000 0000 0103 0300"),
    bytes.fromhex("45000034 1c4d 4000 4006 b1e6 c0a80008 c0a800cf 0050 004b 0000 0000 0000 0000 5002 20ff 58f0 0000 0204 05b4 0402 080a 5c5d d7ff 0000 0000 0103 0300"),
    bytes.fromhex("45000034 1c4e 4000 4006 b1e6 c0a80009 c0a800d0 0050 004c 0000 0000 0000 0000 5002 20ff 59f0 0000 0204 05b4 0402 080a 5c5d d8ff 0000 0000 0103 0300"),
    bytes.fromhex("45000034 1c4f 4000 4006 b1e6 c0a8000a c0a800d1 0050 004d 0000 0000 0000 0000 5002 20ff 5af0 0000 0204 05b4 0402 080a 5c5d d9ff 0000 0000 0103 0300")
]

udp_packets = [
    bytes.fromhex("4500003c 1c46 4000 4011 b1e6 c0a80001 c0a800c8 0050 00c8 003d 9a0f 0000 0000"),
    bytes.fromhex("4500003c 1c47 4000 4011 b1e6 c0a80002 c0a800c9 0050 00c8 003d 9a0f 0000 0000"),
    bytes.fromhex("4500003c 1c48 4000 4011 b1e6 c0a80003 c0a800ca 0050 00c8 003d 9a0f 0000 0000"),
    bytes.fromhex("4500003c 1c49 4000 4011 b1e6 c0a80004 c0a800cb 0050 00c8 003d 9a0f 0000 0000"),
    bytes.fromhex("4500003c 1c4a 4000 4011 b1e6 c0a80005 c0a800cc 0050 00c8 003d 9a0f 0000 0000"),
    bytes.fromhex("4500003c 1c4b 4000 4011 b1e6 c0a80006 c0a800cd 0050 00c8 003d 9a0f 0000 0000"),
    bytes.fromhex("4500003c 1c4c 4000 4011 b1e6 c0a80007 c0a800ce 0050 00c8 003d 9a0f 0000 0000"),
    bytes.fromhex("4500003c 1c4d 4000 4011 b1e6 c0a80008 c0a800cf 0050 00c8 003d 9a0f 0000 0000"),
    bytes.fromhex("4500003c 1c4e 4000 4011 b1e6 c0a80009 c0a800d0 0050 00c8 003d 9a0f 0000 0000"),
    bytes.fromhex("4500003c 1c4f 4000 4011 b1e6 c0a8000a c0a800d1 0050 00c8 003d 9a0f 0000 0000")
]

# Define the destination IP (must be reachable)
destination_ip = '172.16.27.105'  # Replace with an appropriate IP address

# Send the TCP packets
for packet in tcp_packets:
    send_raw_packet(packet, destination_ip)

# Send the UDP packets
for packet in udp_packets:
    send_raw_packet(packet, destination_ip)
