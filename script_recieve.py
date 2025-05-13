import socket
import struct
import time
import ipaddress

# User-configurable settings: Add IPs, subnets, and ports to block here.
BLOCKED_IPS = ["172.16.27.105"]  # Add IP addresses here to block them.
BLOCKED_SUBNETS = ["192.168.1.0/24"]  # Add subnets here to block entire networks.
BLOCKED_PORTS = [80]  # Add port numbers here to block traffic on specific ports.
SUPPORTED_PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}  # Supported protocols with their numbers.

packet_count = 0  # Track the total number of packets processed (no need to modify this).

def create_socket():
    try:
        # Create a raw socket to capture all IP packets
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        return sock
    except socket.error as e:
        print(f"Socket could not be created. Error: {e}")
        return None

def parse_ip_packet(packet):
    try:
        # Parse the IP header to extract source IP, destination IP, protocol, and TTL.
        ip_header = packet[14:34]
        ip_header = struct.unpack('!BBHHHBBH4s4s', ip_header)
        source_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        protocol = ip_header[6]
        ttl = ip_header[5]
        return source_ip, dest_ip, protocol, ttl
    except struct.error as e:
        print(f"Failed to parse IP packet: {e}")
        return None, None, None, None

def is_ip_blocked(ip):
    # Check if the IP is in the list of blocked IPs or within a blocked subnet.
    if ip in BLOCKED_IPS:
        return True
    
    ip_obj = ipaddress.IPv4Address(ip)
    for subnet in BLOCKED_SUBNETS:
        if ip_obj in ipaddress.IPv4Network(subnet):
            return True
    
    return False

def filter_packet(packet, source_ip, dest_ip, protocol):
    global packet_count
    packet_count += 1
    
    if not source_ip or not dest_ip:
        return False

    # Block the packet if the source or destination IP is in the blocked list or subnet.
    if is_ip_blocked(source_ip) or is_ip_blocked(dest_ip):
        log_packet("Blocked", source_ip, dest_ip, protocol)
        return False
    
    # Check for TCP packets and block if the source or destination port is blocked.
    if protocol == 6:  # TCP
        try:
            tcp_header = packet[34:54]
            tcp_header = struct.unpack('!HHLLBBHHH', tcp_header)
            source_port = tcp_header[0]
            dest_port = tcp_header[1]
            if source_port in BLOCKED_PORTS or dest_port in BLOCKED_PORTS:
                log_packet("Blocked", source_ip, dest_ip, protocol, source_port, dest_port)
                return False
        except struct.error as e:
            print(f"Failed to parse TCP header: {e}")
            return False

    # Check for UDP packets and block if the source or destination port is blocked.
    elif protocol == 17:  # UDP
        try:
            udp_header = packet[34:42]
            udp_header = struct.unpack('!HHHH', udp_header)
            source_port = udp_header[0]
            dest_port = udp_header[1]
            if source_port in BLOCKED_PORTS or dest_port in BLOCKED_PORTS:
                log_packet("Blocked", source_ip, dest_ip, protocol, source_port, dest_port)
                return False
        except struct.error as e:
            print(f"Failed to parse UDP header: {e}")
            return False

    # Allow the packet if it does not match any blocked criteria.
    log_packet("Allowed", source_ip, dest_ip, protocol)
    return True

def log_packet(action, source_ip, dest_ip, protocol, source_port=None, dest_port=None):
    # Log the packet's details including action (Blocked/Allowed), IPs, ports, protocol, and other details.
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    protocol_name = SUPPORTED_PROTOCOLS.get(protocol, str(protocol))
    log_entry = f"{timestamp} - {action} packet: {source_ip}:{source_port} -> {dest_ip}:{dest_port}, Protocol: {protocol_name}"
    
    print(log_entry)
    
    with open("packet_log.txt", "a") as log_file:
        log_file.write(log_entry + "\n")

# Functions for dynamically blocking or unblocking IPs and ports.
def block_ip(ip):
    if ip not in BLOCKED_IPS:
        BLOCKED_IPS.append(ip)
        print(f"IP {ip} blocked.")

def unblock_ip(ip):
    if ip in BLOCKED_IPS:
        BLOCKED_IPS.remove(ip)
        print(f"IP {ip} unblocked.")

def block_port(port):
    if port not in BLOCKED_PORTS:
        BLOCKED_PORTS.append(port)
        print(f"Port {port} blocked.")

def unblock_port(port):
    if port in BLOCKED_PORTS:
        BLOCKED_PORTS.remove(port)
        print(f"Port {port} unblocked.")

def main():
    sock = create_socket()
    if not sock:
        return

    print("Firewall running... Press Ctrl+C to stop.")

    try:
        while True:
            # Receive incoming packets and process them.
            packet, _ = sock.recvfrom(65565)
            source_ip, dest_ip, protocol, ttl = parse_ip_packet(packet)

            if not filter_packet(packet, source_ip, dest_ip, protocol):
                continue

            # Log the TTL for demonstration purposes.
            print(f"Packet TTL: {ttl}")

            # Periodically print packet statistics.
            if packet_count % 100 == 0:
                print(f"Total packets processed: {packet_count}")

    except KeyboardInterrupt:
        print("Firewall stopped.")
        print(f"Total packets processed: {packet_count}")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
