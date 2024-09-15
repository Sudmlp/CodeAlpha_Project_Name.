import socket
import struct
import binascii

# Create a raw socket
def create_socket():
    try:
        sniffer_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        return sniffer_socket
    except socket.error as e:
        print(f"Socket creation error: {e}")
        return None

# Function to parse Ethernet header
def parse_ethernet_header(packet):
    eth_header = packet[0:14]
    eth_unpacked = struct.unpack("!6s6sH", eth_header)
    dest_mac = binascii.hexlify(eth_unpacked[0]).decode('utf-8')
    src_mac = binascii.hexlify(eth_unpacked[1]).decode('utf-8')
    eth_protocol = socket.htons(eth_unpacked[2])
    return dest_mac, src_mac, eth_protocol

# Function to parse IP header
def parse_ip_header(packet):
    ip_header = packet[14:34]
    ip_unpacked = struct.unpack("!BBHHHBBH4s4s", ip_header)
    version_ihl = ip_unpacked[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    ttl = ip_unpacked[5]
    protocol = ip_unpacked[6]
    src_ip = socket.inet_ntoa(ip_unpacked[8])
    dest_ip = socket.inet_ntoa(ip_unpacked[9])
    return version, ihl, ttl, protocol, src_ip, dest_ip

# Function to parse TCP/UDP header (Example: TCP)
def parse_tcp_header(packet, ihl):
    tcp_header_start = 14 + ihl * 4
    tcp_header = packet[tcp_header_start:tcp_header_start + 20]
    tcp_unpacked = struct.unpack("!HHLLBBHHH", tcp_header)
    src_port = tcp_unpacked[0]
    dest_port = tcp_unpacked[1]
    return src_port, dest_port

# Main sniffer function
def sniff_packets():
    sniffer_socket = create_socket()
    if sniffer_socket is None:
        return

    while True:
        packet, addr = sniffer_socket.recvfrom(65565)
        
        # Parse Ethernet Header
        dest_mac, src_mac, eth_protocol = parse_ethernet_header(packet)
        print(f"Ethernet -> Dest MAC: {dest_mac}, Src MAC: {src_mac}, Protocol: {eth_protocol}")
        
        if eth_protocol == 8:  # IP Protocol
            # Parse IP Header
            version, ihl, ttl, protocol, src_ip, dest_ip = parse_ip_header(packet)
            print(f"IP -> Version: {version}, IHL: {ihl}, TTL: {ttl}, Protocol: {protocol}, Src IP: {src_ip}, Dest IP: {dest_ip}")
            
            if protocol == 6:  # TCP Protocol
                # Parse TCP Header
                src_port, dest_port = parse_tcp_header(packet, ihl)
                print(f"TCP -> Src Port: {src_port}, Dest Port: {dest_port}")
            elif protocol == 17:  # UDP Protocol (you can add a similar function for UDP)
                print("UDP Packet Detected")
        print("="*40)

if __name__ == "__main__":
    sniff_packets()
