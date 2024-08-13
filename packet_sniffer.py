import socket
import struct
import binascii

def packet_sniffer():
    # Create a raw socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    # Set up the socket to capture packets
    sock.bind(("0.0.0.0", 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print("Packet sniffer started. Press 'Ctrl+C' to stop.")

    try:
        while True:
            # Capture a packet
            packet = sock.recvfrom(65565)[0]

            # Parse the packet
            ip_header = packet[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

            # Extract relevant information
            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            # Extract protocol information
            if protocol == 1:
                protocol_name = "ICMP"
            elif protocol == 6:
                protocol_name = "TCP"
            elif protocol == 17:
                protocol_name = "UDP"
            else:
                protocol_name = "Unknown"

            # Extract payload data
            payload = packet[iph_length:]
            payload_hex = binascii.hexlify(payload)

            # Print the packet information
            print("Source IP: " + s_addr)
            print("Destination IP: " + d_addr)
            print("Protocol: " + protocol_name)
            print("TTL: " + str(ttl))
            print("Payload: " + str(payload_hex))
            print("")

    except KeyboardInterrupt:
        print("Packet sniffer stopped.")

if __name__ == "__main__":
    packet_sniffer()
