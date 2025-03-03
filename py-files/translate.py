import dpkt
import sys
import socket

def mac_addr(address):
    """Convert a MAC address to a readable format (AA:BB:CC:DD:EE:FF)"""
    return ':'.join(f'{b:02x}' for b in address)

def inet_to_str(inet):
    """Convert an IP address from binary to a readable string"""
    try:
        return socket.inet_ntoa(inet)  # For IPv4
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)  # For IPv6

def parse_pcap(filename):
    """Parse and display readable network flows from a PCAP file"""
    try:
        with open(filename, 'rb') as f:
            pcap = dpkt.pcap.Reader(f)

            print("\n📡 Network Flows in PCAP File:")
            print("-" * 70)

            for timestamp, buf in pcap:
                eth = dpkt.ethernet.Ethernet(buf)  # Parse Ethernet frame

                # Extract Ethernet Layer
                src_mac = mac_addr(eth.src)
                dst_mac = mac_addr(eth.dst)
                eth_type = eth.type

                if isinstance(eth.data, dpkt.ip.IP):
                    ip = eth.data
                    src_ip = inet_to_str(ip.src)
                    dst_ip = inet_to_str(ip.dst)
                    protocol = ip.p

                    # TCP or UDP?
                    transport_layer = "UNKNOWN"
                    src_port = dst_port = None
                    if isinstance(ip.data, dpkt.tcp.TCP):
                        transport_layer = "TCP"
                        src_port = ip.data.sport
                        dst_port = ip.data.dport
                    elif isinstance(ip.data, dpkt.udp.UDP):
                        transport_layer = "UDP"
                        src_port = ip.data.sport
                        dst_port = ip.data.dport

                    # Print the extracted information
                    print(f"[{timestamp:.6f}] {src_mac} → {dst_mac} | {src_ip}:{src_port} → {dst_ip}:{dst_port} ({transport_layer})")

            print("-" * 70)

    except FileNotFoundError:
        print(f"❌ Error: File '{filename}' not found.")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python parse_pcap.py <filename>")
        sys.exit(1)

    parse_pcap(sys.argv[1])
