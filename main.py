import ipaddress
import socket
import struct
import sys
import argparse
from typing import Dict, Optional
from datetime import datetime

class Packet:
    PROTOCOL_MAP: Dict[int, str] = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }

    def __init__(self, data: bytes):
        self.packet = data
        self._parse_ip_header()

    def _parse_ip_header(self) -> None:
        try:
            header = struct.unpack('<BBHHHBBH4s4s', self.packet[0:20])
            
            self.ver = header[0] >> 4
            self.ihl = header[0] & 0xF
            self.tos = header[1]
            self.len = header[2]
            self.frag_id = header[3]
            self.frag_offset = header[4]
            self.ttl = header[5]
            self.prot = header[6]
            self.checksum = header[7]
            self.src = header[8]
            self.dst = header[9]

            self.src_addr = ipaddress.ip_address(self.src)
            self.dst_addr = ipaddress.ip_address(self.dst)
            
            self.protocol = self.PROTOCOL_MAP.get(self.prot, str(self.prot))
            
        except struct.error as e:
            raise ValueError(f"Failed to unpack packet header: {e}")
        except ValueError as e:
            raise ValueError(f"Invalid IP address in packet: {e}")

    def print_header_short(self) -> None:
        """Print a short summary of the packet header."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        print(f'[{timestamp}] {self.protocol}: {self.src_addr} -> {self.dst_addr} (TTL: {self.ttl})')

class PacketSniffer:
    """
    Network packet sniffer that can capture TCP or ICMP packets.
    """
    def __init__(self, host: str, protocol: str):
        """
        Initialize the packet sniffer.
        
        Args:
            host (str): IP address to sniff on
            protocol (str): Protocol to sniff ('tcp' or 'icmp')
        """
        self.host = host
        self.protocol = protocol.lower()
        self._setup_socket()

    def _setup_socket(self) -> None:
        """Set up the raw socket for packet sniffing."""
        if self.protocol == "tcp":
            socket_protocol = socket.IPPROTO_TCP
        elif self.protocol == "icmp":
            socket_protocol = socket.IPPROTO_ICMP
        else:
            raise ValueError(f"Unsupported protocol: {self.protocol}")

        try:
            self.sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
            self.sniffer.bind((self.host, 0))
            self.sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        except PermissionError:
            sys.exit("Error: This script requires root/administrator privileges")
        except socket.error as e:
            sys.exit(f"Socket creation error: {e}")

    def start_sniffing(self) -> None:
        print(f"\nStarting packet capture on {self.host} for {self.protocol.upper()} packets...")
        print("Press Ctrl+C to stop capturing.\n")

        try:
            while True:
                raw_data = self.sniffer.recv(65535)
                try:
                    packet = Packet(raw_data)
                    packet.print_header_short()
                except ValueError as e:
                    print(f"Error parsing packet: {e}")
                    continue
        except KeyboardInterrupt:
            print("\nPacket capture stopped by user")
        finally:
            self.sniffer.close()

def main():
    parser = argparse.ArgumentParser(
        description='Network Packet Sniffer',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "--ip",
        help="IP address to sniff on",
        type=str,
        required=True
    )
    parser.add_argument(
        "--proto",
        help="protocol to sniff",
        type=str,
        choices=['tcp', 'icmp'],
        required=True
    )

    try:
        opts = parser.parse_args()
        sniffer = PacketSniffer(opts.ip, opts.proto)
        sniffer.start_sniffing()
    except Exception as e:
        sys.exit(f"Error: {e}")

if __name__ == "__main__":
    main()
