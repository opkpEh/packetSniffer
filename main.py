import ipaddress
import socket
import struct
import sys
import argparse  # to take args from the command line
from logging import exception

parser = argparse.ArgumentParser(description='Sniffing packets')
parser.add_argument('--i', help='IP address to sniff on', required=True)
opts = parser.parse_args()

class Packet:
    def __init__(self, data):
        self.packet = data
        header = struct.unpack('<BBHHHBBH4s4s', self.packet[:20])
        self.ver = header[0] >> 4
        self.ihl = header[0] & 0xF
        self.tos = header[1]
        self.len = header[2]
        self.id = header[3]
        self.offset = header[4]
        self.ttl = header[5]
        self.protocol = header[6]
        self.num = header[7]
        self.src = header[8]
        self.dst = header[9]

        self.src_addr = ipaddress.ip_address(self.src)
        self.dst_addr = ipaddress.ip_address(self.dst)

        self.protocol_map = {1: "ICMP"}

        try:
            self.protocol = self.protocol_map[self.protocol]
        except KeyError as e:
            print(f"Unknown protocol {self.protocol}: {e}")

    def print_header_short(self):
        print(f'Protocol: {self.protocol} {self.src_addr} to {self.dst_addr}')

def sniff(host):
    socket_protocol = socket.IPPROTO_ICMP
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        while True:
            try:
                raw_data, addr = sniffer.recvfrom(65565)
                packet = Packet(raw_data)
                packet.print_header_short()
            except KeyboardInterrupt:
                print("\nExiting due to keyboard interrupt.")
                sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == '__main__':
    sniff(opts.i)
