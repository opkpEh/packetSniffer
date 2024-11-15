import ipaddress
import socket
import struct
import sys
import argparse #take args from command line
from logging import exception

parser= argparse.ArgumentParser(description='Sniffing packets')
parser.add_argument('--i', help='IP address to sniff on', required=True)
opts= parser.parse_args()

class Packet:
    def __init__(self, data):
        self.packet= data
        header= struct.unpack('<BBHHHBBH4s4s', self.packet[:20])
        self.ver= header[0]>>4
        self.ihl= header[0]&0xF
        self.tos= header[1]
        self.len= header[2]
        self.id= header[3]
        self.offset= header[4]
        self.ttl= header[5]
        self.protocol= header[6]
        self.num= header[7]
        self.src= header[8]
        self.dst= header[9]

        self.src_addr= ipaddress.ip_address(self.src)
        self.dst_addr= ipaddress.ip_address(self.dst)

        self.protocol_map={1: "ICMP"}

        try:
            self.protocol= self.protocol_map[self.protocol]
        except exception as e:
            print(f"{e}")

def sniff():


if __name__ == '__main__':
    sniff()