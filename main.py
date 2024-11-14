import ipaddress
import socket
import struct
import sys
import argparse #take args from command line

parser= argparse.ArgumentParser(description='Sniffing packets')
parser.add_argument('--i', help='IP address to sniff on', required=True)
opts= parser.parse_args()

class Packet:
    def __init__(self):
        pass

def sniff():
    pass

if __name__ == '__main__':
    sniff()

