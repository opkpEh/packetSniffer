import ipaddress
import socket
import struct
import sys
import argparse #helps create a command line interface to pass in the arguments

#creates a new parser object, the description will be shown when --help is done
parser= argparse.ArgumentParser(description='Network Packet Sniffer')

#adds a new command line argument --ip for this file
parser.add_argument("--ip", help="IP address to sniff on",type=str, required=True)
parser.add_argument("--proto", help="protocol to sniff (TCP/ICMP)", required=True, type=str, choices=['tcp','icmp'])

#stores the passed arguments in opts when the script is run
opts=  parser.parse_args()

class Packet:
    def __init__(self,data):
        self.packet= data
        header= struct.unpack('<BBHHHBBH4s4s',self.packet[0:20])
        # to make sure that out of the 8 bits we only get the 4 bits of start we need
        self.ver= header[0] >> 4
        # we apply boolean and operator, this converts the higher end to 0s and keeps lower end intact
        self.ihl= header[0] & 0xF
        self.tos= header[1]
        self.len= header[2]
        self.frag_id= header[3]
        self.frag_offset= header[4]
        self.ttl= header[5]
        self.prot= header[6]# identifies the protocol type
        self.checksum= header[7]
        self.src= header[8]
        self.dst= header[9]

        # converts source ip address into doted ip address
        self.src_addr= ipaddress.ip_address(self.src)

        self.dst_addr= ipaddress.ip_address(self.dst)

        self.protocol_map= {1: "ICMP", 6: "TCP"}

        try:
            self.protocol= self.protocol_map[self.prot]
        except Exception as e:
            print(f'{e} No protocol found for {self.prot}')
            self.protocol= str(self.prot)

    def print_header_short(self):
        print(f'Protocol: {self.protocol} {self.src_addr} -> {self.dst_addr}')

def sniff(host):
    if opts.proto=="tcp":
        socket_protocol = socket.IPPROTO_TCP
    else:
        socket_protocol = socket.IPPROTO_ICMP
    sniffer= socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
    sniffer.bind((host,0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        while True:
            raw_data= sniffer.recv(65535)
            packet= Packet(raw_data)
            packet.print_header_short()

            if KeyboardInterrupt:
                sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)



if __name__=="__main__":
    sniff(opts.ip)