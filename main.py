import ipaddress
import socket
import struct
import sys
import argparse #helps create a command line interface to pass in the arguments

#creates a new parser object, the description will be shown when --help is done
parser= argparse.ArgumentParser(description='Network Packet Sniffer')

#adds a new command line argument --ip for this file
parser.add_argument("--ip", help="IP address to sniff on",type=str, required=True)

#stores the passed arguments in opts when the script is run
opts=  parser.parse_args()

class Packet:
    pass

def sniff():
    pass

if __name__=="__main__":
    sniff()