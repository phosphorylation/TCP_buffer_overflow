import socket
from struct import *
from threading import Thread
import sys

def prep_IP(data,frag_offset,more,no_frag):
    total = b''  #total header
    version = '4'  #4

    IHL = '5'
    DSCP = '00' #none
    total_length= int(20+data.__len__()/2)
    total_length=hex(total_length)[2:]
    while total_length.__len__()<4:
        total_length = '0'+total_length
    identification='04d2' #45674
    if no_frag==1:
        flags ='010' #don't frag
    if more ==1:
        if no_frag==0:
            flags ='001' #more frag
    if more ==0:
        if no_frag==0:
            flags ='000' #last frag
    fragment_Offset =frag_offset #in binary, 13digits
    flagAfrag = hex(int(flags+fragment_Offset,2))[2:]
    while flagAfrag.__len__()<4:
        flagAfrag = '0'+flagAfrag
    TTL ='7F' #127
    protocol ='01' #ICMP
    header_checksum = '0000'
    source = 'C0A8DE01'
    dest = 'C0A8DE02'


    total = version+IHL+DSCP+total_length+identification+flagAfrag+TTL+protocol+source+dest
    header_checksum =checksum(total)
    total= total[0:20]+header_checksum+total[20:]
    print(checksum(total))
    total +=data
    #packet=bytearray.fromhex('4500001C04D240007F01B9B9C0A8DE01C0A8DE020800F32D04D20000')
    total =bytearray.fromhex(total)
    print(total)
    #print(packet)
    return total


def checksum(header):
    i=0
    total =0
    while i<header.__len__():  ##going through the bytes in 4, adding them together
        seg=header[i:i+4]
        seg_dec=int(seg,16)
        total+=seg_dec
        i=i+4
    total =hex(total)[2:]
    while total.__len__()<4:   ##padding to 4bytes
        total = str(0)+total
    total1=total[0:1]
    total2=total[1:]
    total =int(total2,16)+int(total1,16)  ##adding carry
    # total = hex(total)[2:]
    # while total.__len__()<4:
    #     total = str(0)+total
    value =hex(total ^0xFFFF)  ##getting compliement
    return value[2:]

def prep_ICMP(data):
    type ='08'
    code ='00'
    check_sum=''
    identifier = '04D2'
    sequence ='0000'
    ICMP_no_check=type+code+identifier+sequence+data
    check_sum = '0000'
    ICMP_no_check=ICMP_no_check[0:4]+check_sum+ICMP_no_check[4:]
    return ICMP_no_check
        #'0800F32D04D20000'

def receive_message():
    all_bytes = b''
    while True:
        try:
            m_len = se_socket.recv(10)
            all_bytes+=m_len
        except:
            None
        if all_bytes.__len__() >=2:
            break
    m_len = all_bytes[0:2]
    all_bytes = all_bytes[2:]
    m_len_Unpacked = unpack('>H',m_len)
    print("receive_message length")
    print(m_len_Unpacked[0])
    while True:
        try:
            message = se_socket.recv(10)
            all_bytes+=message
        except:
            None
        if all_bytes.__len__() == m_len_Unpacked[0]:
            break
    return all_bytes


def print_message():
    message = receive_message()
    print("message::", message)
    ICMP_header = message[20:21]
    ICMP_code = message[21:22]
    ICMP_check_sum = message[22:24]
    ICMP_rest_of_header = message[24:28]
    ICMP_content = message[28:]
    print("type::", ICMP_header)
    print("code::", ICMP_code)
    try:
        print("possible content:", ICMP_content.decode())
    except:
        print("decode exception")

def oversized_packet_gen():
    message = '11'*1472
    return message

if __name__ == '__main__':
    PORT = 27076
    SERVER_IP = "cs177.seclab.cs.ucsb.edu"
    se_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    se_socket.connect((SERVER_IP, PORT))
    se_socket.settimeout(0.1)

    ICMP_packet = prep_ICMP(oversized_packet_gen())##random stuff in hex

    total_ICMP_len = len(ICMP_packet)
    last_frag = 0
    per_frag = 127 * 8 * 2
    while True:
        ICMP_packet1=ICMP_packet[last_frag:per_frag]  ##1024 bytes, 128 frag offset
        frag_offset = bin(int(last_frag/16))[2:]
        while len(frag_offset)<13:
            frag_offset='0'+frag_offset
        test_packet1 =prep_IP(ICMP_packet1,frag_offset,1,0)
        m_len = len(test_packet1)
        m_len_Ready = pack('>H', m_len)
        se_socket.sendall(m_len_Ready)
        se_socket.sendall(test_packet1)
        last_frag =per_frag
        per_frag=last_frag+128*8*2

        if per_frag>=total_ICMP_len:
            ICMP_packet1 = ICMP_packet[last_frag:]
            frag_offset = bin(int(last_frag/16))[2:]
            while len(frag_offset) < 13:
                frag_offset = '0' + frag_offset
            test_packet1 = prep_IP(ICMP_packet1,frag_offset, 0, 0)
            m_len = len(test_packet1)
            m_len_Ready = pack('>H', m_len)
            se_socket.sendall(m_len_Ready)
            se_socket.sendall(test_packet1)
            break

    print_message()

    # test_packet2 = prep_IP(ICMP_packet2, '0000000000001', 0, 0)
    # m_len = len(test_packet2)
    # m_len_Ready = pack('>H', m_len)
    # se_socket.send(m_len_Ready)
    # se_socket.send(test_packet2)
    # print_message()
