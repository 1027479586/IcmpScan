import socket
from random import randint
from scapy.all import *
from whois import whois


def main():
    '''
    data = whois('www.baidu.com')   #whois信息
    ip = socket.gethostbyname('www.baidu.com')  #ip地址
    '''

    ip_id = randint(1,65535)
    icmp_id = randint(1,65535)
    icmp_seq = randint(1,65535)
    packet = IP(dst="192.168.1.100",ttl=64,id=ip_id)/ICMP(id=icmp_id,seq=icmp_seq)/b'kill'
    result = sr1(packet,timeout=1,verbose=False)
    if result:
        for rc in result:
            scan_ip = rc[IP].src
            print(scan_ip+' is alive')
    else:
        print('is down')

    pass



    # req,res = sr(IP(dst="192.168.1.100")/ICMP())
    # for req1,res1 in req:
    #     print(res1.sprintf("%IP.src% is alive"))
    #
    # pass

if __name__ == '__main__':
    main()