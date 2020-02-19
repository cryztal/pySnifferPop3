import socket
import base64
from struct import *


class SessionElem:

    def __init__(self, sip, spo, dip, dpo, seq, ack, data):
        self.sip = sip
        self.spo = spo
        self.dip = dip
        self.dpo = dpo
        self.seq = seq
        self.ack = ack
        self.data = data

    def __str__(self):
        return 'Source Ip = {self.sip}, Source Port = {self.sop} Destination Ip = {self.dip} Destination Port = {self.dop}, Acknowlendgement = {self.ack} \rDATA = {self.data}'.format(
            self=self)


def sortbyseq(sessionelem):
    if sessionelem.seq < sessionelem.ack:
        return sessionelem.seq
    else:
        return sessionelem.ack


try:
    s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    sessionAll = []
    while True:
        packet = s.recvfrom(65565)

        packet = packet[0]

        eth_length = 14

        eth_header = packet[:eth_length]

        eth = unpack('!6s6sH', eth_header)

        eth_protocol = socket.ntohs(eth[2])

        if eth_protocol == 8:

            ip_header = packet[eth_length:20 + eth_length]

            iph = unpack('!BBHHHBBH4s4s', ip_header)

            version_ihl = iph[0]

            iph_length = version_ihl & 0xF
            iph_length = iph_length * 4

            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8]);
            d_addr = socket.inet_ntoa(iph[9]);

            if protocol == 6:

                tcp_header = packet[34:54]

                tcph = unpack('!HHLLBBHHH', tcp_header)

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4
                tcph_length = tcph_length * 4

                h_size = eth_length + iph_length + tcph_length
                data = packet[h_size:]

                if dest_port == 110 or source_port == 110:
                    elem = SessionElem(str(s_addr), str(source_port), str(d_addr), str(dest_port), str(sequence),
                                       str(acknowledgement), str(data))
                    if (data != ("").encode('utf-8')) and (data.find(("\x00").encode('utf-8'))) == -1:
                        sessionAll.append(elem)
                        # print(
                        # 'Source IP   : ' + str(s_addr))
                        # print(
                        # 'Source Port : ' + str(source_port))
                        # print(
                        # 'Dest IP     : ' + str(d_addr))
                        # print(
                        # 'Dest Port   : ' + str(dest_port))
                        # print(
                        # 'Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement))
                        # print(
                        # 'Data : ', str(data))
                        if data == ('+OK CommuniGate Pro POP3 Server connection closed\r\n').encode('utf-8'):
                            break;
    sessionAll.sort(key=sortbyseq)

    print('\n\tFull session')
    for item in sessionAll:
        print(item.data)
    print('\n\tPlain data:')
    serv = False
    mail = False
    for item in sessionAll:

        if serv:
            print('encoded: ' + item.data[4:-5])
            print('decoded: ' + base64.b64decode(item.data[4:-5]).decode())
            serv = False
            mail = True
        else:
            if mail:
                print('encoded: ' + item.data[2:-5])
                print('decoded: ' + base64.b64decode(item.data[2:-5]).decode())
                mail = False
            else:
                if (item.data.find('AUTH CRAM-MD5') != -1):
                    serv = True
                if (item.data.find('X-Real-To') != -1):
                    lst = item.data.split('\\r\\n')
                    print("\r\nYou have a new message")
                    # print(lst)
                    print(lst[5])
                    print(lst[6])
                    print(lst[9])
                    print("message : ")
                    print(lst[16:-2])

except:
    print('Error')
