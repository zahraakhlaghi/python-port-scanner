import socket
from struct import *
import time
from  services import  services


class Packet:
    def __init__(self,method, src_ip, dest_ip, dest_port):
        ############
        # IP segment
        self.version = 0x4
        self.ihl = 0x5
        self.type_of_service = 0x0
        self.total_length = 0x28
        self.identification = 0xabcd
        self.flags = 0x0
        self.fragment_offset = 0x0
        self.ttl = 0x40
        self.protocol = 0x6
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(src_ip)
        self.dest_addr = socket.inet_aton(dest_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.f_fo = (self.flags << 13) + self.fragment_offset

        #############
        # TCP segment
        self.src_port = 0x3039
        self.dest_port = dest_port
        self.seq_no = 0x0
        self.ack_no = 0x0
        self.data_offset = 0x5
        self.reserved = 0x0
        if method==1:#syn packet
           self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0
        elif method==2:#ack packet
            self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0
        elif method==3:#fin packet
            self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1
        self.window_size = 0x7110
        self.checksum = 0x0
        self.urg_pointer = 0x0
        self.data_offset_res_flags = (self.data_offset << 12) + (self.reserved << 9) + (self.ns << 8) + (
                    self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (
                                                 self.rst << 2) + (self.syn << 1) + self.fin

        ########
        # packet
        self.tcp_header = b""
        self.ip_header = b""
        self.packet = b""

    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w
        # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s

    def generate_tmp_ip_header(self):
        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                             self.identification, self.f_fo,
                             self.ttl, self.protocol, self.header_checksum,
                             self.src_addr,
                             self.dest_addr)
        return tmp_ip_header

    def generate_tmp_tcp_header(self):
        tmp_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                              self.seq_no,
                              self.ack_no,
                              self.data_offset_res_flags, self.window_size,
                              self.checksum, self.urg_pointer)
        return tmp_tcp_header

    def generate_packet(self):
        # IP header + checksum
        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                               self.identification, self.f_fo,
                               self.ttl, self.protocol, self.calc_checksum(self.generate_tmp_ip_header()),
                               self.src_addr,
                               self.dest_addr)
        # TCP header + checksum
        tmp_tcp_header = self.generate_tmp_tcp_header()
        pseudo_header = pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol,
                             len(tmp_tcp_header))
        psh = pseudo_header + tmp_tcp_header
        final_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                self.seq_no,
                                self.ack_no,
                                self.data_offset_res_flags, self.window_size,
                                self.calc_checksum(psh), self.urg_pointer)

        self.ip_header = final_ip_header
        self.tcp_header = final_tcp_header
        self.packet = final_ip_header + final_tcp_header

    def send_packet(self,delay):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(self.packet, (self.dest_ip, 0))
        return recv_packet(delay)

def recv_packet(delay):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    start_time=time.time()
    try:
        while time.time() - start_time <= delay:
            data, addr = s.recvfrom(65535)
            s.close()
            return data

    except:
        return False

def syn_scann(port,host,delay):
    p = Packet(1,str(local_ip()),host, port)
    p.generate_packet()
    result = p.send_packet(delay)
    if result:
      data=result[14:]
      version_header_length = data[0]
      header_length = (version_header_length & 15) * 4
      ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', data[:20])
      src = get_ip(src)
      target = get_ip(target)
      data = data[header_length:]
      if str(target)==str(local_ip()) and str(src)==str(host) and int(proto)==6:
          src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = unpack('! H H L L H', data[:14])
          ack = (offset_reserved_flags & 16) >> 4
          rst = (offset_reserved_flags & 4) >> 2
          syn = (offset_reserved_flags & 2) >> 1

          if ack and syn:
            try :
                print('{}/tcp \t     open \t {} '.format(port,services[str(port)]))
            except:
                print('{}/tcp \t     open \t '.format(port))

          elif rst:
              try:
                  print('{}/tcp \t closed \t {} '.format(port, services[str(port)]))
              except:
                  print('{}/tcp \t closed \t '.format(port))

    time.sleep(delay)

def ack_scann(port,host,delay):
    p = Packet(2,str(local_ip()),host, port)
    p.generate_packet()
    result = p.send_packet(delay)
    if result:
      data=result[14:]
      version_header_length = data[0]
      header_length = (version_header_length & 15) * 4
      ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', data[:20])
      src = get_ip(src)
      target = get_ip(target)
      data = data[header_length:]
      if str(target)==str(local_ip()) and str(src)==str(host) and int(proto)==6:
          src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = unpack('! H H L L H', data[:14])
          rst = (offset_reserved_flags & 4) >> 2
          if rst :
              try:
                  print('{}/tcp \t unfiltered \t {} '.format(port, services[str(port)]))
              except:
                  print('{}/tcp \t unfiltered \t '.format(port))

    time.sleep(delay)

def fin_scann(port,host,delay):
    p = Packet(3,str(local_ip()),host, port)
    p.generate_packet()
    result = p.send_packet(delay)
    if result:
      data=result[14:]
      version_header_length = data[0]
      header_length = (version_header_length & 15) * 4
      ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', data[:20])
      src = get_ip(src)
      target = get_ip(target)
      data = data[header_length:]
      if str(target)==str(local_ip()) and str(src)==str(host) and int(proto)==6:
          src_port, dest_port, sequence, acknowledgment, offset_reserved_flags = unpack('! H H L L H', data[:14])
          rst = (offset_reserved_flags & 4) >> 2
          if rst :
            try:
               print('{}/tcp \t closed \t {}'.format(port, services[str(port)]))
            except:
                print('{}/tcp \t closed \t '.format(port))

    else:
        try:
          print('{}/tcp \t open|filtered \t {}'.format(port, services[str(port)]))
        except:
            print('{}/tcp \t open|filtered \t'.format(port))

    time.sleep(delay)

def window_scann(port,host,delay):
    p = Packet(2,str(local_ip()),host, port)
    p.generate_packet()
    result = p.send_packet(delay)
    if result:
      data=result[14:]
      version_header_length = data[0]
      header_length = (version_header_length & 15) * 4
      ttl, proto, src, target = unpack('! 8x B B 2x 4s 4s', data[:20])
      src = get_ip(src)
      target = get_ip(target)
      data = data[header_length:]
      if str(target)==str(local_ip()) and str(src)==str(host) and int(proto)==6:
          src_port, dest_port, sequence, acknowledgment, offset_reserved_flags,window_size = unpack('! H H L L H H', data[:16])
          rst = (offset_reserved_flags & 4) >> 2
          if rst and window_size:
            try:
               print('{}/tcp \t open \t {}'.format(port, services[str(port)]))
            except:
                print('{}/tcp \t open \t '.format(port))
          elif rst:
              try:
                 print('{}/tcp \t closed \t {}'.format(port, services[str(port)]))
              except:
                  print('{}/tcp \t closed \t '.format(port))

    time.sleep(delay)


def local_ip():
   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   try:
     s.connect(('10.255.255.255', 1))
     IP = s.getsockname()[0]
   except Exception:
     IP = '127.0.0.1'
   finally:
     s.close()
   return IP

def get_ip(addr):
         return '.'.join(map(str, addr))
