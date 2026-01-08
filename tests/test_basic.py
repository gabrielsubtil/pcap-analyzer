import unittest
import struct
import sys
import os

# Adiciona src ao path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from backend.parser import parse_pcap, parse_pcapng

class TestParser(unittest.TestCase):
    def test_pcap_parsing(self):
        # Cria um PCAP válido em memória (Little Endian)
        # Global Header (24 bytes): Magic(4) + Major(2) + Minor(2) + Zone(4) + SigFigs(4) + SnapLen(4) + Network(4)
        magic = 0xa1b2c3d4
        global_header = struct.pack('<IHHIIII', magic, 2, 4, 0, 0, 65535, 1)
        
        # Packet Header (16 bytes): TsSec(4) + TsUsec(4) + InclLen(4) + OrigLen(4)
        # IPv4 Packet Mínimo (20 bytes header + 0 payload)
        # Eth Layer (14) + IP (20) = 34 bytes
        # Dummy packet data: EthHeader(Dst,Src,Type=0800) + IPHeader(VerIhl=45, Len=20, Proto=1(ICMP), Src=1.2.3.4, Dst=5.6.7.8)
        
        eth_header = b'\x00'*6 + b'\x00'*6 + b'\x08\x00' # Type 0x0800 (IPv4)
        
        # IP Wrapper
        # Ver=4, IHL=5 -> 0x45
        # TotalLen=20 -> \x00\x14
        # TTL=64, Proto=1 (ICMP) -> \x40\x01
        # Src=1.2.3.4 -> \x01\x02\x03\x04
        # Dst=5.6.7.8 -> \x05\x06\x07\x08
        ip_header = b'\x45\x00\x00\x14' + b'\x00\x01\x00\x00' + b'\x40\x01\x00\x00' + b'\x01\x02\x03\x04' + b'\x05\x06\x07\x08'
        
        packet_data = eth_header + ip_header
        incl_len = len(packet_data)
        
        pkt_header = struct.pack('<IIII', 1700000000, 0, incl_len, incl_len)
        
        file_bytes = global_header + pkt_header + packet_data
        
        packets = parse_pcap(file_bytes)
        
        self.assertEqual(len(packets), 1)
        self.assertEqual(packets[0]['srcIp'], '1.2.3.4')
        self.assertEqual(packets[0]['dstIp'], '5.6.7.8')
        self.assertEqual(packets[0]['proto'], 'ICMP')

    def test_pcapng_parsing(self):
        # Cria um PCAPNG válido mínimo
        # SHB Block (Type=0x0A0D0D0A) -> Magic define endianness
        # BlockLen = 4(Type) + 4(Len) + 4(Magic) + 4(Ver) + 8(SectionLen) + 4(Opt) + 4(Len) = minimo uns 28 bytes
        # SHB Min: Type(4)+Len(4)+Magic(4)+VerMajor(2)+VerMinor(2)+SectionLen(8)+Opt(0)+Len(4) = 32
        
        # Little Endian
        shb_type = 0x0A0D0D0A
        shb_len = 28 # Minimo sem options
        byte_order = 0x1A2B3C4D
        
        # SHB Body: Magic(4) + Ver(2+2) + SectionLen(8)
        shb_body = struct.pack('<IHHq', byte_order, 1, 0, -1)
        
        # Recalcula len: 4+4 + 16(body) + 4(len) = 28
        shb_block = struct.pack('<II', shb_type, 28) + shb_body + struct.pack('<I', 28)
        
        file_bytes = shb_block
        
        packets = parse_pcapng(file_bytes)
        self.assertEqual(len(packets), 0) # Sem pacotes, mas não deve crashar

if __name__ == '__main__':
    unittest.main()
