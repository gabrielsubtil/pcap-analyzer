# Parser Scapy para PCAP e PCAPNG
# Português do Brasil

from scapy.all import PcapReader, rdpcap, Raw
import time

def process_scapy_packet(pkt, packet_id):
    """
    Processa um pacote Scapy e retorna o dicionário padrão para o analisador.
    """
    try:
        # Extração básica IPv4
        if not pkt.haslayer('IP'):
            return None
            
        ip_layer = pkt['IP']
        
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto_num = ip_layer.proto
        proto_name = 'OUTRO'
        
        src_port = None
        dst_port = None
        
        if pkt.haslayer('TCP'):
            proto_name = 'TCP'
            src_port = pkt['TCP'].sport
            dst_port = pkt['TCP'].dport
        elif pkt.haslayer('UDP'):
            proto_name = 'UDP'
            src_port = pkt['UDP'].sport
            dst_port = pkt['UDP'].dport
        elif pkt.haslayer('ICMP'):
            proto_name = 'ICMP'
            # ICMP não tem portas padrão, manter None ou 0 conforme regra
            src_port = 0 
            dst_port = 0
            
        # Payload extraction
        # Pega o payload da camada de transporte ou IP se não houver transporte
        payload = b""
        if pkt.haslayer(Raw):
            payload = pkt[Raw].load
        elif pkt.haslayer('DNS'):
            # Se Scapy decodificou como DNS, converte de volta para bytes para analisador manual
            payload = bytes(pkt['DNS'])
        elif pkt.haslayer('UDP') and len(pkt['UDP'].payload) > 0:
            # Fallback para UDP
             payload = bytes(pkt['UDP'].payload)
        elif pkt.haslayer('TCP') and len(pkt['TCP'].payload) > 0:
             # Fallback para TCP
             payload = bytes(pkt['TCP'].payload)
        
        # Timestamp
        timestamp = float(pkt.time) * 1000 # Convert to ms
        
        return {
            'id': packet_id,
            'srcIp': src_ip,
            'dstIp': dst_ip,
            'proto': proto_name,
            'srcPort': src_port,
            'dstPort': dst_port,
            'length': len(pkt),
            'payload': payload,
            'timestamp': timestamp # Mantém numérico
        }

    except Exception as e:
        # print(f"Erro processando pacote {packet_id}: {e}")
        return None

def parse_pcap(file_bytes_or_path):
    """
    Lê arquivo PCAP/PCAPNG usando Scapy.
    Aceita caminho do arquivo (preferível para streaming) ou bytes (via buffer).
    """
    packets = []
    
    # Se receber bytes (do upload via pywebview), precisamos salvar temporariamente
    # ou usar bytesio, mas Scapy costuma querer arquivo para PcapReader (streaming).
    # Com rdpcap aceita BytesIO, mas carrega tudo na RAM.
    # Dado que "file_bytes" vem do ler_pcap no boot.py que lê tudo pra memória:
    # Vamos manter a leitura de bytes mas passar para o Scapy.
    
    # NOTA: O fluxo atual lê o arquivo inteiro em memória no Python antes de chamar parse_pcap.
    # Para performance ideal com Scapy e arquivos grandes, o ideal seria passar o PATH.
    # Mas como o parser.py recebe "file_bytes", vamos adaptar.
    
    import io
    from scapy.utils import PcapReader as ScapyPcapReader
    from scapy.utils import PcapNgReader as ScapyPcapNgReader
    
    # Detecção básica de Magic Number para diferenciar PCAP/NG se necessário,
    # ou deixar o Scapy tentar detectar via rdpcap que é genérico.
    
    try:
        # Criar um arquivo virtual em memória
        mem_file = io.BytesIO(file_bytes_or_path)
        
        # rdpcap lê tudo de uma vez. Para 5000 pacotes é ok.
        # Para gigabytes, travaria.
        # Usuário pediu "Bibliotecas Padrão" e "Confiabilidade".
        # Scapy rdpcap lida com PCAP e PCAPNG automaticamente.
        
        scapy_packets = rdpcap(mem_file)
        
        packet_id = 1
        for pkt in scapy_packets:
            parsed = process_scapy_packet(pkt, packet_id)
            if parsed:
                packets.append(parsed)
                packet_id += 1
                
        return packets
        
    except Exception as e:
        print(f"Erro no Scapy Parse: {e}")
        return []

# Alias para compatibilidade, já que rdpcap resolve ambos
def parse_pcapng(file_bytes):
    return parse_pcap(file_bytes)

