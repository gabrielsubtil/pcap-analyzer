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

def parse_pcap(file_path):
    """
    Lê arquivo PCAP/PCAPNG usando Scapy em modo Streaming (Generator).
    Recebe caminho do arquivo para performance ideal.
    """
    # Importação dentro da função para evitar custo de carga inicial se não usado
    from scapy.utils import PcapReader as ScapyPcapReader
    from scapy.error import Scapy_Exception

    packet_id = 1
    
    try:
        # PcapReader do Scapy detecta automaticamente se é pcap ou pcapng
        # e lê pacote por pacote do disco (Iterador).
        with ScapyPcapReader(file_path) as pcap_reader:
            for pkt in pcap_reader:
                parsed = process_scapy_packet(pkt, packet_id)
                if parsed:
                    yield parsed
                    packet_id += 1
                    
    except Scapy_Exception as e:
        print(f"Erro Scapy (arquivo pode estar corrompido ou incompleto): {e}")
    except Exception as e:
        print(f"Erro Genérico no Parse PCAP: {e}")
        # Em generators, exceções interrompem o loop. 
        # Podemos logar e terminar graciosamente para que o analisador aproveite o que já leu.

# Alias para compatibilidade, já que rdpcap resolve ambos
def parse_pcapng(file_bytes):
    return parse_pcap(file_bytes)

