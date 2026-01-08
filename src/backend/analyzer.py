# Lógica de Análise de Tráfego
# Português do Brasil

import re
from collections import defaultdict
from .consts import THREAT_SIGNATURES, TRAFFIC_RULES, SUSPICIOUS_PORTS
from .database import db

def analyze_packets(packets):
    """
    Analisa uma lista de pacotes processados e retorna um relatório completo.
    Utiliza SQLite em memória para armazenar objetos grandes (strings).
    """
    # 1. Limpa banco de dados anterior
    db.clear_data()

    report = {
        'totalPackets': len(packets),
        'totalBytes': sum(p['length'] for p in packets),
        'uniqueIps': set(),
        'uniqueSrcIpsCount': 0,
        'uniqueDstIpsCount': 0,
        'topTalkers': [],
        'topDestinations': [],
        'protocolStats': defaultdict(int),
        'portStats': defaultdict(int),
        'srcPortStats': defaultdict(int),
        'packetSizeStats': defaultdict(int),
        'suspiciousFindings': [],
        'threatStats': [],
        'threatStrings': [], # Agora vazio, populado via API on-demand
        'extractedStrings': []
    }

    talker_map = defaultdict(int)
    destination_map = defaultdict(int)
    
    # Mapas auxiliares para agregação
    threat_map = {} # key -> ThreatStat
    
    # Buffer para inserção em massa no SQLite
    threat_string_buffer = {} # Dedup buffer before DB
    dns_buffer = {} # Dedup buffer for DNS

    # DNS Types Map
    DNS_TYPES = {
        1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 41: 'OPT', 255: 'ANY'
    }

    def add_threat(key, title, desc):
        if key not in threat_map:
            threat_map[key] = {
                'id': key,
                'title': title,
                'description': desc,
                'count': 0
            }
        threat_map[key]['count'] += 1

    def add_threat_string(t_type, desc, explanation, payload):
        text = ""
        if payload:
            if isinstance(payload, bytes):
                text = payload.decode('latin1', errors='replace')
            else:
                text = str(payload)
            
            # Sanitiza
            text = re.sub(r'[^\x20-\x7E]', '.', text)
            
        if not text or len(text) < 3 or (len(text) > 10 and text.count('.') > len(text) * 0.8):
             text = "[Nenhum payload ASCII legível detectado]"
        elif not any(c.isalnum() for c in text): 
             text = "[Nenhum payload ASCII legível detectado]"

        key = f"{t_type}-{text}"
        if key not in threat_string_buffer:
            threat_string_buffer[key] = {
                'key': key,
                'threatType': t_type,
                'threatDesc': desc,
                'threatExplanation': explanation,
                'payload': text,
                'count': 0
            }
        threat_string_buffer[key]['count'] += 1

    def parse_dns_query(payload):
        """
        Tenta extrair Transaction ID, Name e Type de um pacote DNS (bytes).
        Retorna (tx_id_hex, name, type_str) ou (None, None, None).
        """
        if not payload or len(payload) < 12:
            return None, None, None
            
        try:
            # Header
            # ID: 2 bytes
            tx_id = payload[:2]
            tx_id_hex = "0x" + tx_id.hex()
            
            # Flags (2 bytes), QDCOUNT (2 bytes), ANCOUNT (2 bytes), NSCOUNT (2 bytes), ARCOUNT (2 bytes)
            # Question Section starts at offset 12
            
            # Parse Query Name (QNAME)
            offset = 12
            labels = []
            
            while offset < len(payload):
                length = payload[offset]
                
                if length == 0:
                    offset += 1
                    break # End of name
                
                if (length & 0xC0) == 0xC0:
                    # Compression pointer (not typical in Query section but possible)
                    # For simplicity in this parser, we might stop here or skip
                    offset += 2
                    break
                
                offset += 1
                if offset + length > len(payload):
                    return None, None, None
                    
                label = payload[offset : offset + length]
                try:
                    labels.append(label.decode('utf-8'))
                except:
                    labels.append(label.decode('latin1', errors='replace'))
                    
                offset += length
            
            qname = ".".join(labels)
            
            # QTYPE (2 bytes)
            if offset + 2 > len(payload):
                return tx_id_hex, qname, "UNKNOWN"
                
            qtype_val = int.from_bytes(payload[offset : offset + 2], byteorder='big')
            qtype_str = DNS_TYPES.get(qtype_val, f"TYPE{qtype_val}")
            
            return tx_id_hex, qname, qtype_str

        except Exception:
            return None, None, None

    def add_dns_record(payload):
        tx_id, name, qtype = parse_dns_query(payload)
        
        if not name or not qtype:
            return # Skip invalid DNS

        key = f"{name}|{qtype}"

        if key not in dns_buffer:
            dns_buffer[key] = {
                'transaction_id': tx_id,
                'query_name': name,
                'query_type': qtype,
                'count': 0
            }
        dns_buffer[key]['count'] += 1

    for p in packets:
        # DNS Logic (Port 53) - Process FIRST but ALLOW flow to general stats
        if p['srcPort'] == 53 or p['dstPort'] == 53:
            add_dns_record(p['payload'])

        # IPs
        report['uniqueIps'].add(p['srcIp'])
        report['uniqueIps'].add(p['dstIp'])
        
        talker_map[p['srcIp']] += 1
        destination_map[p['dstIp']] += 1
        
        # Protocol
        report['protocolStats'][p['proto']] += 1
        
        # Size
        report['packetSizeStats'][p['length']] += 1
        
        # Ports
        if p['srcPort'] is not None and p['srcPort'] >= 0:
            report['srcPortStats'][p['srcPort']] += 1
        else:
             report['srcPortStats']['_null'] += 1
            
        if p['dstPort'] is not None and p['dstPort'] >= 0:
            report['portStats'][p['dstPort']] += 1
        else:
             report['portStats']['_null'] += 1
        

        # 2. Loop Genérico de Regras (Data-Driven by Consts)
        for rule in TRAFFIC_RULES:
            match = False
            criteria = rule.get('criteria', {})
            
            if not criteria:
                continue
            
            # ... rest of the loop logic is unchanged in essence, but including it for context matching if needed ...
            # To minimize churn I will just insert the DNS check above and keep existing logic.
            # But replace_file_content needs contiguous block. 
            # I will include the rule loop start to anchor.
            
            if 'src_port_not' in criteria:
                if p['srcPort'] == criteria['src_port_not']:
                    continue

            if 'dst_port_not' in criteria:
                if p['dstPort'] == criteria['dst_port_not']:
                    continue

            # Critérios de INCLUSÃO
            if 'src_port' in criteria:
                if criteria['src_port'] == 0 and p['srcPort'] == 0:
                    match = True
                elif 'proto' in criteria:
                     if p['proto'] == criteria['proto'] and p['srcPort'] == criteria['src_port']:
                         match = True
                elif p['proto'] in ['TCP', 'UDP'] and p['srcPort'] == criteria['src_port']:
                    match = True

            elif 'dst_ports' in criteria:
                if p['dstPort'] in criteria['dst_ports']:
                    match = True
                    if 'src_port_max' in criteria:
                        if p['srcPort'] is None or p['srcPort'] > criteria['src_port_max']:
                            match = False

            elif 'src_port_max' in criteria and 'dst_ports' not in criteria:
                 if p['srcPort'] is not None and p['srcPort'] <= criteria['src_port_max']:
                     match = True

            if 'src_ports' in criteria and p['srcPort'] in criteria['src_ports']:
                 match = True

            if match:
                 add_threat(rule['id'], rule['title'], rule['comment'])
                 add_threat_string(rule['title'], rule['comment'], rule['explanation'], p['payload'])

        # 3. Portas Suspeitas
        if p['dstPort'] in SUSPICIOUS_PORTS:
             info = SUSPICIOUS_PORTS[p['dstPort']]
             threat_id = f"suspicious_port_{p['dstPort']}"
             add_threat(threat_id, info.get('desc'), info.get('explanation', ''))
             str_title = f"Porta Destino {p['dstPort']}"
             add_threat_string(str_title, info.get('desc'), info.get('explanation', ''), p['payload'])

        elif p['srcPort'] in SUSPICIOUS_PORTS:
             info = SUSPICIOUS_PORTS[p['srcPort']]
             threat_id = f"suspicious_port_{p['srcPort']}"
             add_threat(threat_id, info.get('desc'), info.get('explanation', ''))
             str_title = f"Porta Origem {p['srcPort']}"
             add_threat_string(str_title, info.get('desc'), info.get('explanation', ''), p['payload'])

        # 3. Assinaturas de Strings
        if p['payload'] and len(p['payload']) > 5:
            for sig in THREAT_SIGNATURES:
                if sig['regex'].search(p['payload']):
                    report['suspiciousFindings'].append({
                        'type': sig['type'],
                        'description': f"{sig['desc']} no pacote #{p['id']}",
                        'packetId': p['id']
                    })
                    add_threat(f"sig-{sig['type']}", sig['type'], sig['desc'])
                    add_threat_string(sig['type'], sig['desc'], sig['explanation'], p['payload'])

    # Finalização: Persiste Strings no SQLite e remove do JSON
    if threat_string_buffer:
        db.insert_strings_bulk(list(threat_string_buffer.values()))
    
    if dns_buffer:
        db.insert_dns_bulk(list(dns_buffer.values()))
    
    # report['threatStrings'] permanece VAZIO [] para não pesar o JSON.
    # O Frontend buscará via API get_strings()
    
    report['uniqueSrcIpsCount'] = len(talker_map)
    report['uniqueDstIpsCount'] = len(destination_map)
    
    # Otimização: Limitar listas de IPs para evitar JSON gigante
    # Se o usuário precisar ver TODOS, implementaremos paginação depois.
    report['uniqueIps'] = list(report['uniqueIps'])[:1000] 

    report['topTalkers'] = sorted(talker_map.items(), key=lambda x: x[1], reverse=True)[:100]
    report['topDestinations'] = sorted(destination_map.items(), key=lambda x: x[1], reverse=True)[:100]
    
    report['threatStats'] = sorted(threat_map.values(), key=lambda x: x['count'], reverse=True)

    return report
