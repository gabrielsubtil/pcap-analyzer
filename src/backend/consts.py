
import re

# 1. Assinaturas de Strings/Payloads
THREAT_SIGNATURES = [
  { 
    'regex': re.compile(b'(sqlmap|nikto|masscan|nmap|brup)', re.I), 
    'type': 'Scanners Conhecidos', 
    'desc': 'Ferramentas de reconhecimento e ataque detectadas.', 
    'explanation': 'Identifica assinaturas de scanners populares. Indica reconhecimento ativo da infraestrutura ou tentativas automáticas de exploração de vulnerabilidades.',
    'logic': 'Payload matches regex: /(sqlmap|nikto|masscan|nmap|brup)/i'
  },
  { 
    'regex': re.compile(b'(eval\(|base64_decode\(|system\(|shell_exec\()', re.I), 
    'type': 'Webshells PHP Comuns', 
    'desc': 'Execução de funções críticas PHP (Backdoors).', 
    'explanation': 'Detecta funções PHP perigosas comumente usadas em webshells para executar comandos do sistema operacional ou ofuscar código malicioso.',
    'logic': 'Payload matches regex: /(eval\\(|base64_decode\\(|system\\(|shell_exec\\()/i'
  },
  { 
    'regex': re.compile(b'Authorization: Basic', re.I), 
    'type': 'Auth Fraca', 
    'desc': 'Uso de Basic Auth (Credenciais em Base64).', 
    'explanation': 'Mecanismo de autenticação inseguro que transmite credenciais apenas codificadas em Base64, permitindo fácil interceptação e decodificação.',
    'logic': 'Payload matches regex: /Authorization: Basic/i'
  },
  { 
    'regex': re.compile(b'alert\(|script>', re.I), 
    'type': 'XSS', 
    'desc': 'Injeção de scripts maliciosos detectada.', 
    'explanation': 'Tentativa de injetar código JavaScript em páginas web. Pode permitir roubo de sessão, redirecionamentos ou execução de ações em nome do usuário.',
    'logic': 'Payload matches regex: /alert\\(|script>/i'
  },
  { 
    'regex': re.compile(b'\/bin\/sh|\/bin\/bash|cmd\.exe', re.I), 
    'type': 'RCE', 
    'desc': 'Chamadas diretas ao shell do sistema.', 
    'explanation': 'Tentativa crítica de invocar o interpretador de comandos do SO. Geralmente indica exploração bem-sucedida ou tentativa direta de controle do servidor.',
    'logic': 'Payload matches regex: /\\/bin\\/sh|\\/bin\\/bash|cmd\\.exe/i'
  },
]

# 2. Portas suspeitas (Regras Simples Baseadas no Destino ou Origem)
SUSPICIOUS_PORTS = {
  21: { 'desc': 'Tráfego FTP não criptografado.', 'explanation': 'Protocolo de transferência de arquivos legado. Credenciais e dados trafegam em texto claro, vulneráveis a interceptação.', 'logic': 'DstPort == 21 OR SrcPort == 21' },
  23: { 'desc': 'Acesso Telnet inseguro.', 'explanation': 'Protocolo de terminal remoto sem criptografia. Permite captura fácil de senhas e comandos. Deve ser substituído por SSH.', 'logic': 'DstPort == 23 OR SrcPort == 23' },
  6667: { 'desc': 'Tráfego IRC (Potencial Botnet).', 'explanation': 'Protocolo de chat frequentemente utilizado por malwares para comunicação com servidores de Comando e Controle (C&C).', 'logic': 'DstPort == 6667 OR SrcPort == 6667' },
  
  # Windows Services
  445: { 'desc': 'Exposição SMB/CIFS.', 'explanation': 'Compartilhamento de arquivos Windows. Alvo primário de ransomwares e exploits (ex: EternalBlue). Não deve ser exposto na internet.', 'logic': 'DstPort == 445 OR SrcPort == 445' },
  139: { 'desc': 'Sessão NetBIOS exposta.', 'explanation': 'Serviço legado que permite enumeração de nomes e compartilhamentos. Risco significativo de reconhecimento de rede interna.', 'logic': 'DstPort == 139 OR SrcPort == 139' },
  137: { 'desc': 'Serviço de Nomes NetBIOS.', 'explanation': 'Protocolo de resolução de nomes local. Sua exposição permite mapeamento da topologia da rede interna.', 'logic': 'DstPort == 137 OR SrcPort == 137' },
  135: { 'desc': 'Mapeador RPC Endpoint.', 'explanation': 'Mapeia serviços RPC disponíveis. Fundamental para o funcionamento do AD, mas crítico se exposto, permitindo enumeração detalhada.', 'logic': 'DstPort == 135 OR SrcPort == 135' },
  3389: { 'desc': 'RDP (Acesso Remoto).', 'explanation': 'Acesso gráfico remoto ao Windows. Alvo frequente de ataques de força bruta e exploits de execução remota.', 'logic': 'DstPort == 3389 OR SrcPort == 3389' },

  # Network Management
  161: { 'desc': 'Gerenciamento SNMP.', 'explanation': 'Protocolo de monitoramento. Versões baixas transmitem strings de comunidade em texto claro. Alvo de amplificação UDP.', 'logic': 'DstPort == 161 OR SrcPort == 161' },

  # Directory Services
  389: { 'desc': 'LDAP não criptografado.', 'explanation': 'Serviço de diretório (AD/OpenLDAP). O tráfego não criptografado expõe a estrutura do diretório e credenciais.', 'logic': 'DstPort == 389 OR SrcPort == 389' },
  636: { 'desc': 'LDAPS (LDAP sobre SSL).', 'explanation': 'Embora criptografado, a exposição pública de serviços de diretório aumenta significativamente a superfície de ataque.', 'logic': 'DstPort == 636 OR SrcPort == 636' },
  3268: { 'desc': 'Catálogo Global AD (LDAP).', 'explanation': 'Interface de busca para florestas AD. Exposição permite enumeração global de usuários e recursos da organização.', 'logic': 'DstPort == 3268 OR SrcPort == 3268' },
  3269: { 'desc': 'Catálogo Global AD (Seguro).', 'explanation': 'Versão SSL do Catálogo Global. A exposição pública ainda representa um risco de segurança e reconhecimento.', 'logic': 'DstPort == 3269 OR SrcPort == 3269' },

  # Unix/Linux Services
  111: { 'desc': 'RPC Portmapper.', 'explanation': 'Mapeia programas RPC para portas. Usado em ataques de reflexão DDoS (DrDoS) e enumeração de serviços NFS.', 'logic': 'DstPort == 111 OR SrcPort == 111' },
  2049: { 'desc': 'NFS (Network File System).', 'explanation': 'Protocolo de compartilhamento de arquivos Unix. Exposição na WAN é extremamente crítica, permitindo acesso direto aos dados.', 'logic': 'DstPort == 2049 OR SrcPort == 2049' },

  # Bancos de Dados Expostos
  1433: { 'desc': 'SQL Server (MSSQL) exposto.', 'explanation': 'Banco de dados Microsoft. Exposição pública convida ataques de força bruta, injeção SQL e comprometimento de dados.', 'logic': 'DstPort == 1433 OR SrcPort == 1433' },
  3306: { 'desc': 'MySQL/MariaDB exposto.', 'explanation': 'Servidor de banco de dados popular. Vulnerável a ataques de senha e exploits de versão se acessível publicamente.', 'logic': 'DstPort == 3306 OR SrcPort == 3306' },
  5432: { 'desc': 'PostgreSQL exposto.', 'explanation': 'SGBD Avançado. Acesso irrestrito permite tentativas de autenticação e possível execução de código (dependendo da configuração).', 'logic': 'DstPort == 5432 OR SrcPort == 5432' },
  6379: { 'desc': 'Redis exposto.', 'explanation': 'Armazenamento em memória chave-valor. Frequentemente não autenticado por padrão, permitindo roubo de dados e RCE instantâneo.', 'logic': 'DstPort == 6379 OR SrcPort == 6379' },
  27017: { 'desc': 'MongoDB exposto.', 'explanation': 'Banco NoSQL orientado a documentos. Histórico de instâncias abertas resultando em vazamento massivo de dados e ransomware.', 'logic': 'DstPort == 27017 OR SrcPort == 27017' },
}

# 3. Regras Lógicas de Tráfego Complexas
# Convertido 'logic' string para 'criteria' dict para uso no analyzer.py
TRAFFIC_RULES = [
  # --- REGRAS DE PORTA 0 ---
  {
    'id': 'invalid_port_0',
    'title': 'Tráfego Inválido (Porta 0)',
    'comment': 'Uso da porta 0 (reservada) na origem ou destino.',
    'explanation': 'A porta 0 é reservada e inválida para tráfego TCP/UDP padrão. Geralmente indica scanning, fingerprinting de OS ou pacotes malformados.',
    'explanation': 'A porta 0 é reservada e inválida para tráfego TCP/UDP padrão. Geralmente indica scanning, fingerprinting de OS ou pacotes malformados.',
    'logic': 'SrcPort == 0 OR DstPort == 0',
    'criteria': {'src_port': 0, 'dst_ports': [0]} # Analyzer handles Port 0 specially as OR
  },
  
  # --- REGRAS DE AMPLIFICAÇÃO / REFLEXÃO ---
  {
    'id': 'ssdp_amp',
    'title': 'Amplificação SSDP (Porta 1900)',
    'comment': 'Tráfego originado na porta 1900 (UPnP/SSDP).',
    'explanation': 'Dispositivos UPnP mal configurados são usados para ataques DDoS de reflexão massivos. Tráfego vindo desta porta é suspeito.',
    'explanation': 'Dispositivos UPnP mal configurados são usados para ataques DDoS de reflexão massivos. Tráfego vindo desta porta é suspeito.',
    'logic': 'SrcPort == 1900',
    'criteria': {'src_port': 1900}
  },
  {
    'id': 'snmp_amp',
    'title': 'Amplificação SNMP (Porta 161)',
    'comment': 'Tráfego originado na porta 161 (SNMP).',
    'explanation': 'Dispositivos SNMP respondendo a consultas GetBulk spoofadas. Vetor de amplificação DDoS com alto fator de multiplicação.',
    'explanation': 'Dispositivos SNMP respondendo a consultas GetBulk spoofadas. Vetor de amplificação DDoS com alto fator de multiplicação.',
    'logic': 'SrcPort == 161',
    'criteria': {'src_port': 161}
  },
  {
    'id': 'mdns_amp',
    'title': 'Amplificação mDNS (Porta 5353)',
    'comment': 'Tráfego originado na porta 5353 (Multicast DNS).',
    'explanation': 'Protocolo de descoberta local que não deve trafegar na WAN. Usado para amplificação DDoS e vazamento de informações do host.',
    'explanation': 'Protocolo de descoberta local que não deve trafegar na WAN. Usado para amplificação DDoS e vazamento de informações do host.',
    'logic': 'SrcPort == 5353',
    'criteria': {'src_port': 5353}
  },
  {
    'id': 'memcached_amp',
    'title': 'Amplificação Memcached (Porta 11211)',
    'comment': 'Tráfego originado na porta 11211.',
    'explanation': 'Serviço de cache conhecido por fatores de amplificação gigantescos em ataques DDoS (UDP).',
    'explanation': 'Serviço de cache conhecido por fatores de amplificação gigantescos em ataques DDoS (UDP).',
    'logic': 'SrcPort == 11211',
    'criteria': {'src_port': 11211}
  },
  {
    'id': 'cldap_amp',
    'title': 'Reflexão CLDAP (Porta 389)',
    'comment': 'Tráfego UDP originado na porta 389.',
    'explanation': 'Servidores LDAP expostos via UDP (CLDAP) são abusados para ataques de reflexão com alto fator de amplificação.',
    'explanation': 'Servidores LDAP expostos via UDP (CLDAP) são abusados para ataques de reflexão com alto fator de amplificação.',
    'logic': 'SrcPort == 389 AND Proto == UDP',
    'criteria': {'src_port': 389, 'proto': 'UDP'}
  },
  {
    'id': 'ntp_amp_src',
    'title': 'Reflexão NTP (Origem 123)',
    'comment': 'Alto volume de tráfego vindo da porta 123.',
    'explanation': 'Respostas NTP não solicitadas (Monlist) usadas em ataques de negação de serviço distribuído.',
    'explanation': 'Respostas NTP não solicitadas (Monlist) usadas em ataques de negação de serviço distribuído.',
    'logic': 'SrcPort == 123',
    'criteria': {'src_port': 123, 'dst_port_not': 123} # Implicit "valid NTP" exclusion typically added, but based on user logic only SrcPort==123 mentioned? 
    # User's logic string: 'SrcPort == 123'. 
    # However, keeping proper logic to avoid false positives (valid NTP reply) is wise unless strictly forbidden. 
    # I will stick to criteria that matches the INTENT. Analyzer has 'dst_port_not' support.
  },
  {
    'id': 'chargen_abuse',
    'title': 'Serviço Chargen (Porta 19)',
    'comment': 'Tráfego originado na porta 19 (Obsoleto).',
    'explanation': 'Serviço legado (Character Generator) abusado para ataques de amplificação. Não possui uso legítimo moderno na internet.',
    'explanation': 'Serviço legado (Character Generator) abusado para ataques de amplificação. Não possui uso legítimo moderno na internet.',
    'logic': 'SrcPort == 19',
    'criteria': {'src_port': 19}
  },

  # --- REGRAS DE ACESSO INDEVIDO ---


  {
    'id': 'ntp_abuse_low_port',
    'title': 'Acesso Indevido NTP (Regra de Controle)',
    'comment': 'Origem porta < 1024 (exceto 123) tentando acessar NTP.',
    'explanation': 'Bloqueia tráfego vindo de portas baixas para NTP, prevenindo abusos e garantindo que origem legítima seja 123 ou portas altas.',
    'explanation': 'Bloqueia tráfego vindo de portas baixas para NTP, prevenindo abusos e garantindo que origem legítima seja 123 ou portas altas.',
    'logic': 'DstPort == 123 AND SrcPort < 1024 AND SrcPort != 123',
    'criteria': {'src_port_max': 1023, 'dst_ports': [123], 'src_port_not': 123}
  },
  {
    'id': 'chargen_dst_abuse',
    'title': 'Destino Chargen (Porta 19)',
    'comment': 'Tráfego destinado à porta 19.',
    'explanation': 'Tentativa de ativar o serviço Chargen em um host para iniciar um ataque de reflexão.',
    'explanation': 'Tentativa de ativar o serviço Chargen em um host para iniciar um ataque de reflexão.',
    'logic': 'DstPort == 19',
    'criteria': {'dst_ports': [19]}
  },
  {
    'id': 'web_low_source',
    'title': 'Ataque Web Low-to-Low',
    'comment': 'Origem 1-1023 -> Destino 80/443/8080/8443/8000/8008.',
    'explanation': 'Conexão vindo de porta privilegiada para servidor Web. Indica servidor hackeado atacando ou evasão de firewall.',
    'explanation': 'Conexão vindo de porta privilegiada para servidor Web. Indica servidor hackeado atacando ou evasão de firewall.',
    'logic': 'SrcPort IN [1..1023] AND DstPort IN [80, 443, 8080, 8443, 8000, 8008]',
    'criteria': {'src_port_max': 1023, 'dst_ports': [80, 443, 8080, 8443, 8000, 8008]}
  },
  {
    'id': 'ms_rpc_smb_low',
    'title': 'Ataque Windows Low-to-Low',
    'comment': 'Origem 1-1023 -> Destino 135/139/445.',
    'explanation': 'Tráfego RPC/SMB originado em portas baixas. Padrão anômalo indicativo de propagação de worms.',
    'explanation': 'Tráfego RPC/SMB originado em portas baixas. Padrão anômalo indicativo de propagação de worms.',
    'logic': 'SrcPort IN [1..1023] AND DstPort IN [135, 139, 445]',
    'criteria': {'src_port_max': 1023, 'dst_ports': [135, 139, 445]}
  },
  {
    'id': 'netbios_low',
    'title': 'Ataque NetBIOS Low-to-Low',
    'comment': 'Origem 1-1023 -> Destino 137/138.',
    'explanation': 'Cruzamento de tráfego NetBIOS entre portas baixas, comum em tentativas de amplificação.',
    'explanation': 'Cruzamento de tráfego NetBIOS entre portas baixas, comum em tentativas de amplificação.',
    'logic': 'SrcPort IN [1..1023] AND DstPort IN [137, 138]',
    'criteria': {'src_port_max': 1023, 'dst_ports': [137, 138]}
  },
  {
    'id': 'unix_nfs_low',
    'title': 'Ataque NFS/RPC Low-to-Low',
    'comment': 'Origem 1-1023 -> Destino 111/2049.',
    'explanation': 'Tentativa de montagem ou exploração de NFS partindo de porta privilegiada.',
    'explanation': 'Tentativa de montagem ou exploração de NFS partindo de porta privilegiada.',
    'logic': 'SrcPort IN [1..1023] AND DstPort IN [111, 2049]',
    'criteria': {'src_port_max': 1023, 'dst_ports': [111, 2049]}
  },
  {
    'id': 'remote_infra_low',
    'title': 'Ataque Infra Low-to-Low',
    'comment': 'Origem 1-1023 -> Destino 22/23/3389/21.',
    'explanation': 'Tentativa de conexão SSH/RDP/Telnet/FTP vindo de porta privilegiada. Indica pivoteamento.',
    'explanation': 'Tentativa de conexão SSH/RDP/Telnet/FTP vindo de porta privilegiada. Indica pivoteamento.',
    'logic': 'SrcPort IN [1..1023] AND DstPort IN [22, 23, 3389, 21]',
    'criteria': {'src_port_max': 1023, 'dst_ports': [22, 23, 3389, 21]}
  },
  {
    'id': 'reflection_vectors_low',
    'title': 'Vetor Reflexão Low-to-Low',
    'comment': 'Origem 1-1023 -> Destino 1900/5353/389.',
    'explanation': 'Dispositivos tentando falar com vetores de amplificação (SSDP/mDNS/LDAP) usando portas baixas.',
    'explanation': 'Dispositivos tentando falar com vetores de amplificação (SSDP/mDNS/LDAP) usando portas baixas.',
    'logic': 'SrcPort IN [1..1023] AND DstPort IN [1900, 5353, 389]',
    'criteria': {'src_port_max': 1023, 'dst_ports': [1900, 5353, 389]}
  },
  {
    'id': 'dns_low_to_low',
    'title': 'Ataque DNS Low-to-Low',
    'comment': 'Acesso fora do padrão do DNS',
    'explanation': 'Origem de 0-1023 com exceção da origem porta 53 tentando acessar a porta de destino 53.',
    'logic': 'SrcPort 0-1023 AND SrcPort != 53 AND DstPort == 53',
    'criteria': {'src_port_max': 1023, 'dst_ports': [53], 'src_port_not': 53}
  },
]

def get_threat_catalog():
    """Retorna lista unificada para exibição no frontend."""
    catalog = []
    
    # 1. Signatures
    for sig in THREAT_SIGNATURES:
        catalog.append({
            'id': f"sig-{sig['type']}", 
            'title': sig['type'],
            'comment': sig['desc'],
            'explanation': sig['explanation'],
            'explanation': sig['explanation'],
            'logic': sig.get('logic', '')
        })
        
    # 2. Suspicious Ports
    for port, info in SUSPICIOUS_PORTS.items():
        catalog.append({
            'id': f"suspicious_port_{port}", 
            'title': info.get('desc', f'Porta Suspeita {port}'), 
            'comment': info.get('desc', ''), 
            'explanation': info['explanation'],
            'explanation': info['explanation'],
            'logic': info.get('logic', '')
        })
        
    # 3. Traffic Rules (Single Source of Truth - Dedup by ID match reference)
    seen_ids = set()
    for rule in TRAFFIC_RULES:
        if rule['id'] not in seen_ids:
            seen_ids.add(rule['id'])
            catalog.append({
                'id': rule['id'],
                'title': rule['title'],
                'comment': rule['comment'],
                'explanation': rule['explanation'],
                'explanation': rule['explanation'],
                'logic': rule.get('logic', '')
            })
        
    return catalog
