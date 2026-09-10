use etherparse::{LaxPacketHeaders, NetHeaders, TransportHeader};
use pcap_parser::{PcapBlockOwned, PcapError, create_reader, pcapng::Block};
use serde::Serialize;
use std::{
    collections::{BTreeSet, HashMap},
    fs::File,
    net::Ipv4Addr,
    path::Path,
};

pub const PARSER_BUFFER_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PACKET_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_PACKETS: u64 = 1_000_000;
pub const MAX_BLOCKS: u64 = 1_000_000;
const TOP_N: usize = 10;
const MAX_SIGNATURE_SCAN_BYTES: usize = 64 * 1024;
pub const MAX_DNS_ENTRIES: usize = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureFormat {
    Pcap,
    PcapNg,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureValidationError {
    HeaderTooShort,
    UnsupportedFormat,
}
pub fn detect_format(header: &[u8]) -> Result<CaptureFormat, CaptureValidationError> {
    let magic: [u8; 4] = header
        .get(..4)
        .ok_or(CaptureValidationError::HeaderTooShort)?
        .try_into()
        .unwrap();
    match magic {
        [0xd4, 0xc3, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0xc3, 0xd4]
        | [0x4d, 0x3c, 0xb2, 0xa1]
        | [0xa1, 0xb2, 0x3c, 0x4d] => Ok(CaptureFormat::Pcap),
        [0x0a, 0x0d, 0x0d, 0x0a] => Ok(CaptureFormat::PcapNg),
        _ => Err(CaptureValidationError::UnsupportedFormat),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LinktypeMetric {
    pub value: i32,
    pub packets: u64,
    pub packet_metrics_supported: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct DistributionMetric {
    pub value: String,
    pub packets: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct PortMetric {
    pub port: u16,
    pub packets: u64,
}
#[derive(Debug, Clone, Default, Serialize)]
pub struct ProtocolCounts {
    pub tcp: u64,
    pub udp: u64,
    pub icmp: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct ProtocolSummary {
    pub version: &'static str,
    pub parsed_packets: u64,
    pub unparsed_packets: u64,
    pub truncated_packets: u64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub protocol_counts: ProtocolCounts,
    pub source_ports: Vec<PortMetric>,
    pub destination_ports: Vec<PortMetric>,
    pub unique_source_ips: u64,
    pub unique_destination_ips: u64,
    pub top_talkers: Vec<DistributionMetric>,
    pub top_destinations: Vec<DistributionMetric>,
    pub packet_size_stats: HashMap<u64, u64>,
}
#[derive(Debug, Clone, Serialize)]
pub struct CaptureMetrics {
    pub contract_version: &'static str,
    pub analysis: &'static str,
    pub format: &'static str,
    pub file_bytes: u64,
    pub block_count: u64,
    pub packet_count: u64,
    pub captured_bytes: u64,
    pub original_bytes: u64,
    pub truncated_packets: u64,
    pub linktypes: Vec<LinktypeMetric>,
    pub unsupported_formats: Vec<&'static str>,
    pub unsupported_linktypes: Vec<i32>,
    pub summary: ProtocolSummary,
    pub threat_summary: Vec<ThreatSummaryEntry>,
    pub dns: DnsSummary,
    #[serde(skip)]
    pub(crate) dns_records: Vec<DnsParityEntry>,
    #[serde(skip)]
    pub(crate) aggregate: AggregateState,
}
#[derive(Debug, Clone, Serialize)]
pub struct DnsSummary {
    pub version: &'static str,
    pub supported_transport: &'static str,
    pub parsed_queries: u64,
    pub unique_queries: u64,
    pub malformed_packets: u64,
    pub truncated_packets: u64,
    pub compressed_packets: u64,
    pub tcp_unsupported_packets: u64,
    pub cardinality_capped: bool,
}
#[derive(Debug, Clone, Serialize)]
pub struct DnsEntry {
    pub name: String,
    pub qtype: String,
    pub count: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct DnsParityEntry {
    #[serde(rename = "transactionId")]
    pub transaction_id: u16,
    #[serde(rename = "queryName")]
    pub query_name: String,
    #[serde(rename = "queryType")]
    pub query_type: String,
    pub count: u64,
}
#[derive(Debug, Clone, Serialize)]
pub struct ThreatSummaryEntry {
    pub rule_id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub count: u64,
}
#[derive(Debug)]
pub enum ParseError {
    InvalidCapture,
    LimitExceeded(&'static str),
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AggregateState {
    pub(crate) src_ips: BTreeSet<Ipv4Addr>,
    pub(crate) dst_ips: BTreeSet<Ipv4Addr>,
    pub(crate) talkers: HashMap<Ipv4Addr, u64>,
    pub(crate) destinations: HashMap<Ipv4Addr, u64>,
    pub(crate) src_ports: HashMap<u16, u64>,
    pub(crate) dst_ports: HashMap<u16, u64>,
    pub(crate) packet_sizes: HashMap<u64, u64>,
    pub(crate) protocols: ProtocolCounts,
    threats: ThreatCounts,
    pub(crate) dns: HashMap<(u16, String, String), u64>,
    pub(crate) parsed: u64,
    pub(crate) unparsed: u64,
    pub(crate) truncated: u64,
    pub(crate) dns_parsed: u64,
    pub(crate) dns_malformed: u64,
    pub(crate) dns_truncated: u64,
    pub(crate) dns_compressed: u64,
    pub(crate) dns_tcp: u64,
}

#[derive(Default)]
struct Acc {
    parsed: u64,
    unparsed: u64,
    truncated: u64,
    protocols: ProtocolCounts,
    src_ports: HashMap<u16, u64>,
    dst_ports: HashMap<u16, u64>,
    src_ips: BTreeSet<Ipv4Addr>,
    dst_ips: BTreeSet<Ipv4Addr>,
    talkers: HashMap<Ipv4Addr, u64>,
    destinations: HashMap<Ipv4Addr, u64>,
    packet_sizes: HashMap<u64, u64>,
    threats: ThreatCounts,
    dns: HashMap<(u16, String, String), u64>,
    dns_parsed: u64,
    dns_malformed: u64,
    dns_truncated: u64,
    dns_compressed: u64,
    dns_tcp: u64,
}

#[derive(Default, Clone, Debug)]
struct ThreatCounts {
    counts: HashMap<&'static str, u64>,
}

impl ThreatCounts {
    fn add(&mut self, id: &'static str) {
        *self.counts.entry(id).or_default() += 1;
    }
    fn entries(&self) -> Vec<ThreatSummaryEntry> {
        let mut entries: Vec<_> = THREAT_CATALOG
            .iter()
            .filter_map(|rule| {
                self.counts.get(rule.id).map(|count| ThreatSummaryEntry {
                    rule_id: rule.id,
                    title: rule.title,
                    description: rule.description,
                    count: *count,
                })
            })
            .collect();
        entries.sort_by(|a, b| b.count.cmp(&a.count).then(a.rule_id.cmp(b.rule_id)));
        entries
    }
}

struct ThreatDefinition {
    id: &'static str,
    title: &'static str,
    description: &'static str,
}

const THREAT_CATALOG: &[ThreatDefinition] = &[
    ThreatDefinition {
        id: "suspicious_port_21",
        title: "Porta 21 (FTP)",
        description: "Tráfego FTP não criptografado.",
    },
    ThreatDefinition {
        id: "suspicious_port_23",
        title: "Porta 23 (Telnet)",
        description: "Acesso Telnet inseguro.",
    },
    ThreatDefinition {
        id: "suspicious_port_6667",
        title: "Porta 6667 (IRC)",
        description: "Tráfego IRC potencialmente associado a botnet.",
    },
    ThreatDefinition {
        id: "suspicious_port_445",
        title: "Porta 445 (SMB)",
        description: "Exposição SMB/CIFS.",
    },
    ThreatDefinition {
        id: "suspicious_port_139",
        title: "Porta 139 (NetBIOS)",
        description: "Sessão NetBIOS exposta.",
    },
    ThreatDefinition {
        id: "suspicious_port_137",
        title: "Porta 137 (NetBIOS)",
        description: "Serviço de nomes NetBIOS.",
    },
    ThreatDefinition {
        id: "suspicious_port_135",
        title: "Porta 135 (RPC)",
        description: "Mapeador RPC exposto.",
    },
    ThreatDefinition {
        id: "suspicious_port_3389",
        title: "Porta 3389 (RDP)",
        description: "Acesso remoto RDP.",
    },
    ThreatDefinition {
        id: "suspicious_port_161",
        title: "Porta 161 (SNMP)",
        description: "Gerenciamento SNMP exposto.",
    },
    ThreatDefinition {
        id: "suspicious_port_389",
        title: "Porta 389 (LDAP)",
        description: "LDAP não criptografado.",
    },
    ThreatDefinition {
        id: "suspicious_port_636",
        title: "Porta 636 (LDAPS)",
        description: "Catálogo LDAP seguro exposto.",
    },
    ThreatDefinition {
        id: "suspicious_port_3268",
        title: "Porta 3268 (AD)",
        description: "Catálogo Global AD exposto.",
    },
    ThreatDefinition {
        id: "suspicious_port_3269",
        title: "Porta 3269 (AD seguro)",
        description: "Catálogo Global AD seguro exposto.",
    },
    ThreatDefinition {
        id: "suspicious_port_111",
        title: "Porta 111 (RPC)",
        description: "RPC Portmapper exposto.",
    },
    ThreatDefinition {
        id: "suspicious_port_2049",
        title: "Porta 2049 (NFS)",
        description: "NFS exposto.",
    },
    ThreatDefinition {
        id: "suspicious_port_1433",
        title: "Porta 1433 (MSSQL)",
        description: "SQL Server exposto.",
    },
    ThreatDefinition {
        id: "suspicious_port_3306",
        title: "Porta 3306 (MySQL)",
        description: "MySQL/MariaDB exposto.",
    },
    ThreatDefinition {
        id: "suspicious_port_5432",
        title: "Porta 5432 (PostgreSQL)",
        description: "PostgreSQL exposto.",
    },
    ThreatDefinition {
        id: "suspicious_port_6379",
        title: "Porta 6379 (Redis)",
        description: "Redis exposto.",
    },
    ThreatDefinition {
        id: "suspicious_port_27017",
        title: "Porta 27017 (MongoDB)",
        description: "MongoDB exposto.",
    },
    ThreatDefinition {
        id: "invalid_port_0",
        title: "Tráfego inválido (porta 0)",
        description: "Uso da porta 0 reservada na origem ou destino.",
    },
    ThreatDefinition {
        id: "ssdp_amp",
        title: "Amplificação SSDP",
        description: "Tráfego originado na porta 1900.",
    },
    ThreatDefinition {
        id: "snmp_amp",
        title: "Amplificação SNMP",
        description: "Tráfego originado na porta 161.",
    },
    ThreatDefinition {
        id: "mdns_amp",
        title: "Amplificação mDNS",
        description: "Tráfego originado na porta 5353.",
    },
    ThreatDefinition {
        id: "memcached_amp",
        title: "Amplificação Memcached",
        description: "Tráfego originado na porta 11211.",
    },
    ThreatDefinition {
        id: "cldap_amp",
        title: "Reflexão CLDAP",
        description: "Tráfego UDP originado na porta 389.",
    },
    ThreatDefinition {
        id: "ntp_amp_src",
        title: "Reflexão NTP",
        description: "Tráfego originado na porta 123 para destino diferente de 123.",
    },
    ThreatDefinition {
        id: "chargen_abuse",
        title: "Serviço Chargen",
        description: "Tráfego originado na porta 19.",
    },
    ThreatDefinition {
        id: "ntp_abuse_low_port",
        title: "Acesso indevido NTP",
        description: "Origem baixa diferente de 123 para destino 123.",
    },
    ThreatDefinition {
        id: "chargen_dst_abuse",
        title: "Destino Chargen",
        description: "Tráfego destinado à porta 19.",
    },
    ThreatDefinition {
        id: "web_low_source",
        title: "Web low-to-low",
        description: "Origem 1-1023 para portas web.",
    },
    ThreatDefinition {
        id: "ms_rpc_smb_low",
        title: "Windows low-to-low",
        description: "Origem 1-1023 para RPC/SMB.",
    },
    ThreatDefinition {
        id: "netbios_low",
        title: "NetBIOS low-to-low",
        description: "Origem 1-1023 para NetBIOS.",
    },
    ThreatDefinition {
        id: "unix_nfs_low",
        title: "NFS/RPC low-to-low",
        description: "Origem 1-1023 para NFS/RPC.",
    },
    ThreatDefinition {
        id: "remote_infra_low",
        title: "Infra low-to-low",
        description: "Origem 1-1023 para SSH/Telnet/RDP/FTP.",
    },
    ThreatDefinition {
        id: "reflection_vectors_low",
        title: "Vetor de reflexão low-to-low",
        description: "Origem 1-1023 para SSDP/mDNS/LDAP.",
    },
    ThreatDefinition {
        id: "dns_low_to_low",
        title: "DNS low-to-low",
        description: "Origem 0-1023 diferente de 53 para destino 53.",
    },
    ThreatDefinition {
        id: "sig-scanners",
        title: "Scanners conhecidos",
        description: "Assinatura fixa de ferramentas de reconhecimento.",
    },
    ThreatDefinition {
        id: "sig-webshells",
        title: "Webshells PHP comuns",
        description: "Assinatura fixa de funções PHP críticas.",
    },
    ThreatDefinition {
        id: "sig-auth",
        title: "Auth fraca",
        description: "Assinatura fixa de cabeçalho Authorization.",
    },
    ThreatDefinition {
        id: "sig-xss",
        title: "XSS",
        description: "Assinatura fixa de injeção de script.",
    },
    ThreatDefinition {
        id: "sig-rce",
        title: "RCE",
        description: "Assinatura fixa de chamadas ao shell.",
    },
];

pub fn catalog() -> Vec<ThreatSummaryEntry> {
    THREAT_CATALOG
        .iter()
        .map(|rule| ThreatSummaryEntry {
            rule_id: rule.id,
            title: rule.title,
            description: rule.description,
            count: 0,
        })
        .collect()
}

pub fn parse_capture(path: &Path, file_bytes: u64) -> Result<CaptureMetrics, ParseError> {
    let file = File::open(path).map_err(|_| ParseError::InvalidCapture)?;
    let mut reader =
        create_reader(PARSER_BUFFER_BYTES, file).map_err(|_| ParseError::InvalidCapture)?;
    let mut format = None;
    let mut block_count: u64 = 0;
    let mut packet_count: u64 = 0;
    let mut captured_bytes: u64 = 0;
    let mut original_bytes: u64 = 0;
    let mut truncated_packets: u64 = 0;
    let mut linktypes: HashMap<i32, u64> = HashMap::new();
    let mut interfaces = Vec::new();
    let mut acc = Acc::default();
    loop {
        let (offset, block) = match reader.next() {
            Ok(b) => b,
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().map_err(|_| ParseError::InvalidCapture)?;
                continue;
            }
            Err(_) => return Err(ParseError::InvalidCapture),
        };
        block_count += 1;
        if block_count > MAX_BLOCKS {
            return Err(ParseError::LimitExceeded("block_count"));
        }
        let mut packet: Option<(&[u8], i32, u64, u64)> = None;
        match block {
            PcapBlockOwned::LegacyHeader(h) => {
                format = Some("pcap");
                interfaces = vec![h.network.0];
            }
            PcapBlockOwned::Legacy(p) => {
                format = Some("pcap");
                let lt = *interfaces.first().ok_or(ParseError::InvalidCapture)?;
                packet = Some((p.data, lt, p.caplen as u64, p.origlen as u64));
            }
            PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                format = Some("pcapng");
                interfaces.clear();
            }
            PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                interfaces.push(idb.linktype.0);
            }
            PcapBlockOwned::NG(Block::EnhancedPacket(p)) => {
                let lt = *interfaces
                    .get(p.if_id as usize)
                    .ok_or(ParseError::InvalidCapture)?;
                packet = Some((p.data, lt, p.caplen as u64, p.origlen as u64));
            }
            PcapBlockOwned::NG(Block::SimplePacket(p)) => {
                let lt = *interfaces.first().ok_or(ParseError::InvalidCapture)?;
                packet = Some((p.data, lt, p.data.len() as u64, p.origlen as u64));
            }
            PcapBlockOwned::NG(_) => {}
        }
        if let Some((data, lt, caplen, origlen)) = packet {
            packet_count += 1;
            if packet_count > MAX_PACKETS {
                return Err(ParseError::LimitExceeded("packet_count"));
            }
            if caplen > MAX_PACKET_BYTES || origlen > MAX_PACKET_BYTES {
                return Err(ParseError::InvalidCapture);
            }
            captured_bytes = captured_bytes
                .checked_add(caplen)
                .ok_or(ParseError::LimitExceeded("captured_bytes"))?;
            *acc.packet_sizes.entry(caplen).or_default() += 1;
            original_bytes = original_bytes
                .checked_add(origlen)
                .ok_or(ParseError::LimitExceeded("original_bytes"))?;
            if caplen != origlen {
                truncated_packets += 1;
            }
            *linktypes.entry(lt).or_default() += 1;
            if matches!(lt, 1 | 113) {
                analyze_packet(data, lt, caplen != origlen, &mut acc);
            } else {
                acc.unparsed += 1;
            }
        }
        reader.consume(offset);
    }
    let format = format.ok_or(ParseError::InvalidCapture)?;
    let unsupported_linktypes = linktypes
        .keys()
        .copied()
        .filter(|v| !matches!(v, 1 | 113))
        .collect();
    let linktypes = linktypes
        .into_iter()
        .map(|(value, packets)| LinktypeMetric {
            value,
            packets,
            packet_metrics_supported: matches!(value, 1 | 113),
        })
        .collect();
    let aggregate = AggregateState {
        src_ips: acc.src_ips.clone(),
        dst_ips: acc.dst_ips.clone(),
        talkers: acc.talkers.clone(),
        destinations: acc.destinations.clone(),
        src_ports: acc.src_ports.clone(),
        dst_ports: acc.dst_ports.clone(),
        packet_sizes: acc.packet_sizes.clone(),
        protocols: acc.protocols.clone(),
        threats: acc.threats.clone(),
        dns: acc.dns.clone(),
        parsed: acc.parsed,
        unparsed: acc.unparsed,
        truncated: acc.truncated,
        dns_parsed: acc.dns_parsed,
        dns_malformed: acc.dns_malformed,
        dns_truncated: acc.dns_truncated,
        dns_compressed: acc.dns_compressed,
        dns_tcp: acc.dns_tcp,
    };
    Ok(CaptureMetrics {
        contract_version: "pcap-doctor.metrics.v2",
        analysis: "lax_protocol_summary",
        format,
        file_bytes,
        block_count,
        packet_count,
        captured_bytes,
        original_bytes,
        truncated_packets,
        linktypes,
        unsupported_formats: Vec::new(),
        unsupported_linktypes,
        summary: ProtocolSummary {
            version: "pcap-doctor.protocol-summary.v1",
            parsed_packets: acc.parsed,
            unparsed_packets: acc.unparsed,
            truncated_packets,
            packet_count,
            byte_count: captured_bytes,
            protocol_counts: acc.protocols,
            source_ports: ports(acc.src_ports),
            destination_ports: ports(acc.dst_ports),
            unique_source_ips: acc.src_ips.len() as u64,
            unique_destination_ips: acc.dst_ips.len() as u64,
            top_talkers: ips(acc.talkers.clone()),
            top_destinations: ips(acc.destinations),
            packet_size_stats: acc.packet_sizes,
        },
        threat_summary: acc.threats.entries(),
        dns: DnsSummary {
            version: "pcap-doctor.dns.v1",
            supported_transport: "UDP",
            parsed_queries: acc.dns_parsed,
            unique_queries: acc.dns.len() as u64,
            malformed_packets: acc.dns_malformed,
            truncated_packets: acc.dns_truncated,
            compressed_packets: acc.dns_compressed,
            tcp_unsupported_packets: acc.dns_tcp,
            cardinality_capped: acc.dns.len() >= MAX_DNS_ENTRIES,
        },
        dns_records: dns_records(acc.dns),
        aggregate,
    })
}

pub fn aggregate_captures(captures: Vec<CaptureMetrics>) -> Result<CaptureMetrics, ParseError> {
    let mut captures = captures.into_iter();
    let mut result = captures.next().ok_or(ParseError::InvalidCapture)?;
    for capture in captures {
        result.file_bytes = result.file_bytes.saturating_add(capture.file_bytes);
        result.block_count = result.block_count.saturating_add(capture.block_count);
        result.packet_count = result.packet_count.saturating_add(capture.packet_count);
        result.captured_bytes = result.captured_bytes.saturating_add(capture.captured_bytes);
        result.original_bytes = result.original_bytes.saturating_add(capture.original_bytes);
        result.truncated_packets = result
            .truncated_packets
            .saturating_add(capture.truncated_packets);
        for item in capture.linktypes {
            if let Some(existing) = result.linktypes.iter_mut().find(|x| x.value == item.value) {
                existing.packets = existing.packets.saturating_add(item.packets);
            } else {
                result.linktypes.push(item);
            }
        }
        merge_state(&mut result.aggregate, capture.aggregate);
    }
    let a = result.aggregate.clone();
    result.summary.packet_count = result.packet_count;
    result.summary.parsed_packets = a.parsed;
    result.summary.unparsed_packets = a.unparsed;
    result.summary.truncated_packets = result.truncated_packets;
    result.summary.byte_count = result.captured_bytes;
    result.summary.protocol_counts = a.protocols.clone();
    result.summary.source_ports = ports(a.src_ports.clone());
    result.summary.destination_ports = ports(a.dst_ports.clone());
    result.summary.unique_source_ips = a.src_ips.len() as u64;
    result.summary.unique_destination_ips = a.dst_ips.len() as u64;
    result.summary.top_talkers = ips(a.talkers.clone());
    result.summary.top_destinations = ips(a.destinations.clone());
    result.summary.packet_size_stats = a.packet_sizes.clone();
    result.threat_summary = a.threats.entries();
    result.dns = DnsSummary {
        version: "pcap-doctor.dns.v1",
        supported_transport: "UDP",
        parsed_queries: a.dns_parsed,
        unique_queries: a.dns.len() as u64,
        malformed_packets: a.dns_malformed,
        truncated_packets: a.dns_truncated,
        compressed_packets: a.dns_compressed,
        tcp_unsupported_packets: a.dns_tcp,
        cardinality_capped: a.dns.len() >= MAX_DNS_ENTRIES,
    };
    result.dns_records = dns_records(a.dns.clone());
    Ok(result)
}

fn merge_state(left: &mut AggregateState, right: AggregateState) {
    left.src_ips.extend(right.src_ips);
    left.dst_ips.extend(right.dst_ips);
    for (key, value) in right.talkers {
        *left.talkers.entry(key).or_default() += value;
    }
    for (key, value) in right.destinations {
        *left.destinations.entry(key).or_default() += value;
    }
    for (key, value) in right.src_ports {
        *left.src_ports.entry(key).or_default() += value;
    }
    for (key, value) in right.dst_ports {
        *left.dst_ports.entry(key).or_default() += value;
    }
    for (key, value) in right.packet_sizes {
        *left.packet_sizes.entry(key).or_default() += value;
    }
    left.protocols.tcp += right.protocols.tcp;
    left.protocols.udp += right.protocols.udp;
    left.protocols.icmp += right.protocols.icmp;
    for (key, value) in right.threats.counts {
        *left.threats.counts.entry(key).or_default() += value;
    }
    for (key, value) in right.dns {
        *left.dns.entry(key).or_default() += value;
    }
    left.parsed += right.parsed;
    left.unparsed += right.unparsed;
    left.truncated += right.truncated;
    left.dns_parsed += right.dns_parsed;
    left.dns_malformed += right.dns_malformed;
    left.dns_truncated += right.dns_truncated;
    left.dns_compressed += right.dns_compressed;
    left.dns_tcp += right.dns_tcp;
}
fn evaluate_threats(
    counts: &mut ThreatCounts,
    src: Option<u16>,
    dst: Option<u16>,
    protocol: &str,
    payload: &[u8],
) {
    let (Some(src), Some(dst)) = (src, dst) else {
        return;
    };
    const PORTS: &[(u16, &str)] = &[
        (21, "suspicious_port_21"),
        (23, "suspicious_port_23"),
        (6667, "suspicious_port_6667"),
        (445, "suspicious_port_445"),
        (139, "suspicious_port_139"),
        (137, "suspicious_port_137"),
        (135, "suspicious_port_135"),
        (3389, "suspicious_port_3389"),
        (161, "suspicious_port_161"),
        (389, "suspicious_port_389"),
        (636, "suspicious_port_636"),
        (3268, "suspicious_port_3268"),
        (3269, "suspicious_port_3269"),
        (111, "suspicious_port_111"),
        (2049, "suspicious_port_2049"),
        (1433, "suspicious_port_1433"),
        (3306, "suspicious_port_3306"),
        (5432, "suspicious_port_5432"),
        (6379, "suspicious_port_6379"),
        (27017, "suspicious_port_27017"),
    ];
    if src == 0 || dst == 0 {
        counts.add("invalid_port_0");
    }
    for &(port, id) in PORTS {
        if src == port || dst == port {
            counts.add(id);
        }
    }
    for &(id, port) in &[
        ("ssdp_amp", 1900),
        ("snmp_amp", 161),
        ("mdns_amp", 5353),
        ("memcached_amp", 11211),
        ("chargen_abuse", 19),
    ] {
        if src == port {
            counts.add(id);
        }
    }
    if protocol == "UDP" && src == 389 {
        counts.add("cldap_amp");
    }
    if src == 123 && dst != 123 {
        counts.add("ntp_amp_src");
    }
    if dst == 123 && src <= 1023 && src != 123 {
        counts.add("ntp_abuse_low_port");
    }
    if dst == 19 {
        counts.add("chargen_dst_abuse");
    }
    for &(id, destinations) in &[
        ("web_low_source", &[80, 443, 8080, 8443, 8000, 8008][..]),
        ("ms_rpc_smb_low", &[135, 139, 445][..]),
        ("netbios_low", &[137, 138][..]),
        ("unix_nfs_low", &[111, 2049][..]),
        ("remote_infra_low", &[22, 23, 3389, 21][..]),
        ("reflection_vectors_low", &[1900, 5353, 389][..]),
    ] {
        if src > 0 && src <= 1023 && destinations.contains(&dst) {
            counts.add(id);
        }
    }
    if src <= 1023 && src != 53 && dst == 53 {
        counts.add("dns_low_to_low");
    }
    let bounded = &payload[..payload.len().min(MAX_SIGNATURE_SCAN_BYTES)];
    const SIGNATURES: &[(&str, &[&[u8]])] = &[
        (
            "sig-scanners",
            &[b"sqlmap", b"nikto", b"masscan", b"nmap", b"brup"],
        ),
        (
            "sig-webshells",
            &[b"eval(", b"base64_decode(", b"system(", b"shell_exec("],
        ),
        ("sig-auth", &[b"authorization:"]),
        ("sig-xss", &[b"alert(", b"script>"]),
        ("sig-rce", &[b"/bin/sh", b"/bin/bash", b"cmd.exe"]),
    ];
    for &(id, needles) in SIGNATURES {
        if needles
            .iter()
            .any(|needle| ascii_contains_ci(bounded, needle))
        {
            counts.add(id);
        }
    }
}

fn ascii_contains_ci(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle)
            .all(|(a, b)| a.to_ascii_lowercase() == b.to_ascii_lowercase())
    })
}

fn analyze_packet(data: &[u8], linktype: i32, externally_truncated: bool, a: &mut Acc) {
    let packet = if linktype == 1 {
        match LaxPacketHeaders::from_ethernet(data) {
            Ok(packet) => packet,
            Err(_) => {
                a.unparsed += 1;
                return;
            }
        }
    } else {
        match LaxPacketHeaders::from_linux_sll(data) {
            Ok(packet) => packet,
            Err(_) => {
                a.unparsed += 1;
                return;
            }
        }
    };
    let incomplete = packet.stop_err.is_some();
    if incomplete {
        a.truncated += 1;
    }
    let Some(NetHeaders::Ipv4(ip, _)) = packet.net else {
        a.unparsed += 1;
        return;
    };
    let src = ip.source;
    let dst = ip.destination;
    let Some(transport) = packet.transport else {
        a.unparsed += 1;
        return;
    };
    a.src_ips.insert(src.into());
    a.dst_ips.insert(dst.into());
    *a.talkers.entry(src.into()).or_default() += 1;
    *a.destinations.entry(dst.into()).or_default() += 1;
    let (src_port, dst_port, protocol) = match transport {
        TransportHeader::Tcp(t) => {
            a.protocols.tcp += 1;
            *a.src_ports.entry(t.source_port).or_default() += 1;
            *a.dst_ports.entry(t.destination_port).or_default() += 1;
            a.parsed += 1;
            (Some(t.source_port), Some(t.destination_port), "TCP")
        }
        TransportHeader::Udp(u) => {
            a.protocols.udp += 1;
            *a.src_ports.entry(u.source_port).or_default() += 1;
            *a.dst_ports.entry(u.destination_port).or_default() += 1;
            a.parsed += 1;
            (Some(u.source_port), Some(u.destination_port), "UDP")
        }
        TransportHeader::Icmpv4(_) => {
            a.protocols.icmp += 1;
            a.parsed += 1;
            (None, None, "ICMP")
        }
        _ => {
            a.unparsed += 1;
            return;
        }
    };
    let payload = match packet.payload {
        etherparse::LaxPayloadSlice::Empty => &[][..],
        etherparse::LaxPayloadSlice::Ether(p) => p.payload,
        etherparse::LaxPayloadSlice::Ip(p) => p.payload,
        etherparse::LaxPayloadSlice::Udp { payload, .. } => payload,
        etherparse::LaxPayloadSlice::Tcp { payload, .. } => payload,
        etherparse::LaxPayloadSlice::LinuxSll(p) => p.payload,
        etherparse::LaxPayloadSlice::MacsecModified { payload, .. } => payload,
        _ => &[],
    };
    evaluate_threats(&mut a.threats, src_port, dst_port, protocol, payload);
    if protocol == "TCP" && (src_port == Some(53) || dst_port == Some(53)) {
        a.dns_tcp += 1;
    } else if protocol == "UDP" && (src_port == Some(53) || dst_port == Some(53)) {
        if externally_truncated {
            a.dns_truncated += 1;
        }
        match parse_dns_query(if externally_truncated { &[] } else { payload }) {
            DnsParseOutcome::Query {
                transaction_id,
                name,
                qtype,
            } => {
                a.dns_parsed += 1;
                if a.dns
                    .contains_key(&(transaction_id, name.clone(), qtype.clone()))
                    || a.dns.len() < MAX_DNS_ENTRIES
                {
                    *a.dns.entry((transaction_id, name, qtype)).or_default() += 1;
                }
            }
            DnsParseOutcome::Compressed => a.dns_compressed += 1,
            DnsParseOutcome::Malformed => a.dns_malformed += 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum DnsParseOutcome {
    Query {
        transaction_id: u16,
        name: String,
        qtype: String,
    },
    Compressed,
    Malformed,
}

fn parse_dns_query(data: &[u8]) -> DnsParseOutcome {
    if data.len() < 12 {
        return DnsParseOutcome::Malformed;
    }
    if data[2] & 0x80 != 0 || u16::from_be_bytes([data[4], data[5]]) == 0 {
        return DnsParseOutcome::Malformed;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        let Some(&len) = data.get(pos) else {
            return DnsParseOutcome::Malformed;
        };
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xc0 == 0xc0 {
            return DnsParseOutcome::Compressed;
        }
        if len > 63 {
            return DnsParseOutcome::Malformed;
        }
        pos += 1;
        let end = pos.saturating_add(len as usize);
        let Some(label) = data.get(pos..end) else {
            return DnsParseOutcome::Malformed;
        };
        if label
            .iter()
            .any(|b| !b.is_ascii_alphanumeric() && !matches!(b, b'-' | b'_'))
        {
            return DnsParseOutcome::Malformed;
        }
        labels.push(std::str::from_utf8(label).ok().unwrap_or_default());
        pos = end;
        if labels.iter().map(|x| x.len() + 1).sum::<usize>() > 254 {
            return DnsParseOutcome::Malformed;
        }
    }
    if labels.is_empty() || data.get(pos..pos + 4).is_none() {
        return DnsParseOutcome::Malformed;
    }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    let qtype = match qtype {
        1 => "A".into(),
        28 => "AAAA".into(),
        n => format!("TYPE{n}"),
    };
    DnsParseOutcome::Query {
        transaction_id: u16::from_be_bytes([data[0], data[1]]),
        name: labels.join("."),
        qtype,
    }
}

fn dns_records(m: HashMap<(u16, String, String), u64>) -> Vec<DnsParityEntry> {
    let mut entries: Vec<_> = m
        .into_iter()
        .map(
            |((transaction_id, query_name, query_type), count)| DnsParityEntry {
                transaction_id,
                query_name,
                query_type,
                count,
            },
        )
        .collect();
    entries.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then(a.query_name.cmp(&b.query_name))
            .then(a.query_type.cmp(&b.query_type))
            .then(a.transaction_id.cmp(&b.transaction_id))
    });
    entries
}
pub(crate) fn legacy_dns_entries(records: &[DnsParityEntry]) -> Vec<DnsEntry> {
    records
        .iter()
        .map(|record| DnsEntry {
            name: record.query_name.clone(),
            qtype: record.query_type.clone(),
            count: record.count,
        })
        .collect()
}
fn ports(mut m: HashMap<u16, u64>) -> Vec<PortMetric> {
    let mut v: Vec<_> = m
        .drain()
        .map(|(port, packets)| PortMetric { port, packets })
        .collect();
    v.sort_by(|a, b| b.packets.cmp(&a.packets).then(a.port.cmp(&b.port)));
    v.truncate(TOP_N);
    v
}
fn ips(m: HashMap<Ipv4Addr, u64>) -> Vec<DistributionMetric> {
    let mut v: Vec<_> = m
        .into_iter()
        .map(|(ip, packets)| DistributionMetric {
            value: ip.to_string(),
            packets,
        })
        .collect();
    v.sort_by(|a, b| b.packets.cmp(&a.packets).then(a.value.cmp(&b.value)));
    v.truncate(TOP_N);
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };
    #[test]
    fn synthetic_pcap_is_parsed() {
        let mut b = pcap_header(1);
        b.extend_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4]);
        let p = temp_path();
        fs::write(&p, &b).unwrap();
        let m = parse_capture(&p, b.len() as u64).unwrap();
        fs::remove_file(p).unwrap();
        assert_eq!((m.format, m.packet_count, m.captured_bytes), ("pcap", 1, 4));
        assert_eq!(m.summary.unparsed_packets, 1);
        assert_eq!(m.summary.packet_size_stats.get(&4), Some(&1));
    }
    #[test]
    fn synthetic_ethernet_protocols_are_summarized() {
        use etherparse::PacketBuilder;
        let mut bytes = pcap_header(1);
        let mut frames = Vec::new();
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 20)
            .tcp(1234, 80, 1, 10)
            .write(&mut frame, &[1, 2, 3])
            .unwrap();
        frames.push(frame);
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 3], 20)
            .udp(5555, 53)
            .write(&mut frame, &[1, 2, 3])
            .unwrap();
        frames.push(frame);
        let mut frame = Vec::new();
        PacketBuilder::ethernet2([0, 1, 2, 3, 4, 5], [6, 7, 8, 9, 10, 11])
            .ipv4([10, 0, 0, 4], [10, 0, 0, 2], 20)
            .icmpv4_echo_request(1, 1)
            .write(&mut frame, &[1, 2, 3])
            .unwrap();
        frames.push(frame);
        for frame in frames {
            let n = frame.len() as u32;
            bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]);
            bytes.extend_from_slice(&n.to_le_bytes());
            bytes.extend_from_slice(&n.to_le_bytes());
            bytes.extend_from_slice(&frame);
        }
        let p = temp_path();
        fs::write(&p, &bytes).unwrap();
        let m = parse_capture(&p, bytes.len() as u64).unwrap();
        fs::remove_file(p).unwrap();
        assert_eq!(m.summary.parsed_packets, 3);
        assert_eq!(m.summary.protocol_counts.tcp, 1);
        assert_eq!(m.summary.protocol_counts.udp, 1);
        assert_eq!(m.summary.protocol_counts.icmp, 1);
        assert_eq!(m.summary.unique_source_ips, 2);
        assert_eq!(m.summary.destination_ports[0].port, 53);
    }
    #[test]
    fn malformed_frame_is_counted_without_failing_capture() {
        let mut b = pcap_header(1);
        b.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4]);
        let p = temp_path();
        fs::write(&p, &b).unwrap();
        let m = parse_capture(&p, b.len() as u64).unwrap();
        fs::remove_file(p).unwrap();
        assert_eq!(m.summary.unparsed_packets, 1);
    }
    #[test]
    fn threat_heuristics_cover_ports_traffic_and_all_signatures_without_payload() {
        let mut c = ThreatCounts::default();
        evaluate_threats(
            &mut c,
            Some(21),
            Some(40000),
            "TCP",
            b"SQLMAP eval( Authorization: secret alert( /bin/sh",
        );
        evaluate_threats(&mut c, Some(0), Some(53), "UDP", b"nmap");
        evaluate_threats(&mut c, Some(1900), Some(50000), "UDP", b"nikto");
        evaluate_threats(&mut c, Some(161), Some(50000), "UDP", b"masscan");
        evaluate_threats(&mut c, Some(5353), Some(50000), "UDP", b"brup");
        evaluate_threats(&mut c, Some(11211), Some(50000), "UDP", b"base64_decode(");
        evaluate_threats(&mut c, Some(389), Some(50000), "UDP", b"script>");
        evaluate_threats(&mut c, Some(123), Some(50000), "UDP", b"cmd.exe");
        evaluate_threats(&mut c, Some(100), Some(80), "TCP", &[]);
        evaluate_threats(&mut c, Some(100), Some(135), "TCP", &[]);
        evaluate_threats(&mut c, Some(100), Some(137), "TCP", &[]);
        evaluate_threats(&mut c, Some(100), Some(111), "TCP", &[]);
        evaluate_threats(&mut c, Some(100), Some(22), "TCP", &[]);
        evaluate_threats(&mut c, Some(100), Some(1900), "TCP", &[]);
        evaluate_threats(&mut c, Some(100), Some(123), "TCP", &[]);
        evaluate_threats(&mut c, Some(100), Some(19), "TCP", &[]);
        let entries = c.entries();
        for id in [
            "suspicious_port_21",
            "invalid_port_0",
            "ssdp_amp",
            "snmp_amp",
            "mdns_amp",
            "memcached_amp",
            "cldap_amp",
            "ntp_amp_src",
            "ntp_abuse_low_port",
            "chargen_dst_abuse",
            "web_low_source",
            "ms_rpc_smb_low",
            "netbios_low",
            "unix_nfs_low",
            "remote_infra_low",
            "reflection_vectors_low",
            "dns_low_to_low",
            "sig-scanners",
            "sig-webshells",
            "sig-auth",
            "sig-xss",
            "sig-rce",
        ] {
            assert!(
                entries.iter().any(|entry| entry.rule_id == id),
                "missing {id}"
            );
        }
        let json = serde_json::to_string(&entries).unwrap();
        assert!(!json.contains("SQLMAP") && !json.contains("secret"));
    }
    fn pcap_header(n: u32) -> Vec<u8> {
        let mut h = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0,
        ];
        h.extend_from_slice(&n.to_le_bytes());
        h
    }
    #[test]
    fn dns_query_parser_aggregates_a_and_aaaa_and_labels_unsupported_forms() {
        let a = dns_query(b"example.com", 1);
        let aaaa = dns_query(b"example.com", 28);
        assert_eq!(
            parse_dns_query(&a),
            DnsParseOutcome::Query {
                transaction_id: 1,
                name: "example.com".into(),
                qtype: "A".into()
            }
        );
        assert_eq!(
            parse_dns_query(&aaaa),
            DnsParseOutcome::Query {
                transaction_id: 1,
                name: "example.com".into(),
                qtype: "AAAA".into()
            }
        );
        let mut compressed = a.clone();
        compressed[12] = 0xc0;
        assert_eq!(parse_dns_query(&compressed), DnsParseOutcome::Compressed);
        assert_eq!(parse_dns_query(&a[..15]), DnsParseOutcome::Malformed);
    }
    fn dns_query(name: &[u8], qtype: u16) -> Vec<u8> {
        let mut out = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split(|b| *b == b'.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label);
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out
    }
    fn temp_path() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "pcap-doctor-test-{}.pcap",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
}
