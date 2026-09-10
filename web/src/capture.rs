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
}
#[derive(Debug)]
pub enum ParseError {
    InvalidCapture,
    LimitExceeded(&'static str),
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
            top_talkers: ips(acc.talkers),
            top_destinations: ips(acc.destinations),
        },
    })
}

fn analyze_packet(data: &[u8], linktype: i32, _externally_truncated: bool, a: &mut Acc) {
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
    match transport {
        TransportHeader::Tcp(t) => {
            a.protocols.tcp += 1;
            *a.src_ports.entry(t.source_port).or_default() += 1;
            *a.dst_ports.entry(t.destination_port).or_default() += 1;
            a.parsed += 1;
        }
        TransportHeader::Udp(u) => {
            a.protocols.udp += 1;
            *a.src_ports.entry(u.source_port).or_default() += 1;
            *a.dst_ports.entry(u.destination_port).or_default() += 1;
            a.parsed += 1;
        }
        TransportHeader::Icmpv4(_) => {
            a.protocols.icmp += 1;
            a.parsed += 1;
        }
        _ => a.unparsed += 1,
    }
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
    fn pcap_header(n: u32) -> Vec<u8> {
        let mut h = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0,
        ];
        h.extend_from_slice(&n.to_le_bytes());
        h
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
