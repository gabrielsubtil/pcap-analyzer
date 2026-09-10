use pcap_parser::{PcapBlockOwned, PcapError, create_reader, pcapng::Block};
use serde::Serialize;
use std::{collections::BTreeSet, fs::File, path::Path};

pub const PARSER_BUFFER_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_PACKET_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_PACKETS: u64 = 1_000_000;
pub const MAX_BLOCKS: u64 = 1_000_000;

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
        .expect("slice length checked");
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
}

#[derive(Debug)]
pub enum ParseError {
    InvalidCapture,
    LimitExceeded(&'static str),
}

pub fn parse_capture(path: &Path, file_bytes: u64) -> Result<CaptureMetrics, ParseError> {
    let file = File::open(path).map_err(|_| ParseError::InvalidCapture)?;
    let mut reader =
        create_reader(PARSER_BUFFER_BYTES, file).map_err(|_| ParseError::InvalidCapture)?;
    let mut format = None;
    let mut block_count = 0;
    let mut packet_count = 0;
    let mut captured_bytes = 0;
    let mut original_bytes = 0;
    let mut truncated_packets = 0;
    let mut linktypes = BTreeSet::new();
    let mut interfaces = Vec::new();

    loop {
        let (offset, block) = match reader.next() {
            Ok(block) => block,
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
        match block {
            PcapBlockOwned::LegacyHeader(header) => {
                format = Some("pcap");
                linktypes.insert((header.network.0, 0));
            }
            PcapBlockOwned::Legacy(packet) => {
                format = Some("pcap");
                packet_count += 1;
                count_packet(
                    packet.caplen as u64,
                    packet.origlen as u64,
                    &mut captured_bytes,
                    &mut original_bytes,
                    &mut truncated_packets,
                )?;
                if packet_count > MAX_PACKETS {
                    return Err(ParseError::LimitExceeded("packet_count"));
                }
                if let Some((linktype, count)) = linktypes.iter().next().copied() {
                    linktypes.replace((linktype, count + 1));
                }
            }
            PcapBlockOwned::NG(Block::SectionHeader(_)) => {
                format = Some("pcapng");
                interfaces.clear();
            }
            PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                interfaces.push(idb.linktype.0);
                linktypes.insert((idb.linktype.0, 0));
            }
            PcapBlockOwned::NG(Block::EnhancedPacket(packet)) => {
                packet_count += 1;
                let caplen = packet.caplen as u64;
                count_packet(
                    caplen,
                    packet.origlen as u64,
                    &mut captured_bytes,
                    &mut original_bytes,
                    &mut truncated_packets,
                )?;
                if packet_count > MAX_PACKETS {
                    return Err(ParseError::LimitExceeded("packet_count"));
                }
                increment_linktype(
                    &mut linktypes,
                    interfaces
                        .get(packet.if_id as usize)
                        .copied()
                        .ok_or(ParseError::InvalidCapture)?,
                );
            }
            PcapBlockOwned::NG(Block::SimplePacket(packet)) => {
                packet_count += 1;
                let caplen = packet.data.len() as u64;
                count_packet(
                    caplen,
                    packet.origlen as u64,
                    &mut captured_bytes,
                    &mut original_bytes,
                    &mut truncated_packets,
                )?;
                if packet_count > MAX_PACKETS {
                    return Err(ParseError::LimitExceeded("packet_count"));
                }
                increment_linktype(
                    &mut linktypes,
                    interfaces
                        .first()
                        .copied()
                        .ok_or(ParseError::InvalidCapture)?,
                );
            }
            PcapBlockOwned::NG(_) => {}
        }
        reader.consume(offset);
    }
    let format = format.ok_or(ParseError::InvalidCapture)?;
    let linktypes = linktypes
        .into_iter()
        .map(|(value, packets)| LinktypeMetric {
            value,
            packets,
            packet_metrics_supported: false,
        })
        .collect();
    Ok(CaptureMetrics {
        contract_version: "pcap-doctor.metrics.v1",
        analysis: "container_metrics_only",
        format,
        file_bytes,
        block_count,
        packet_count,
        captured_bytes,
        original_bytes,
        truncated_packets,
        linktypes,
        unsupported_formats: Vec::new(),
        unsupported_linktypes: Vec::new(),
    })
}

fn increment_linktype(linktypes: &mut BTreeSet<(i32, u64)>, value: i32) {
    if let Some((_, count)) = linktypes
        .iter()
        .find(|(current, _)| *current == value)
        .copied()
    {
        linktypes.replace((value, count + 1));
    } else {
        linktypes.insert((value, 1));
    }
}

fn count_packet(
    caplen: u64,
    origlen: u64,
    captured: &mut u64,
    original: &mut u64,
    truncated: &mut u64,
) -> Result<(), ParseError> {
    if caplen > MAX_PACKET_BYTES || origlen > MAX_PACKET_BYTES {
        return Err(ParseError::LimitExceeded("packet_size"));
    }
    *captured = captured
        .checked_add(caplen)
        .ok_or(ParseError::LimitExceeded("captured_bytes"))?;
    *original = original
        .checked_add(origlen)
        .ok_or(ParseError::LimitExceeded("original_bytes"))?;
    if caplen != origlen {
        *truncated += 1;
    }
    Ok(())
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
        let mut bytes = pcap_header(1);
        bytes.extend_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 1, 2, 3, 4]);
        let path = temp_path("pcap");
        fs::write(&path, &bytes).unwrap();
        let metrics = parse_capture(&path, bytes.len() as u64).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(
            (metrics.format, metrics.packet_count, metrics.captured_bytes),
            ("pcap", 1, 4)
        );
    }

    #[test]
    fn synthetic_pcapng_is_parsed() {
        let mut bytes = vec![
            0x0a, 0x0d, 0x0d, 0x0a, 28, 0, 0, 0, 0x4d, 0x3c, 0x2b, 0x1a, 1, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 28, 0, 0, 0,
        ];
        bytes.extend_from_slice(&[
            1, 0, 0, 0, 24, 0, 0, 0, 1, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 24, 0, 0, 0,
        ]);
        bytes.extend_from_slice(&[
            6, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 1,
            2, 3, 4, 0, 0, 0, 0, 40, 0, 0, 0,
        ]);
        let path = temp_path("pcapng");
        fs::write(&path, &bytes).unwrap();
        let metrics = parse_capture(&path, bytes.len() as u64).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(
            (metrics.format, metrics.packet_count, metrics.captured_bytes),
            ("pcapng", 1, 4)
        );
    }

    #[test]
    fn oversized_frame_is_rejected_before_metrics_grow() {
        let mut bytes = pcap_header(1);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(&[0, 0, 0, 0]);
        bytes.extend_from_slice(&((MAX_PACKET_BYTES as u32) + 1).to_le_bytes());
        bytes.extend_from_slice(&((MAX_PACKET_BYTES as u32) + 1).to_le_bytes());
        let path = temp_path("oversized");
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            parse_capture(&path, bytes.len() as u64),
            Err(ParseError::InvalidCapture)
        ));
        fs::remove_file(path).unwrap();
    }

    fn pcap_header(network: u32) -> Vec<u8> {
        let mut h = vec![
            0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0,
        ];
        h.extend_from_slice(&network.to_le_bytes());
        h
    }
    fn temp_path(ext: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "pcap-doctor-test-{}.{ext}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
}
