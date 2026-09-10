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
