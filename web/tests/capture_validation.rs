use pcap_doctor_web::capture::{detect_format, CaptureFormat, CaptureValidationError};

#[test]
fn detects_all_supported_capture_magic_values() {
    assert_eq!(detect_format(&[0xd4, 0xc3, 0xb2, 0xa1]), Ok(CaptureFormat::Pcap));
    assert_eq!(detect_format(&[0xa1, 0xb2, 0xc3, 0xd4]), Ok(CaptureFormat::Pcap));
    assert_eq!(detect_format(&[0x4d, 0x3c, 0xb2, 0xa1]), Ok(CaptureFormat::Pcap));
    assert_eq!(detect_format(&[0xa1, 0xb2, 0x3c, 0x4d]), Ok(CaptureFormat::Pcap));
    assert_eq!(detect_format(&[0x0a, 0x0d, 0x0d, 0x0a]), Ok(CaptureFormat::PcapNg));
}

#[test]
fn rejects_short_and_unknown_capture_headers_without_panicking() {
    assert_eq!(detect_format(&[]), Err(CaptureValidationError::HeaderTooShort));
    assert_eq!(detect_format(&[0xd4, 0xc3, 0xb2]), Err(CaptureValidationError::HeaderTooShort));
    assert_eq!(detect_format(&[0, 1, 2, 3]), Err(CaptureValidationError::UnsupportedFormat));
}
