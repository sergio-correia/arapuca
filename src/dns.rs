//! Minimal DNS wire format parser for query capture.
//!
//! Parses standard DNS query packets (RFC 1035) to extract the
//! queried domain name and type, and constructs NXDOMAIN responses.
//! Only handles the question section — no compression pointers,
//! answer/authority/additional parsing.

/// A parsed DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub id: u16,
    pub domain: String,
    pub qtype: u16,
    pub qclass: u16,
}

const HEADER_LEN: usize = 12;
const MAX_NAME_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Parse a DNS query from a UDP payload.
///
/// Returns `None` on malformed input, responses (QR=1), or labels
/// containing characters outside `[a-zA-Z0-9-_]`.
pub fn parse_query(buf: &[u8]) -> Option<DnsQuery> {
    if buf.len() < HEADER_LEN {
        return None;
    }

    let id = u16::from_be_bytes([buf[0], buf[1]]);
    let flags = u16::from_be_bytes([buf[2], buf[3]]);

    // QR bit must be 0 (query).
    if flags & 0x8000 != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([buf[4], buf[5]]);
    if qdcount == 0 {
        return None;
    }

    // Parse the first question's QNAME.
    let mut pos = HEADER_LEN;
    let mut labels: Vec<&str> = Vec::new();
    let mut name_len: usize = 0;

    loop {
        if pos >= buf.len() {
            return None;
        }

        let label_len = buf[pos] as usize;
        pos += 1;

        if label_len == 0 {
            break;
        }

        // Reject compression pointers (top 2 bits set).
        if label_len > MAX_LABEL_LEN {
            return None;
        }

        if pos + label_len > buf.len() {
            return None;
        }

        let label_bytes = &buf[pos..pos + label_len];

        // Validate label characters: only [a-zA-Z0-9-].
        // The dot separator is implicit (between labels), not in labels.
        for &b in label_bytes {
            if !b.is_ascii_alphanumeric() && b != b'-' && b != b'_' {
                return None;
            }
        }

        let label = std::str::from_utf8(label_bytes).ok()?;

        // Track total name length (labels + dots).
        if !labels.is_empty() {
            name_len += 1; // dot separator
        }
        name_len += label_len;
        if name_len > MAX_NAME_LEN {
            return None;
        }

        labels.push(label);
        pos += label_len;
    }

    // Need at least QTYPE (2) + QCLASS (2) after QNAME.
    if pos + 4 > buf.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
    let qclass = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]);

    let domain = if labels.is_empty() {
        ".".to_string() // root domain
    } else {
        labels.join(".")
    };

    Some(DnsQuery {
        id,
        domain,
        qtype,
        qclass,
    })
}

/// Build a minimal NXDOMAIN response for a DNS query.
///
/// Copies the header and question section from the original query,
/// setting QR=1 (response), AA=1 (authoritative), and RCODE=3
/// (NXDOMAIN). Answer/authority/additional counts are zeroed.
pub fn build_nxdomain(query_buf: &[u8], id: u16) -> Vec<u8> {
    if query_buf.len() < HEADER_LEN {
        return Vec::new();
    }

    // Walk past the question section to find its end.
    let mut pos = HEADER_LEN;
    loop {
        if pos >= query_buf.len() {
            return Vec::new();
        }
        let label_len = query_buf[pos] as usize;
        pos += 1;
        if label_len == 0 {
            break;
        }
        if label_len > MAX_LABEL_LEN || pos + label_len > query_buf.len() {
            return Vec::new();
        }
        pos += label_len;
    }
    // Skip QTYPE + QCLASS.
    if pos + 4 > query_buf.len() {
        return Vec::new();
    }
    pos += 4;

    let mut resp = Vec::with_capacity(pos);

    // Copy header, then patch it.
    resp.extend_from_slice(&query_buf[..HEADER_LEN]);
    // ID
    resp[0] = (id >> 8) as u8;
    resp[1] = id as u8;
    // Flags: QR=1, AA=1, RCODE=3 (NXDOMAIN).
    // Preserve the original opcode (bits 11-14) and RD (bit 8).
    let orig_flags = u16::from_be_bytes([query_buf[2], query_buf[3]]);
    let opcode = orig_flags & 0x7800; // bits 11-14
    let rd = orig_flags & 0x0100; // bit 8
    let new_flags: u16 = 0x8000 | opcode | 0x0400 | rd | 0x0003;
    resp[2] = (new_flags >> 8) as u8;
    resp[3] = new_flags as u8;
    // Force QDCOUNT=1 (we only include one question section).
    resp[4] = 0;
    resp[5] = 1;
    // Zero out ANCOUNT, NSCOUNT, ARCOUNT.
    resp[6] = 0;
    resp[7] = 0;
    resp[8] = 0;
    resp[9] = 0;
    resp[10] = 0;
    resp[11] = 0;

    // Copy question section.
    resp.extend_from_slice(&query_buf[HEADER_LEN..pos]);

    resp
}

/// Map a DNS query type number to a human-readable name.
pub fn qtype_name(qtype: u16) -> &'static str {
    match qtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        6 => "SOA",
        12 => "PTR",
        15 => "MX",
        16 => "TXT",
        28 => "AAAA",
        33 => "SRV",
        35 => "NAPTR",
        43 => "DS",
        46 => "RRSIG",
        48 => "DNSKEY",
        52 => "TLSA",
        65 => "HTTPS",
        255 => "ANY",
        _ => "OTHER",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_query(domain: &str, qtype: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        // Header: ID=0x1234, flags=0x0100 (RD=1), QDCOUNT=1
        buf.extend_from_slice(&[0x12, 0x34, 0x01, 0x00, 0x00, 0x01]);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

        // QNAME
        if domain == "." {
            buf.push(0);
        } else {
            for label in domain.split('.') {
                buf.push(label.len() as u8);
                buf.extend_from_slice(label.as_bytes());
            }
            buf.push(0);
        }

        // QTYPE + QCLASS (IN=1)
        buf.push((qtype >> 8) as u8);
        buf.push(qtype as u8);
        buf.push(0x00);
        buf.push(0x01);

        buf
    }

    #[test]
    fn parse_a_query() {
        let buf = build_query("example.com", 1);
        let q = parse_query(&buf).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.domain, "example.com");
        assert_eq!(q.qtype, 1);
        assert_eq!(q.qclass, 1);
    }

    #[test]
    fn parse_aaaa_query() {
        let buf = build_query("ipv6.example.org", 28);
        let q = parse_query(&buf).unwrap();
        assert_eq!(q.domain, "ipv6.example.org");
        assert_eq!(q.qtype, 28);
    }

    #[test]
    fn parse_mx_query() {
        let buf = build_query("mail.example.com", 15);
        let q = parse_query(&buf).unwrap();
        assert_eq!(q.domain, "mail.example.com");
        assert_eq!(q.qtype, 15);
    }

    #[test]
    fn parse_root_domain() {
        let buf = build_query(".", 2);
        let q = parse_query(&buf).unwrap();
        assert_eq!(q.domain, ".");
        assert_eq!(q.qtype, 2);
    }

    #[test]
    fn reject_truncated_header() {
        assert!(parse_query(&[0; 11]).is_none());
    }

    #[test]
    fn reject_truncated_name() {
        let mut buf = build_query("example.com", 1);
        buf.truncate(18); // cut in the middle of the name
        assert!(parse_query(&buf).is_none());
    }

    #[test]
    fn reject_truncated_qtype() {
        let mut buf = build_query("example.com", 1);
        buf.truncate(buf.len() - 2); // remove QCLASS
        assert!(parse_query(&buf).is_none());
    }

    #[test]
    fn reject_response_packet() {
        let mut buf = build_query("example.com", 1);
        buf[2] |= 0x80; // set QR=1 (response)
        assert!(parse_query(&buf).is_none());
    }

    #[test]
    fn reject_zero_qdcount() {
        let mut buf = build_query("example.com", 1);
        buf[4] = 0;
        buf[5] = 0;
        assert!(parse_query(&buf).is_none());
    }

    #[test]
    fn reject_oversized_label() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&[0x00, 0x01, 0x01, 0x00, 0x00, 0x01]);
        buf.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        buf.push(64); // label length 64 > MAX_LABEL_LEN (63)
        buf.extend_from_slice(&[b'a'; 64]);
        buf.push(0);
        buf.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        assert!(parse_query(&buf).is_none());
    }

    #[test]
    fn reject_injection_characters() {
        // Domain with quotes — would break NDJSON if not rejected.
        let mut buf = build_query("dummy", 1);
        // Overwrite the label with bytes containing a quote.
        let label_start = HEADER_LEN + 1; // after length byte
        buf[label_start] = b'"';
        assert!(parse_query(&buf).is_none());
    }

    #[test]
    fn reject_newline_in_label() {
        let mut buf = build_query("dummy", 1);
        let label_start = HEADER_LEN + 1;
        buf[label_start] = b'\n';
        assert!(parse_query(&buf).is_none());
    }

    #[test]
    fn reject_brace_in_label() {
        let mut buf = build_query("dummy", 1);
        let label_start = HEADER_LEN + 1;
        buf[label_start] = b'{';
        assert!(parse_query(&buf).is_none());
    }

    #[test]
    fn accept_hyphen_and_underscore() {
        let buf = build_query("my-host_name.example.com", 1);
        let q = parse_query(&buf).unwrap();
        assert_eq!(q.domain, "my-host_name.example.com");
    }

    #[test]
    fn max_length_name() {
        // 253 chars: 63.63.63.63 (63*4 + 3 dots = 255 > 253, so use shorter)
        // Use 4 labels of 62 chars + dots = 62*4 + 3 = 251
        let label = "a".repeat(62);
        let domain = format!("{label}.{label}.{label}.{label}");
        assert_eq!(domain.len(), 251);
        let buf = build_query(&domain, 1);
        let q = parse_query(&buf).unwrap();
        assert_eq!(q.domain, domain);
    }

    #[test]
    fn over_max_length_name() {
        let label = "a".repeat(63);
        let domain = format!("{label}.{label}.{label}.{label}");
        assert!(domain.len() > MAX_NAME_LEN);
        let buf = build_query(&domain, 1);
        assert!(parse_query(&buf).is_none());
    }

    #[test]
    fn nxdomain_response_structure() {
        let query = build_query("evil.com", 1);
        let resp = build_nxdomain(&query, 0x1234);

        assert!(resp.len() >= HEADER_LEN);
        // ID
        assert_eq!(resp[0], 0x12);
        assert_eq!(resp[1], 0x34);
        // QR=1
        assert_ne!(resp[2] & 0x80, 0);
        // AA=1
        assert_ne!(resp[2] & 0x04, 0);
        // RCODE=3 (NXDOMAIN)
        assert_eq!(resp[3] & 0x0F, 3);
        // RD preserved from query
        assert_ne!(resp[2] & 0x01, 0);
        // QDCOUNT=1
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1);
        // ANCOUNT=0
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[test]
    fn nxdomain_rejects_short_input() {
        assert!(build_nxdomain(&[0; 5], 0).is_empty());
    }

    #[test]
    fn qtype_names() {
        assert_eq!(qtype_name(1), "A");
        assert_eq!(qtype_name(28), "AAAA");
        assert_eq!(qtype_name(5), "CNAME");
        assert_eq!(qtype_name(15), "MX");
        assert_eq!(qtype_name(16), "TXT");
        assert_eq!(qtype_name(33), "SRV");
        assert_eq!(qtype_name(255), "ANY");
        assert_eq!(qtype_name(9999), "OTHER");
    }
}
