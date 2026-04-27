//! HTTP download utilities.

use std::io;
use std::path::Path;

/// Download a file from `url` to `dest`, streaming to disk.
///
/// Computes SHA256 incrementally during the download and returns the
/// hex digest. Shows a progress bar on stderr when connected to a
/// terminal.
#[cfg(feature = "microvm")]
pub fn fetch_to_file(url: &str, dest: &Path) -> io::Result<String> {
    use std::io::{Read, Write};
    use std::time::Instant;

    log::info!("downloading {url}");

    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(1800))
        .build()
        .map_err(|e| io::Error::other(format!("HTTP client: {e}")))?;

    let response = client
        .get(url)
        .send()
        .map_err(|e| io::Error::other(format!("GET {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "GET {url}: HTTP {}",
            response.status()
        )));
    }

    let total = response.content_length();
    let mut reader = response;
    let mut file = std::fs::File::create(dest)?;
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())
        .map_err(|e| io::Error::other(format!("SHA256 init: {e}")))?;

    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stderr());
    let start = Instant::now();
    let mut downloaded: u64 = 0;
    let mut last_update = Instant::now();
    let mut buf = vec![0u8; 256 * 1024];

    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        file.write_all(&buf[..n])?;
        hasher
            .update(&buf[..n])
            .map_err(|e| io::Error::other(format!("SHA256 update: {e}")))?;
        downloaded += n as u64;

        if is_tty && last_update.elapsed().as_millis() >= 100 {
            print_progress(downloaded, total, start.elapsed());
            last_update = Instant::now();
        }
    }

    if is_tty {
        print_progress(downloaded, total, start.elapsed());
        eprintln!();
    }

    let digest = hasher
        .finish()
        .map_err(|e| io::Error::other(format!("SHA256 finish: {e}")))?;
    let hex = hex_encode(&digest);

    log::info!(
        "downloaded {downloaded} bytes to {} (sha256:{hex})",
        dest.display()
    );
    Ok(hex)
}

/// Fetch the text content of a URL (for CHECKSUM files, directory listings).
#[cfg(feature = "microvm")]
pub fn fetch_text(url: &str, max_bytes: usize) -> io::Result<String> {
    use std::io::Read;

    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| io::Error::other(format!("HTTP client: {e}")))?;

    let response = client
        .get(url)
        .send()
        .map_err(|e| io::Error::other(format!("GET {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "GET {url}: HTTP {}",
            response.status()
        )));
    }

    let mut body = String::new();
    response
        .take(max_bytes as u64)
        .read_to_string(&mut body)
        .map_err(|e| io::Error::other(format!("reading {url}: {e}")))?;

    Ok(body)
}

/// Parse a Fedora CHECKSUM file and extract the SHA256 digest for the
/// given filename. Skips PGP armor, comments, and empty lines.
#[cfg(feature = "microvm")]
pub fn parse_checksum(body: &str, filename: &str) -> Option<String> {
    let expected_prefix = format!("SHA256 ({filename}) = ");

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("-----")
            || trimmed.starts_with('#')
            || trimmed.starts_with("Hash:")
        {
            continue;
        }
        if let Some(hex) = trimmed.strip_prefix(&expected_prefix) {
            let hex = hex.trim();
            if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Some(hex.to_lowercase());
            }
        }
    }
    None
}

/// Compute SHA256 of a file on disk (for opt-in cache verification).
#[cfg(feature = "microvm")]
pub fn sha256_file(path: &Path) -> io::Result<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)?;
    let mut hasher = openssl::hash::Hasher::new(openssl::hash::MessageDigest::sha256())
        .map_err(|e| io::Error::other(format!("SHA256 init: {e}")))?;

    let mut buf = vec![0u8; 256 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher
            .update(&buf[..n])
            .map_err(|e| io::Error::other(format!("SHA256 update: {e}")))?;
    }

    let digest = hasher
        .finish()
        .map_err(|e| io::Error::other(format!("SHA256 finish: {e}")))?;
    Ok(hex_encode(&digest))
}

/// Encode bytes as lowercase hex.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// Print a progress line to stderr, overwriting the current line.
#[cfg(feature = "microvm")]
fn print_progress(downloaded: u64, total: Option<u64>, elapsed: std::time::Duration) {
    use std::io::Write;

    let dl_mib = downloaded as f64 / (1024.0 * 1024.0);
    let secs = elapsed.as_secs_f64().max(0.01);
    let speed = dl_mib / secs;

    match total {
        Some(t) if t > 0 => {
            let pct = (downloaded as f64 / t as f64 * 100.0).min(100.0);
            let total_mib = t as f64 / (1024.0 * 1024.0);
            eprint!(
                "\r\x1b[2K  {pct:5.1}%  {dl_mib:7.1} MiB / {total_mib:.1} MiB  {speed:.1} MiB/s"
            );
        }
        _ => {
            eprint!("\r\x1b[2K  {dl_mib:7.1} MiB  {speed:.1} MiB/s");
        }
    }

    let _ = std::io::stderr().flush();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_bytes() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x0a, 0xab]), "00ff0aab");
    }

    #[cfg(feature = "microvm")]
    mod checksum {
        use super::super::parse_checksum;

        const SAMPLE_CHECKSUM: &str = "\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

# Fedora-Cloud-Base-Generic.x86_64-42-1.1.qcow2: 532217856 bytes
SHA256 (Fedora-Cloud-Base-Generic.x86_64-42-1.1.qcow2) = e401a4db2e5e04d1967b6729774faa96da629bcf3ba90b67d8d9cce9906bec0f
# Fedora-Cloud-Base-AmazonEC2-42-1.1.x86_64.raw.xz: 541542268 bytes
SHA256 (Fedora-Cloud-Base-AmazonEC2-42-1.1.x86_64.raw.xz) = a3bbb6aeae4a85658b21ac2b4e5511eb9f6f2dc53383b054855f9264dbe63585
-----BEGIN PGP SIGNATURE-----
iQIzBAEBCAAdFiEEsPSVBFj2nhFQxsXtyKxJFhBe+UQFAmf4+/IACgkQ
-----END PGP SIGNATURE-----";

        #[test]
        fn parse_valid() {
            let hash = parse_checksum(
                SAMPLE_CHECKSUM,
                "Fedora-Cloud-Base-Generic.x86_64-42-1.1.qcow2",
            );
            assert_eq!(
                hash.as_deref(),
                Some("e401a4db2e5e04d1967b6729774faa96da629bcf3ba90b67d8d9cce9906bec0f")
            );
        }

        #[test]
        fn parse_filename_mismatch() {
            let hash = parse_checksum(SAMPLE_CHECKSUM, "nonexistent.qcow2");
            assert!(hash.is_none());
        }

        #[test]
        fn parse_amazon_entry() {
            let hash = parse_checksum(
                SAMPLE_CHECKSUM,
                "Fedora-Cloud-Base-AmazonEC2-42-1.1.x86_64.raw.xz",
            );
            assert_eq!(
                hash.as_deref(),
                Some("a3bbb6aeae4a85658b21ac2b4e5511eb9f6f2dc53383b054855f9264dbe63585")
            );
        }

        #[test]
        fn parse_empty_body() {
            assert!(parse_checksum("", "file.qcow2").is_none());
        }

        #[test]
        fn parse_invalid_hex_length() {
            let body = "SHA256 (file.qcow2) = abcd";
            assert!(parse_checksum(body, "file.qcow2").is_none());
        }

        #[test]
        fn parse_invalid_hex_chars() {
            let body = "SHA256 (file.qcow2) = zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
            assert!(parse_checksum(body, "file.qcow2").is_none());
        }

        #[test]
        fn parse_pgp_armor_only() {
            let body = "\
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA256

-----BEGIN PGP SIGNATURE-----
base64data
-----END PGP SIGNATURE-----";
            assert!(parse_checksum(body, "file.qcow2").is_none());
        }
    }
}
