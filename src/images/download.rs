//! HTTP download utilities.

use std::io;
use std::path::Path;

/// Download a file from `url` to `dest`, streaming to disk.
///
/// Uses `reqwest` (blocking) with rustls for TLS. The response body
/// is streamed directly to the file rather than buffered in memory.
#[cfg(feature = "microvm")]
pub fn fetch_to_file(url: &str, dest: &Path) -> io::Result<()> {
    log::info!("downloading {url}");

    let client = reqwest::blocking::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(30))
        .timeout(std::time::Duration::from_secs(1800))
        .build()
        .map_err(|e| io::Error::other(format!("HTTP client: {e}")))?;

    let mut response = client
        .get(url)
        .send()
        .map_err(|e| io::Error::other(format!("GET {url}: {e}")))?;

    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "GET {url}: HTTP {}",
            response.status()
        )));
    }

    let mut file = std::fs::File::create(dest)?;
    let bytes = io::copy(&mut response, &mut file)?;

    log::info!("downloaded {bytes} bytes to {}", dest.display());
    Ok(())
}
