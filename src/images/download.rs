//! HTTP download utilities.

use std::io;
use std::path::Path;

/// Download a file from `url` to `dest`, streaming to disk.
///
/// Shows a progress bar on stderr when connected to a terminal.
/// Falls back to simple status lines when piped.
#[cfg(feature = "microvm")]
pub fn fetch_to_file(url: &str, dest: &Path) -> io::Result<()> {
    use std::io::{Read, Write};
    use std::time::Instant;

    log::info!("downloading {url}");

    let client = reqwest::blocking::Client::builder()
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

    log::info!("downloaded {downloaded} bytes to {}", dest.display());
    Ok(())
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
