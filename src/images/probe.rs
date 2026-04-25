//! Auto-detect partition layout from qcow2 images.
//!
//! Uses `qemu-img dd` to extract the GPT partition table and
//! `qemu-nbd` + the NBD protocol to read filesystem superblocks.
//! Both tools are rootless (no /dev/nbd* kernel devices needed).

use std::io;
use std::path::Path;

use super::metadata::ImageMetadata;

/// Discoverable Partitions Specification root GUIDs.
const DPS_ROOT_X86_64: &str = "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709";
const DPS_ROOT_AARCH64: &str = "B921B045-1DF0-41C3-AF44-4C6F280D3FAE";

/// Linux filesystem GUID (generic).
const LINUX_FS_GUID: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";

/// Probe a qcow2 image to detect its partition layout and filesystem.
#[cfg(feature = "microvm")]
pub fn probe_image(qcow2_path: &Path) -> io::Result<ImageMetadata> {
    let gpt_bytes = qemu_img_dd(qcow2_path, 34)?;

    let mut cursor = std::io::Cursor::new(gpt_bytes);
    let disk = gpt::GptConfig::new()
        .writable(false)
        .open_from_device(&mut cursor)
        .map_err(|e| io::Error::other(format!("GPT parse: {e}")))?;

    let sector_size = disk.logical_block_size().as_u64();
    let (part_num, partition) = find_root_partition(disk.partitions())?;
    let part_offset = partition.first_lba * sector_size;

    let super_bytes = read_superblock(qcow2_path, part_offset)?;
    let fstype = detect_filesystem(&super_bytes)?;

    let mount_options = if fstype == "btrfs" {
        Some("subvol=root".into())
    } else {
        None
    };

    Ok(ImageMetadata {
        root_device: format!("/dev/vda{part_num}"),
        fstype,
        mount_options,
        init: "/sbin/init".into(),
        sha256: None,
        base_sha256: None,
    })
}

/// Read 68KB from a qcow2 image at the given byte offset using
/// qemu-nbd in socket mode (rootless) + the NBD protocol.
#[cfg(feature = "microvm")]
fn read_superblock(qcow2_path: &Path, offset: u64) -> io::Result<Vec<u8>> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::net::UnixStream;

    let sock_dir = tempfile::tempdir()?;
    let sock_path = sock_dir.path().join("nbd.sock");

    let mut nbd_proc = std::process::Command::new("qemu-nbd")
        .arg("--read-only")
        .arg("-t")
        .arg("-k")
        .arg(&sock_path)
        .arg("-f")
        .arg("qcow2")
        .arg(qcow2_path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::other(format!("qemu-nbd: {e}")))?;

    // Guard: always kill qemu-nbd, even on panic.
    struct NbdGuard<'a>(&'a mut std::process::Child);
    impl Drop for NbdGuard<'_> {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let _guard = NbdGuard(&mut nbd_proc);

    // Wait for the socket to appear.
    for _ in 0..50 {
        if sock_path.exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    if !sock_path.exists() {
        return Err(io::Error::other("qemu-nbd socket did not appear"));
    }

    let stream = UnixStream::connect(&sock_path)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;

    let export = nbd::client::handshake(&stream, b"")
        .map_err(|e| io::Error::other(format!("NBD handshake: {e}")))?;
    let mut client = nbd::client::NbdClient::new(&stream, &export);

    client.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; 68 * 1024];
    client.read_exact(&mut buf)?;
    Ok(buf)
}

/// Find the root partition from the GPT partition table.
///
/// Prefers partitions with Discoverable Partitions Specification
/// root GUIDs. Falls back to the largest Linux filesystem partition.
fn find_root_partition(
    partitions: &std::collections::BTreeMap<u32, gpt::partition::Partition>,
) -> io::Result<(u32, &gpt::partition::Partition)> {
    let arch = std::env::consts::ARCH;
    let dps_root = match arch {
        "x86_64" => Some(DPS_ROOT_X86_64),
        "aarch64" => Some(DPS_ROOT_AARCH64),
        _ => None,
    };

    if let Some(dps_guid) = dps_root {
        for (&num, part) in partitions {
            let guid = format!("{}", part.part_type_guid.guid);
            if guid.eq_ignore_ascii_case(dps_guid) {
                return Ok((num, part));
            }
        }
    }

    let mut best: Option<(u32, &gpt::partition::Partition, u64)> = None;
    for (&num, part) in partitions {
        let guid = format!("{}", part.part_type_guid.guid);
        if guid.eq_ignore_ascii_case(LINUX_FS_GUID) {
            let size = part.last_lba.saturating_sub(part.first_lba);
            if best.as_ref().is_none_or(|b| size > b.2) {
                best = Some((num, part, size));
            }
        }
    }

    match best {
        Some((num, part, _)) => Ok((num, part)),
        None => {
            let mut dump = String::from("partitions found:\n");
            for (&num, part) in partitions {
                dump.push_str(&format!(
                    "  {num}: type={} size={}MB name={}\n",
                    part.part_type_guid.guid,
                    (part.last_lba.saturating_sub(part.first_lba)) * 512 / (1024 * 1024),
                    part.name,
                ));
            }
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("no root partition found in GPT\n{dump}"),
            ))
        }
    }
}

/// Detect filesystem type from superblock magic bytes.
fn detect_filesystem(data: &[u8]) -> io::Result<String> {
    if data.len() >= 0x43A && data[0x438] == 0x53 && data[0x439] == 0xEF {
        return Ok("ext4".into());
    }

    if data.len() >= 4 && &data[0..4] == b"XFSB" {
        return Ok("xfs".into());
    }

    if data.len() >= 0x10048 && &data[0x10040..0x10048] == b"_BHRfS_M" {
        return Ok("btrfs".into());
    }

    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "unrecognized filesystem (not ext4, xfs, or btrfs)",
    ))
}

/// Extract raw sectors from the start of a qcow2 via `qemu-img dd`.
#[cfg(feature = "microvm")]
fn qemu_img_dd(qcow2_path: &Path, count_sectors: usize) -> io::Result<Vec<u8>> {
    let tmp = tempfile::NamedTempFile::new()?;
    let tmp_path = tmp.path();

    let output = std::process::Command::new("qemu-img")
        .arg("dd")
        .arg(format!("if={}", qcow2_path.display()))
        .arg(format!("of={}", tmp_path.display()))
        .arg("bs=512")
        .arg(format!("count={count_sectors}"))
        .arg("-f")
        .arg("qcow2")
        .arg("-O")
        .arg("raw")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .output()?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(io::Error::other(format!("qemu-img dd failed: {stderr}")));
    }

    let data = std::fs::read(tmp_path)?;
    let expected = count_sectors * 512;
    if data.len() != expected {
        return Err(io::Error::other(format!(
            "qemu-img dd: expected {expected} bytes, got {}",
            data.len()
        )));
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_ext4() {
        let mut data = vec![0u8; 0x500];
        data[0x438] = 0x53;
        data[0x439] = 0xEF;
        assert_eq!(detect_filesystem(&data).unwrap(), "ext4");
    }

    #[test]
    fn detect_xfs() {
        let mut data = vec![0u8; 0x500];
        data[0..4].copy_from_slice(b"XFSB");
        assert_eq!(detect_filesystem(&data).unwrap(), "xfs");
    }

    #[test]
    fn detect_btrfs() {
        let mut data = vec![0u8; 0x10100];
        data[0x10040..0x10048].copy_from_slice(b"_BHRfS_M");
        assert_eq!(detect_filesystem(&data).unwrap(), "btrfs");
    }

    #[test]
    fn detect_unknown() {
        let data = vec![0u8; 0x10100];
        assert!(detect_filesystem(&data).is_err());
    }

    #[test]
    fn detect_too_short_for_btrfs() {
        let mut data = vec![0u8; 0x500];
        data[0x438] = 0x53;
        data[0x439] = 0xEF;
        assert_eq!(detect_filesystem(&data).unwrap(), "ext4");
    }
}
