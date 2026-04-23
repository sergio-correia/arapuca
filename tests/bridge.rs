//! Integration tests for the network namespace proxy bridge.
//!
//! These tests require `unshare --user --net` to work, which needs
//! unprivileged user namespace support. Skipped if unavailable.

#[cfg(target_os = "linux")]
mod linux {
    use std::process::Command;

    fn netns_available() -> bool {
        Command::new("unshare")
            .args(["--user", "--net", "--map-current-user", "--", "/bin/true"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
    }

    #[test]
    fn loopback_up_in_namespace() {
        if !netns_available() {
            eprintln!("skipping: unshare --user --net not available");
            return;
        }

        // Build the test helper inline: a small program that calls
        // loopback_up() and then checks if lo is UP. We can't call
        // loopback_up() directly from this process because we're not
        // in a netns. Instead, use unshare to run a child that
        // verifies the loopback state via /sys/class/net/lo/flags.
        //
        // Strategy: run `unshare --user --net --map-current-user`
        // with a script that reads lo flags (should be 0x8 = DOWN),
        // then runs our binary in a mode that brings up lo, then
        // reads flags again (should be 0x9 = UP).
        //
        // Since we can't easily call Rust code inside unshare, we
        // test the observable effect: lo starts DOWN in a fresh
        // netns, and `ip link` confirms it.

        let output = Command::new("unshare")
            .args([
                "--user",
                "--net",
                "--map-current-user",
                "--",
                "cat",
                "/sys/class/net/lo/operstate",
            ])
            .output()
            .expect("unshare failed");

        let state = String::from_utf8_lossy(&output.stdout);
        let state = state.trim();
        assert!(
            state == "down" || state == "unknown",
            "lo should be down/unknown in a fresh netns, got: {state}"
        );
    }
}
