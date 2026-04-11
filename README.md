# Arapuca

Process sandbox for Linux and macOS providing kernel-enforced isolation.
On Linux: Landlock, seccomp BPF, cgroups v2, and network namespaces. On
macOS: Apple's Seatbelt (`sandbox-exec`) with deny-default profiles.
Available as a Rust library (with C FFI) and a CLI binary.

Arapuca is designed for running **untrusted code** — even a fully
compromised subprocess is contained by OS-level restrictions that cannot
be bypassed from userspace.

## Features

### Linux

- **Landlock** filesystem restrictions (ABI v1-v6) — allowlist of
  readable and writable paths
- **Seccomp BPF** syscall filtering — tiered deny list (KILL for
  ptrace/mount/namespace manipulation, EPERM for symlinks/network)
- **Cgroups v2** resource limits — memory, CPU, PIDs, OOM detection,
  usage telemetry
- **Network namespace** isolation — CLONE_NEWUSER + CLONE_NEWNET
  blocks all direct network access

### macOS

- **Seatbelt** (`sandbox-exec`) — deny-default profile with explicit
  allows for filesystem, exec, and Unix domain sockets
- **Path validation** — strict character allowlist prevents Seatbelt
  profile injection attacks
- **Memory monitor** — best-effort RSS polling (500ms) with SIGKILL
  on limit breach (no cgroups on macOS)
- **Parent-PID watchdog** — kills subprocess if parent dies (replaces
  Linux's `PR_SET_PDEATHSIG`)
- Skips `RLIMIT_AS` on Apple Silicon (causes immediate SIGKILL due
  to macOS virtual memory behavior)

### Both platforms

- **Resource limits** — RLIMIT_AS, RLIMIT_NPROC, RLIMIT_CPU,
  RLIMIT_FSIZE
- **Process lifecycle** — launch, wait, resource stats, cleanup
- **C FFI** — shared library with C header for integration from
  C/C++/Go/Python
- **Fail-closed** — if any restriction fails to apply, the process
  exits before running the target command

## Quick Start

### Binary

The simplest integration: wrap any command with `arapuca`.

```bash
# Build
cargo build --release

# Run a command with filesystem restrictions
ARAPUCA_READ_PATHS="/usr:/lib:/lib64:/bin:/etc:/dev" \
ARAPUCA_WRITE_PATHS="/tmp/workspace" \
./target/release/arapuca -- python3 agent.py

# The sandboxed process:
# - Can only read files under /usr, /lib, /bin, /etc, /dev
# - Can only write under /tmp/workspace
# - Cannot create network sockets (AF_INET/AF_INET6 blocked)
# - Cannot call ptrace, mount, or manipulate namespaces
# - Is killed if the parent process dies
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `ARAPUCA_READ_PATHS` | Colon-separated readable paths |
| `ARAPUCA_WRITE_PATHS` | Colon-separated writable paths |
| `ARAPUCA_RLIMIT_AS` | Max virtual memory in bytes |
| `ARAPUCA_RLIMIT_NPROC` | Max number of processes |
| `ARAPUCA_RLIMIT_CPU` | Max CPU time in seconds |
| `ARAPUCA_RLIMIT_FSIZE` | Max file size in bytes |

All `ARAPUCA_*` variables are stripped from the environment before
exec — the sandboxed process cannot inspect its own configuration.

### Rust Library

```rust
use arapuca::platform::{Sandbox, new};

let sandbox = new()?;

let config = arapuca::Config {
    profile: arapuca::Profile {
        read_paths: vec!["/usr".into(), "/lib".into(), "/etc".into()],
        write_paths: vec!["/tmp/workspace".into()],
        max_memory_mb: 2048,
        max_pids: 256,
        max_cpu_pct: 200, // 2 cores
        use_netns: true,
        ..Default::default()
    },
    socket_dir: "/tmp/sockets".into(),
    task_id: "task-42".into(),
    phase: "executing".into(),
    work_dir: Some("/tmp/workspace".into()),
    ..Default::default() // stdout, stderr, network_proxy_socket
};

let mut process = sandbox.launch(&config, "/usr/bin/python3", &["agent.py"], &[])?;
let status = process.wait()?;
let stats = process.resource_stats();
println!("peak memory: {} bytes", stats.memory_peak_bytes);
process.cleanup();
```

### C Library

Build the shared library and generate the header:

```bash
cargo build --release  # produces libarapuca.so (Linux) or .dylib (macOS)
make header            # generates include/arapuca.h
```

```c
#include <arapuca.h>

struct arapuca_ArapucaProfile *p = arapuca_profile_new();
arapuca_profile_add_read_path(p, "/usr");
arapuca_profile_add_read_path(p, "/lib");
arapuca_profile_add_write_path(p, "/tmp/workspace");
arapuca_profile_set_memory_mb(p, 2048);
arapuca_profile_set_netns(p, true);

if (arapuca_apply(p) != 0) {
    fprintf(stderr, "sandbox failed: %s\n", arapuca_last_error());
    exit(1);
}

arapuca_profile_free(p);
execvp("python3", argv);  // now sandboxed
```

Link with `-larapuca -ldl -lpthread`.

## Security Model

### Threat Model

The sandboxed process is **fully untrusted**. Arapuca assumes the
process may be prompt-injected, exploit vulnerabilities, or actively
attempt to escape. The sandbox limits blast radius even in the worst
case.

### Defense Layers (Linux)

| Layer | Mechanism | What it prevents |
|-------|-----------|------------------|
| Landlock | Kernel filesystem MAC | Reading/writing files outside allowlist |
| Seccomp BPF | Syscall filter | ptrace, mount, namespace escape, kernel modules |
| Network namespace | CLONE_NEWNET | All direct network access (AF_INET/AF_INET6) |
| Cgroups v2 | Resource limits | Memory exhaustion, fork bombs, CPU starvation |
| Rlimits | POSIX limits | Large file creation, process proliferation |
| Pdeathsig | PR_SET_PDEATHSIG | Orphan processes surviving parent crash |
| Setsid | Session detach | Signal propagation to host terminal |
| Env stripping | Remove ARAPUCA_* | Agent inspecting its own sandbox config |

### Defense Layers (macOS)

| Layer | Mechanism | What it prevents |
|-------|-----------|------------------|
| Seatbelt | sandbox-exec profile | Filesystem/network access outside allowlist |
| Rlimits | POSIX limits | Large file creation, process proliferation |
| Memory monitor | RSS polling (500ms) | Memory exhaustion (best-effort) |
| Parent watchdog | getppid polling (2s) | Orphan processes surviving parent crash |
| Setsid | Session detach | Signal propagation to host terminal |
| Env stripping | Remove ARAPUCA_* | Agent inspecting its own sandbox config |

### Seccomp Filter (Linux only)

Two tiers with different responses:

**Tier 1 — KILL_PROCESS** (no legitimate use): `ptrace`, `mount`,
`chroot`, `unshare`, `setns`, `clone3`, `memfd_create`, `io_uring_*`,
`bpf`, `kexec_*`, kernel module syscalls, new mount API (`fsopen`,
`fsmount`, `move_mount`, `open_tree`, `mount_setattr`).

**Tier 2 — EPERM** (may be probed by libraries): `symlink`, `link`,
`socket(AF_INET)`, `socket(AF_INET6)`, `perf_event_open`,
`prctl(PR_SET_PDEATHSIG, 0)`, `prctl(PR_SET_DUMPABLE, 1)`.

`socket(AF_UNIX)` is explicitly **allowed** — needed for IPC with the
host (JSON-RPC, LLM proxy).

### Network Model

The sandboxed process has **zero direct IP access**. All network
traffic must flow through a host-side proxy via Unix domain sockets.

```
┌─────────────────────────────────────────────────┐
│  Host process                                   │
│                                                 │
│  ┌──────────┐   ┌──────────┐                    │
│  │ JSON-RPC │   │ LLM      │                    │
│  │ control  │   │ proxy    │───► external APIs  │
│  └────┬─────┘   └────┬─────┘                    │
│       │              │                          │
│   Unix socket    Unix socket                    │
│   (control.sock) (llm.sock)                     │
│       │              │                          │
├───────┼──────────────┼──────────────────────────┤
│       │              │    Sandbox boundary      │
│       ▼              ▼                          │
│  ┌─────────────────────────────────────────┐    │
│  │  Sandboxed process                      │    │
│  │                                         │    │
│  │  • AF_INET/AF_INET6 blocked (EPERM)     │    │
│  │  • AF_UNIX allowed (control + LLM only) │    │
│  │  • AGENT_NETWORK_PROXY env var          │    │
│  │    points to LLM socket path            │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

**How it works per platform:**

| | Linux | macOS |
|-|-------|-------|
| Block IP | Seccomp returns `EPERM` for `socket(AF_INET/AF_INET6)`. Optionally `CLONE_NEWNET` removes all network interfaces. | Seatbelt `(deny default)` blocks all TCP/UDP. |
| Allow Unix sockets | Seccomp does not filter `AF_UNIX` — passes through. | `(allow network-outbound (remote unix))` plus literal file access on each socket path. |
| Proxy socket delivery | `AGENT_NETWORK_PROXY` env var (not stripped). | Same. |

The `AGENT_NETWORK_PROXY` env var deliberately avoids the `ARAPUCA_`
prefix so it survives the wrapper binary's environment sanitization.
The host-side proxy can enforce allowlists, rate limits, and logging
on all outbound traffic — the sandboxed process cannot bypass it.

## Architecture

### Overview

Arapuca provides two interfaces:

- **Library** (`rlib` + `cdylib`): Rust API and C FFI for embedding
  sandbox enforcement into a host process. The library manages the full
  subprocess lifecycle — launch, wait, resource stats, cleanup.
- **Binary** (`arapuca -- cmd [args...]`): A wrapper that applies
  restrictions to itself, then `execve()`s the target command. Used by
  the library as a subprocess wrapper for Landlock/seccomp/rlimit
  enforcement.

The library spawns sandboxed processes by composing platform-specific
isolation primitives. On Linux, the binary acts as an inner wrapper
(Landlock + seccomp + rlimits applied before exec). On macOS,
`sandbox-exec` provides the kernel policy and the binary applies only
rlimits.

### Platform Abstraction

The `Sandbox` trait defines the platform contract:

```rust
pub trait Sandbox: Send + Sync {
    fn launch(&self, cfg: &Config, cmd: &str, args: &[&str],
              extra_fds: &[RawFd]) -> Result<Process>;
    fn available(&self) -> Result<()>;
    fn netns_available(&self) -> bool;
    fn cgroups_available(&self) -> bool;
}
```

`platform::new()` returns the appropriate implementation at compile time
via `#[cfg(target_os)]`. There is no runtime platform detection.

### Sandbox Lifecycle

```
Library (host process)
│
├─ Validate inputs (task ID, cgroup paths)
├─ Create temp dir (HOME/TMPDIR for subprocess)
├─ [Linux] Create cgroup, set limits
├─ [macOS] Generate Seatbelt .sb profile
│
├─ Spawn subprocess ──────────────────────────────┐
│   ├─ [Linux]  unshare --net (if netns)          │
│   ├─ [Linux]  arapuca binary wrapper            │
│   │           ├─ Apply Landlock (fs allowlist)  │
│   │           ├─ Apply seccomp (syscall filter) │
│   │           ├─ Apply rlimits                  │
│   │           ├─ Set PR_SET_PDEATHSIG           │
│   │           ├─ Strip ARAPUCA_* env            │
│   │           └─ execve(target)                 │
│   ├─ [macOS]  sandbox-exec -f profile.sb        │
│   │           └─ [arapuca wrapper for rlimits]  │
│   │               └─ execve(target)             │
│   └─ setsid (both platforms)                    │
│                                                 │
├─ [Linux] Add PID to cgroup                      │
├─ [macOS] Start memory monitor thread            │
├─ [macOS] Start parent-PID watchdog thread       │
│                                                 │
├─ wait() ← blocks until subprocess exits ────────┘
├─ resource_stats() ← read cgroup stats (Linux)
└─ cleanup() ← destroy cgroup, remove temp dir
```

### Security Invariants

These are non-negotiable. Any change that weakens them requires
explicit security review:

1. **Fail-closed** — if any sandbox layer fails to apply, the process
   exits non-zero. The subprocess never runs unsandboxed.
2. **PR_SET_NO_NEW_PRIVS** — called before Landlock and seccomp
   (Linux). Prevents privilege escalation via setuid binaries.
3. **Setsid** — subprocess detached from host terminal session.
4. **Cgroup path rejection** — `/sys/fs/cgroup` blocked in read/write
   paths to prevent the subprocess from manipulating its own limits.
5. **Task ID sanitization** — `^[a-zA-Z0-9-]+$`, max 128 chars.
   Prevents path traversal in cgroup and temp dir names.
6. **Env stripping** — `ARAPUCA_*` vars removed before exec so the
   subprocess cannot inspect its own sandbox configuration.
7. **Path validation (macOS)** — strict character allowlist for Seatbelt
   profile paths prevents profile injection attacks.

### Environment Variable Convention

| Prefix | Scope | Stripped before exec? |
|--------|-------|-----------------------|
| `ARAPUCA_*` | Sandbox config (paths, rlimits) | Yes |
| `AGENT_*` | Agent-facing config (proxy sockets) | No |

This separation prevents the bug found in the Go predecessor where
`SANDBOX_NETWORK_PROXY` was set by the library but stripped by the
binary along with all `SANDBOX_*` vars.

### `unsafe` Audit Scope

`#![deny(unsafe_op_in_unsafe_fn)]` is set crate-wide. Every `unsafe`
block has a `// SAFETY:` comment. Expected `unsafe` locations:

| File | Reason |
|------|--------|
| `ffi.rs` | FFI exports, pointer dereference (null-checked) |
| `rlimit.rs` | `prlimit64` / `setrlimit` (raw syscall) |
| `landlock.rs` | `libc::syscall` for ABI version probe |
| `cgroup.rs` | `libc::kill` for SIGKILL |
| `platform/linux.rs` | `pre_exec()` for setsid + pdeathsig |
| `platform/darwin/mod.rs` | `pre_exec()` for setsid, `kill()` for monitors |
| `bin/arapuca.rs` | `libc::prctl`, `libc::execve` |

## Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Static binary (musl, no libc dependency)
cargo build --release --target x86_64-unknown-linux-musl

# Run tests
cargo test

# Lint
cargo clippy -- -D warnings
cargo fmt --check
```

### Requirements

- Rust 1.85+ (edition 2024)
- **Linux**: kernel 5.13+ (Landlock) — degrades gracefully on older
  kernels; cgroups v2 with delegated controllers (for resource limits)
- **macOS**: `sandbox-exec` (ships with macOS, deprecated but functional
  through macOS 15)

## Project Structure

```
src/
├── lib.rs              # Public API, re-exports
├── error.rs            # Error types (thiserror)
├── profile.rs          # Profile, Config, ResourceUsage
├── validate.rs         # Task ID sanitization, cgroup path rejection
├── landlock.rs         # Landlock filesystem restrictions (Linux)
├── seccomp.rs          # Seccomp BPF syscall filter (Linux)
├── rlimit.rs           # POSIX resource limits
├── cgroup.rs           # Cgroups v2 manager (Linux)
├── netns.rs            # Network namespace probe (Linux)
├── env.rs              # Minimal environment, temp dirs, path utils
├── diskquota.rs        # Disk usage monitoring
├── process.rs          # Sandboxed process lifecycle
├── ffi.rs              # C ABI exports
├── platform/
│   ├── mod.rs          # Sandbox trait + factory
│   ├── linux.rs        # Linux sandbox (Landlock + seccomp + cgroups)
│   ├── darwin/
│   │   ├── mod.rs      # macOS sandbox (sandbox-exec + monitors)
│   │   └── darwin_profile.rs  # Seatbelt .sb profile generation
│   └── other.rs        # Degraded fallback (other Unix)
├── bin/
│   └── arapuca.rs    # CLI binary
└── include/
    └── arapuca.h     # C header (generated by cbindgen)
```

## License

Apache-2.0
