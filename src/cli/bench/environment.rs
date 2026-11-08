//! Host description recorded in the artifact: OS, CPU, memory and filesystem type.

use super::schema::{Environment, Fact};
use std::path::Path;

fn run_cmd(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn parse_cpuinfo(text: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "model name").then(|| value.trim().to_owned())
    })
}

fn parse_meminfo(text: &str) -> Option<u64> {
    let rest = text.lines().find_map(|l| l.strip_prefix("MemTotal:"))?;
    let kib: u64 = rest.trim().strip_suffix("kB")?.trim().parse().ok()?;
    kib.checked_mul(1024)
}

fn parse_mounts(text: &str, path: &str) -> Option<String> {
    let mut best: Option<(usize, &str)> = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let (_, Some(point), Some(fstype)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let contains = path == point
            || (path.starts_with(point)
                && (point.ends_with('/') || path[point.len()..].starts_with('/')));
        if contains && best.is_none_or(|(len, _)| point.len() >= len) {
            best = Some((point.len(), fstype));
        }
    }
    best.map(|(_, t)| t.to_owned())
}

fn missing<T>(what: &str) -> Fact<T> {
    Fact::missing(format!(
        "{what} is not readable on this platform without native APIs"
    ))
}

pub(super) fn collect_environment(tmp: &Path) -> Environment {
    let linux_cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|t| parse_cpuinfo(&t));
    let linux_mem = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| parse_meminfo(&t));
    let linux_os = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|s| format!("Linux {}", s.trim()));
    let filesystem = std::fs::read_to_string("/proc/mounts")
        .ok()
        .and_then(|t| parse_mounts(&t, &tmp.to_string_lossy()));

    let (os_version, cpu_model, memory) = if cfg!(windows) {
        (
            run_cmd("cmd", &["/C", "ver"]),
            std::env::var("PROCESSOR_IDENTIFIER")
                .ok()
                .filter(|s| !s.is_empty()),
            run_cmd(
                "powershell",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
                ],
            )
            .and_then(|s| s.parse::<u64>().ok()),
        )
    } else if cfg!(target_os = "macos") {
        (
            run_cmd("sw_vers", &["-productVersion"]).map(|v| format!("macOS {v}")),
            run_cmd("sysctl", &["-n", "machdep.cpu.brand_string"]),
            run_cmd("sysctl", &["-n", "hw.memsize"]).and_then(|s| s.parse::<u64>().ok()),
        )
    } else {
        (linux_os, linux_cpu, linux_mem)
    };

    let fact = |value: Option<String>, what: &str| match value {
        Some(v) => Fact::some(v),
        None => missing(what),
    };
    Environment {
        os: std::env::consts::OS.to_owned(),
        arch: std::env::consts::ARCH.to_owned(),
        os_version: fact(os_version, "OS version"),
        cpu_count: std::thread::available_parallelism()
            .map(|n| Fact::some(n.get() as u64))
            .unwrap_or_else(|e| Fact::missing(format!("parallelism query failed: {e}"))),
        cpu_model: fact(cpu_model, "CPU model"),
        memory_total_bytes: memory.map_or_else(|| missing("total memory"), Fact::some),
        filesystem: fact(filesystem, "file system type"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_file_parsers() {
        assert_eq!(
            parse_cpuinfo("processor : 0\nmodel name\t: Fast CPU @ 3GHz\n").as_deref(),
            Some("Fast CPU @ 3GHz")
        );
        assert_eq!(
            parse_meminfo("MemTotal:       16384 kB\nMemFree: 1 kB\n"),
            Some(16384 * 1024)
        );
        assert_eq!(parse_meminfo("nothing"), None);
        let mounts = "rootfs / ext4 rw 0 0\ntmpfs /tmp tmpfs rw 0 0\ntmpfs /tmpx other rw 0 0\n";
        assert_eq!(
            parse_mounts(mounts, "/tmp/blaze-1").as_deref(),
            Some("tmpfs")
        );
        assert_eq!(parse_mounts(mounts, "/tmpfoo/x").as_deref(), Some("ext4"));
        assert_eq!(parse_mounts(mounts, "/home/u").as_deref(), Some("ext4"));
    }
}
