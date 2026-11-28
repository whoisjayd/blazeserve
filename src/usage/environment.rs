//! What kind of machine a run is on. Every value is a number or comes from a closed list, so
//! nothing a user typed or named can reach a report.

use serde_json::{Map, Value};

use super::Env;
use crate::platform;

const DISTROS: &[&str] = &[
    "windows",
    "macos",
    "ubuntu",
    "debian",
    "fedora",
    "rhel",
    "centos",
    "rocky",
    "almalinux",
    "amzn",
    "alpine",
    "arch",
    "manjaro",
    "opensuse-leap",
    "opensuse-tumbleweed",
    "nixos",
    "linuxmint",
    "pop",
    "kali",
    "raspbian",
    "gentoo",
    "void",
];

/// `value` if it is on the list, else `other`.
fn listed(value: &str, list: &[&'static str]) -> &'static str {
    list.iter()
        .copied()
        .find(|known| known.eq_ignore_ascii_case(value))
        .unwrap_or("other")
}

/// Digits and dots only, so a release string cannot carry text.
fn version_number(raw: &str) -> String {
    raw.chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .take(16)
        .collect()
}

/// The two-letter language of a locale such as `en_US.UTF-8`.
fn language(locale: &str) -> Option<String> {
    let code: String = locale
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect();
    (2..=3)
        .contains(&code.len())
        .then(|| code.to_ascii_lowercase())
}

fn disk_bucket(bytes: u64) -> &'static str {
    const GIB: u64 = 1 << 30;
    match bytes / GIB {
        0..=1 => "<2GiB",
        2..=9 => "2-9GiB",
        10..=49 => "10-49GiB",
        50..=199 => "50-199GiB",
        200..=999 => "200-999GiB",
        _ => ">=1TiB",
    }
}

fn memory_bucket(bytes: u64) -> &'static str {
    const GIB: u64 = 1 << 30;
    // Rounded up: firmware reserves a little of each stick.
    match bytes.div_ceil(GIB) {
        0..=2 => "<=2GiB",
        3..=4 => "3-4GiB",
        5..=8 => "5-8GiB",
        9..=16 => "9-16GiB",
        17..=32 => "17-32GiB",
        33..=64 => "33-64GiB",
        _ => ">64GiB",
    }
}

fn terminal(env: &Env) -> &'static str {
    if env("WT_SESSION").is_some() {
        return "windows-terminal";
    }
    match env("TERM_PROGRAM") {
        Some(program) => listed(
            &program,
            &[
                "vscode",
                "iTerm.app",
                "Apple_Terminal",
                "WezTerm",
                "ghostty",
                "Hyper",
                "tmux",
            ],
        ),
        None => match env("TERM") {
            Some(term) if term.starts_with("xterm") => "xterm",
            Some(term) if term.starts_with("screen") || term.starts_with("tmux") => "tmux",
            Some(_) => "other",
            None => "none",
        },
    }
}

fn shell(env: &Env) -> &'static str {
    if let Some(path) = env("SHELL") {
        let name = path.rsplit('/').next().unwrap_or_default();
        return listed(
            name,
            &["bash", "zsh", "fish", "sh", "dash", "nu", "pwsh", "ksh"],
        );
    }
    if env("PSModulePath").is_some() {
        "powershell"
    } else {
        "other"
    }
}

fn container(env: &Env) -> &'static str {
    if env("KUBERNETES_SERVICE_HOST").is_some() {
        "kubernetes"
    } else if std::path::Path::new("/.dockerenv").exists() {
        "docker"
    } else if env("container").is_some() {
        "other"
    } else {
        "none"
    }
}

pub(super) fn facts(env: &Env) -> Map<String, Value> {
    let mut out = Map::new();
    let mut put = |key: &str, value: Value| {
        out.insert(key.to_owned(), value);
    };
    if let Some((id, version)) = platform::os_release() {
        put("os_distribution", listed(&id, DISTROS).into());
        put("os_version", version_number(&version).into());
    }
    if let Ok(cpus) = std::thread::available_parallelism() {
        put("cpu_count", cpus.get().into());
    }
    if let Some(bytes) = platform::memory_bytes() {
        put("memory_bucket", memory_bucket(bytes).into());
    }
    // The volume the command works in; the folder itself is never named.
    if let Ok(stats) = fs4::statvfs(".") {
        put("disk_total_bucket", disk_bucket(stats.total_space()).into());
        put(
            "disk_free_bucket",
            disk_bucket(stats.available_space()).into(),
        );
    }
    if let Some(language) = platform::locale().as_deref().and_then(language) {
        put("language", language.into());
    }
    put("libc", platform::LIBC.into());
    put("terminal", terminal(env).into());
    put("shell", shell(env).into());
    put("container", container(env).into());
    put("wsl", platform::is_wsl().into());
    put("ssh", env("SSH_CONNECTION").is_some().into());
    put("python", env("BLAZE_PYTHON").is_some().into());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn free_text_never_survives() {
        let secret = |_: &str| Some("/home/ann/secret-project".to_owned());
        for value in facts(&secret).values() {
            assert!(!value.to_string().contains("ann"), "{value}");
        }
        assert_eq!(version_number("24.04 (Ann's build)"), "24.04");
        assert_eq!(language("en_US.UTF-8").as_deref(), Some("en"));
        assert_eq!(language("C"), None);
        assert_eq!(memory_bucket(8 << 30), "5-8GiB");
        assert_eq!(memory_bucket((16 << 30) - 1), "9-16GiB");
    }

    #[test]
    fn this_machine_is_described() {
        let facts = facts(&|_| None);
        for key in [
            "os_distribution",
            "cpu_count",
            "libc",
            "terminal",
            "container",
        ] {
            assert!(facts.contains_key(key), "{key}: {facts:?}");
        }
    }
}
