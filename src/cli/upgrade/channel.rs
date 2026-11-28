//! Which tool installed this copy of blaze, and so which tool should upgrade it.

use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Channel {
    /// A downloaded release binary that `blaze upgrade` replaces itself.
    Binary,
    Pip,
    Cargo,
    Docker,
    /// Installed by a package manager that owns the file; the user upgrades it there.
    Managed {
        manager: &'static str,
        command: &'static str,
    },
}

impl Channel {
    pub fn name(&self) -> &'static str {
        match self {
            Channel::Binary => "binary",
            Channel::Pip => "pip",
            Channel::Cargo => "cargo",
            Channel::Docker => "docker",
            Channel::Managed { .. } => "package-manager",
        }
    }
}

/// `BLAZE_INSTALL_CHANNEL` wins, then `BLAZE_PYTHON` (set by the Python package) means pip,
/// then the location of the executable.
pub fn detect(env: &dyn Fn(&str) -> Option<String>, exe: &Path) -> Channel {
    let python = env("BLAZE_PYTHON").filter(|p| !p.trim().is_empty());
    match env("BLAZE_INSTALL_CHANNEL")
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "pip" => return from_python(python.as_deref()),
        "cargo" => return Channel::Cargo,
        "docker" => return Channel::Docker,
        "binary" => return Channel::Binary,
        _ => {}
    }
    if let Some(python) = python {
        return from_python(Some(&python));
    }
    from_path(exe)
}

/// Splits on both separators so a Windows path is read the same on any host. This only
/// feeds install-location guesses; nothing here touches the file system.
fn lowered_parts(path: &Path) -> Vec<String> {
    path.to_string_lossy()
        .to_ascii_lowercase()
        .split(['/', '\\'])
        .filter(|p| !p.is_empty())
        .map(str::to_owned)
        .collect()
}

fn has_sequence(parts: &[String], want: &[&str]) -> bool {
    parts
        .windows(want.len())
        .any(|w| w.iter().zip(want).all(|(a, b)| a == b))
}

/// pipx and uv keep each tool in its own environment and expect to upgrade it themselves.
fn from_python(python: Option<&str>) -> Channel {
    let Some(python) = python else {
        return Channel::Pip;
    };
    let parts = lowered_parts(Path::new(python));
    if has_sequence(&parts, &["pipx", "venvs"]) {
        return Channel::Managed {
            manager: "pipx",
            command: "pipx upgrade blazeserve",
        };
    }
    if has_sequence(&parts, &["uv", "tools"]) {
        return Channel::Managed {
            manager: "uv",
            command: "uv tool upgrade blazeserve",
        };
    }
    Channel::Pip
}

fn from_path(exe: &Path) -> Channel {
    let parts = lowered_parts(exe);
    let any = |name: &str| parts.iter().any(|p| p == name);
    if has_sequence(&parts, &[".cargo", "bin"]) {
        return Channel::Cargo;
    }
    if any("cellar") || any("homebrew") || any("linuxbrew") {
        return Channel::Managed {
            manager: "Homebrew",
            command: "brew upgrade blazeserve",
        };
    }
    if has_sequence(&parts, &["scoop", "apps"]) || has_sequence(&parts, &["scoop", "shims"]) {
        return Channel::Managed {
            manager: "Scoop",
            command: "scoop update blazeserve",
        };
    }
    if has_sequence(&parts, &["microsoft", "winget"]) || any("windowsapps") {
        return Channel::Managed {
            manager: "winget",
            command: "winget upgrade blazeserve",
        };
    }
    if has_sequence(&parts, &["nix", "store"]) {
        return Channel::Managed {
            manager: "Nix",
            command: "nix profile upgrade blazeserve",
        };
    }
    if !crate::platform::IS_WINDOWS
        && exe.is_absolute()
        && matches!(
            parts.first().map(String::as_str),
            Some("usr" | "bin" | "sbin")
        )
        && !has_sequence(&parts, &["usr", "local"])
    {
        return Channel::Managed {
            manager: "your system package manager",
            command: "the package manager that installed it (apt, dnf, pacman, apk ...)",
        };
    }
    Channel::Binary
}

#[cfg(test)]
mod tests {
    use super::*;

    fn detect_with(vars: &[(&str, &str)], exe: &str) -> Channel {
        let vars: Vec<(String, String)> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        detect(
            &move |k| vars.iter().find(|(n, _)| n == k).map(|(_, v)| v.clone()),
            Path::new(exe),
        )
    }

    #[test]
    fn explicit_channel_beats_the_path() {
        assert_eq!(
            detect_with(
                &[("BLAZE_INSTALL_CHANNEL", "docker")],
                "/home/u/.cargo/bin/blaze"
            ),
            Channel::Docker
        );
        assert_eq!(
            detect_with(
                &[("BLAZE_INSTALL_CHANNEL", "Binary")],
                "/opt/homebrew/bin/blaze"
            ),
            Channel::Binary
        );
        assert_eq!(
            detect_with(&[("BLAZE_INSTALL_CHANNEL", "cargo")], "/tmp/blaze"),
            Channel::Cargo
        );
    }

    #[test]
    fn python_launcher_means_pip_unless_pipx_or_uv_owns_it() {
        assert_eq!(
            detect_with(&[("BLAZE_PYTHON", "/usr/bin/python3")], "/usr/bin/python3"),
            Channel::Pip
        );
        assert_eq!(
            detect_with(
                &[
                    ("BLAZE_INSTALL_CHANNEL", "pip"),
                    (
                        "BLAZE_PYTHON",
                        "/home/u/.local/pipx/venvs/blazeserve/bin/python"
                    )
                ],
                "/x"
            ),
            Channel::Managed {
                manager: "pipx",
                command: "pipx upgrade blazeserve"
            }
        );
        assert_eq!(
            detect_with(
                &[(
                    "BLAZE_PYTHON",
                    "C:\\Users\\u\\AppData\\Roaming\\uv\\tools\\blazeserve\\Scripts\\python.exe"
                )],
                "x"
            ),
            Channel::Managed {
                manager: "uv",
                command: "uv tool upgrade blazeserve"
            }
        );
    }

    #[test]
    fn paths_pick_the_package_manager() {
        assert_eq!(detect_with(&[], "/home/u/.cargo/bin/blaze"), Channel::Cargo);
        assert_eq!(
            detect_with(&[], "C:\\Users\\u\\.cargo\\bin\\blaze.exe"),
            Channel::Cargo
        );
        for (path, manager) in [
            (
                "/opt/homebrew/Cellar/blazeserve/1.0.0/bin/blaze",
                "Homebrew",
            ),
            ("/home/linuxbrew/.linuxbrew/bin/blaze", "Homebrew"),
            (
                "C:\\Users\\u\\scoop\\apps\\blazeserve\\current\\blaze.exe",
                "Scoop",
            ),
            (
                "C:\\Users\\u\\AppData\\Local\\Microsoft\\WinGet\\Packages\\x\\blaze.exe",
                "winget",
            ),
            ("/nix/store/abc-blazeserve/bin/blaze", "Nix"),
        ] {
            match detect_with(&[], path) {
                Channel::Managed { manager: m, .. } => assert_eq!(m, manager, "{path}"),
                other => panic!("{path}: {other:?}"),
            }
        }
    }

    #[test]
    fn plain_locations_are_a_standalone_binary() {
        assert_eq!(detect_with(&[], "/usr/local/bin/blaze"), Channel::Binary);
        assert_eq!(detect_with(&[], "/home/u/bin/blaze"), Channel::Binary);
        assert_eq!(detect_with(&[], "D:\\tools\\blaze.exe"), Channel::Binary);
    }

    #[cfg(unix)]
    #[test]
    fn system_package_directories_are_left_alone() {
        assert!(matches!(
            detect_with(&[], "/usr/bin/blaze"),
            Channel::Managed { .. }
        ));
    }
}
