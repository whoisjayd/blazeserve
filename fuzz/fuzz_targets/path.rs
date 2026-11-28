#![no_main]

use blazeserve::handler::decode_components_for_fuzz;
use blazeserve::security::{is_safe_path, resolve_under};
use libfuzzer_sys::fuzz_target;
use std::path::PathBuf;
use std::sync::OnceLock;

fn base() -> &'static PathBuf {
    static BASE: OnceLock<PathBuf> = OnceLock::new();
    BASE.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("blaze-fuzz-{}", std::process::id()));
        let root = dir.join("root");
        let outside = dir.join("outside");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(root.join("a/b/f.txt"), b"x").unwrap();
        std::fs::write(outside.join("secret.txt"), b"s").unwrap();
        #[cfg(unix)]
        {
            let _ = std::os::unix::fs::symlink(&outside, root.join("link"));
        }
        #[cfg(windows)]
        {
            let _ = std::os::windows::fs::symlink_dir(&outside, root.join("link"));
        }
        root.canonicalize().unwrap()
    })
}

fuzz_target!(|raw: &str| {
    let root = base();
    if let Ok(components) = decode_components_for_fuzz(raw) {
        for part in &components {
            assert!(!part.is_empty());
            assert_ne!(part, ".");
            assert_ne!(part, "..");
            assert!(!part.contains(['/', '\\', '\0']));
        }
        if !components.is_empty() {
            let joined = components.join("/");
            if let Ok(p) = resolve_under(root, &joined) {
                let p = p.canonicalize().unwrap_or(p);
                assert!(p.starts_with(root), "{raw:?} escaped to {}", p.display());
            }
        }
    }
    if let Ok(p) = resolve_under(root, raw) {
        let p = p.canonicalize().unwrap_or(p);
        assert!(p.starts_with(root), "{raw:?} escaped to {}", p.display());
    }
    let candidate = root.join(raw);
    if is_safe_path(root, &candidate) {
        let p = candidate.canonicalize().unwrap_or(candidate);
        assert!(p.starts_with(root), "{raw:?} escaped via {p:?}");
    }
});
