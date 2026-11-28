//! Puts a new executable in place of the running one, and puts the old one back on failure.

use std::io;
use std::path::{Path, PathBuf};

/// Where the previous executable waits on Windows until the next start can delete it.
pub fn backup_path(exe: &Path) -> PathBuf {
    let mut name = exe.as_os_str().to_owned();
    name.push(".old");
    PathBuf::from(name)
}

/// Windows refuses to overwrite a running executable but allows renaming it. Move the old
/// one aside, move the new one in, and move the old one back if that second step fails.
fn swap_with_backup(
    target: &Path,
    staged: &Path,
    rename: &dyn Fn(&Path, &Path) -> io::Result<()>,
) -> Result<(), String> {
    let backup = backup_path(target);
    // A leftover from an earlier upgrade; it is not running any more unless a second upgrade
    // overlaps, in which case the rename below fails and nothing changes.
    let _ = std::fs::remove_file(&backup);
    rename(target, &backup).map_err(|e| format!("cannot move the current program aside: {e}"))?;
    if let Err(e) = rename(staged, target) {
        return match rename(&backup, target) {
            Ok(()) => Err(format!(
                "cannot install the new program ({e}); the previous version was restored"
            )),
            Err(restore) => Err(format!(
                "cannot install the new program ({e}) and cannot restore the old one ({restore}); \
                 it is saved as {}",
                backup.display()
            )),
        };
    }
    Ok(())
}

/// Runs `install`, a tool that writes a new program at `exe`, while this one runs. Windows
/// would refuse to overwrite it, so it waits aside and comes back if nothing replaced it.
pub fn while_aside(
    exe: &Path,
    install: impl FnOnce() -> Result<bool, String>,
) -> Result<bool, String> {
    if !crate::platform::IS_WINDOWS || !exe.is_file() {
        return install();
    }
    let backup = backup_path(exe);
    let _ = std::fs::remove_file(&backup);
    std::fs::rename(exe, &backup)
        .map_err(|e| format!("cannot move the current program aside: {e}"))?;
    let outcome = install();
    if !exe.exists() {
        std::fs::rename(&backup, exe).map_err(|e| {
            format!(
                "cannot restore the old program ({e}); it is saved as {}",
                backup.display()
            )
        })?;
    }
    outcome
}

/// Replaces `target` with `staged`, which must sit on the same file system.
pub fn replace_executable(target: &Path, staged: &Path) -> Result<(), String> {
    if crate::platform::IS_WINDOWS {
        // A running program can be renamed but not overwritten.
        swap_with_backup(target, staged, &|a, b| std::fs::rename(a, b))
    } else {
        // One rename is atomic: a failure leaves the old program untouched.
        std::fs::rename(staged, target).map_err(|e| format!("cannot install the new program: {e}"))
    }
}

/// Deletes the previous executable that a Windows upgrade left beside the current one.
pub fn remove_stale_backup() {
    if !crate::platform::IS_WINDOWS {
        return;
    }
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let is_blaze = exe
        .file_stem()
        .is_some_and(|s| s.eq_ignore_ascii_case("blaze"));
    if is_blaze {
        let _ = std::fs::remove_file(backup_path(&exe));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("blaze.exe");
        let staged = dir.path().join("staged");
        std::fs::write(&target, b"old").unwrap();
        std::fs::write(&staged, b"new").unwrap();
        (dir, target, staged)
    }

    #[test]
    fn an_installer_can_write_the_program_that_is_running() {
        let (_dir, target, _) = setup();
        let done = while_aside(&target, || {
            assert_eq!(target.exists(), !crate::platform::IS_WINDOWS);
            std::fs::write(&target, b"new").unwrap();
            Ok(true)
        });
        assert_eq!(done, Ok(true));
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn an_installer_that_fails_leaves_the_old_program() {
        let (_dir, target, _) = setup();
        assert_eq!(while_aside(&target, || Ok(false)), Ok(false));
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
    }

    #[test]
    fn swap_moves_the_old_program_aside() {
        let (_dir, target, staged) = setup();
        swap_with_backup(&target, &staged, &|a, b| std::fs::rename(a, b)).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
        assert_eq!(std::fs::read(backup_path(&target)).unwrap(), b"old");
    }

    #[test]
    fn swap_restores_the_old_program_when_the_install_step_fails() {
        let (_dir, target, staged) = setup();
        let calls = Cell::new(0);
        let flaky = |a: &Path, b: &Path| {
            calls.set(calls.get() + 1);
            if calls.get() == 2 {
                Err(io::Error::other("disk full"))
            } else {
                std::fs::rename(a, b)
            }
        };
        let err = swap_with_backup(&target, &staged, &flaky).unwrap_err();
        assert!(err.contains("restored"), "{err}");
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
        assert!(!backup_path(&target).exists());
        assert_eq!(std::fs::read(&staged).unwrap(), b"new");
    }

    #[test]
    fn swap_that_cannot_move_aside_changes_nothing() {
        let (_dir, target, staged) = setup();
        let deny = |_: &Path, _: &Path| Err(io::Error::from(io::ErrorKind::PermissionDenied));
        assert!(swap_with_backup(&target, &staged, &deny).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
    }

    #[test]
    fn replace_executable_installs_the_staged_file() {
        let (_dir, target, staged) = setup();
        replace_executable(&target, &staged).unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn failed_replace_leaves_the_old_program() {
        let (dir, target, _) = setup();
        let missing = dir.path().join("does-not-exist");
        assert!(replace_executable(&target, &missing).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"old");
    }
}
