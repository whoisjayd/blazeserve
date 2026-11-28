use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Child, Command};

/// Reads at `offset` without moving a shared cursor.
pub(crate) fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    file.read_at(buf, offset)
}

/// Writes all of `buf` at `offset`; safe from several threads on one handle.
pub(crate) fn write_all_at(file: &File, buf: &[u8], offset: u64) -> io::Result<()> {
    file.write_all_at(buf, offset)
}

/// The inode, so a replaced file gets a new validator even with an equal size and time.
pub(crate) fn file_id(meta: &Metadata) -> u64 {
    meta.ino()
}

/// Whether two looks at a path saw the same file.
pub(crate) fn same_file(a: &Metadata, b: &Metadata) -> bool {
    a.dev() == b.dev() && a.ino() == b.ino()
}

/// Resolves on `Ctrl+C` or `SIGTERM`.
pub(crate) async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).ok();
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        () = async {
            match term.as_mut() {
                Some(t) => { t.recv().await; }
                None => std::future::pending::<()>().await,
            }
        } => {}
    }
}

/// Lets a restart bind while old connections are still in `TIME_WAIT`.
pub(crate) fn set_reuse_address(socket: &socket2::Socket) -> io::Result<()> {
    socket.set_reuse_address(true)
}

/// Keeps the process alive when its terminal goes away.
pub(crate) fn ignore_hangup() {
    // Registering a handler replaces the default action, which would end the process. The
    // handler stays installed after the runtime is dropped.
    if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        rt.block_on(async {
            let _ = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup());
        });
    }
}

/// Names such as `CON` or `a:b` are ordinary here.
pub(crate) const WINDOWS_NAMES: bool = false;

/// A file created with these options is readable by its owner only.
pub(crate) fn owner_only(options: &mut OpenOptions) -> &mut OpenOptions {
    options.mode(0o600)
}

/// Creates `dir` and its parents, and makes `dir` private even if it already existed.
pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// Gives a replacement program the old one's permissions, and makes it executable.
pub(crate) fn copy_executable_permissions(from: &Path, to: &Path) -> io::Result<()> {
    let mode = std::fs::metadata(from)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o755);
    std::fs::set_permissions(to, std::fs::Permissions::from_mode(mode | 0o111))
}

pub(crate) const IS_WINDOWS: bool = false;
pub(crate) const IS_MACOS: bool = cfg!(target_os = "macos");
/// Whether the file system usually treats `A.env` and `a.env` as one name.
pub(crate) const CASE_FOLDS: bool = IS_MACOS;

/// Starts a worker that outlives the terminal.
pub(crate) fn spawn_detached(build: impl Fn() -> io::Result<Command>) -> io::Result<Child> {
    use std::os::unix::process::CommandExt;
    // A process group of its own keeps terminal signals away; the worker also ignores
    // hangups itself.
    build()?.process_group(0).spawn()
}

/// Descriptors are closed on exec unless passed on purpose.
pub(crate) fn stop_inheriting_std_handles() {}
