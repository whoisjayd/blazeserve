use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::os::windows::fs::FileExt;
use std::path::Path;
use std::process::{Child, Command};

/// Reads at `offset`. Every caller passes the offset, so the cursor Windows moves is unused.
pub(crate) fn read_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<usize> {
    file.seek_read(buf, offset)
}

/// Writes all of `buf` at `offset`; safe from several threads on one handle.
pub(crate) fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        let n = file.seek_write(buf, offset)?;
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        buf = &buf[n..];
        offset += n as u64;
    }
    Ok(())
}

/// There is no stable inode here; size and modification time identify the version.
pub(crate) fn file_id(_meta: &Metadata) -> u64 {
    0
}

/// Cannot be told apart without an inode; containment is checked by the caller.
pub(crate) fn same_file(_a: &Metadata, _b: &Metadata) -> bool {
    true
}

/// Resolves on `Ctrl+C`.
pub(crate) async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// Left off: here `SO_REUSEADDR` lets another process bind the same port and take traffic.
pub(crate) fn set_reuse_address(_socket: &socket2::Socket) -> io::Result<()> {
    Ok(())
}

/// A detached process receives no hangup here.
pub(crate) fn ignore_hangup() {}

/// Device names, streams and trailing dots must be refused in served and uploaded paths.
pub(crate) const WINDOWS_NAMES: bool = true;

/// Access follows the folder's list; there is no mode to set.
pub(crate) fn owner_only(options: &mut OpenOptions) -> &mut OpenOptions {
    options
}

pub(crate) fn create_private_dir(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)
}

/// Whether a file runs is decided by its name here.
pub(crate) fn copy_executable_permissions(_from: &Path, _to: &Path) -> io::Result<()> {
    Ok(())
}

pub(crate) const IS_WINDOWS: bool = true;
pub(crate) const IS_MACOS: bool = false;
/// Whether the file system usually treats `A.env` and `a.env` as one name.
pub(crate) const CASE_FOLDS: bool = true;

/// Starts a worker that outlives the terminal.
pub(crate) fn spawn_detached(build: impl Fn() -> io::Result<Command>) -> io::Result<Child> {
    use std::os::windows::process::CommandExt;
    const DETACHED_PROCESS: u32 = 0x0000_0008;
    const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
    const CREATE_BREAKAWAY_FROM_JOB: u32 = 0x0100_0000;
    let base = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP;
    // Leave a job object that would end the worker with the terminal; if the job forbids
    // breakaway, fall back to a plain detached start.
    build()?
        .creation_flags(base | CREATE_BREAKAWAY_FROM_JOB)
        .spawn()
        .or_else(|_| build()?.creation_flags(base).spawn())
}

/// CreateProcess hands a child every inheritable handle, including this process's own output
/// pipes. A caller capturing our output (`id=$(blaze get ... --background)`) would then wait
/// until the job ends. The worker gets its own log handles explicitly instead.
pub(crate) fn stop_inheriting_std_handles() {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{HANDLE_FLAG_INHERIT, SetHandleInformation};
    let handles = [
        std::io::stdin().as_raw_handle(),
        std::io::stdout().as_raw_handle(),
        std::io::stderr().as_raw_handle(),
    ];
    for handle in handles.into_iter().filter(|h| !h.is_null()) {
        // SAFETY: the handle is one of this process's standard handles, which stay open for
        // its whole life; clearing the inherit flag changes nothing else about it.
        unsafe {
            SetHandleInformation(handle.cast(), HANDLE_FLAG_INHERIT, 0);
        }
    }
}

/// `windows` and the build number, which tells the releases apart (22000 and up is 11).
pub(crate) fn os_release() -> Option<(String, String)> {
    use windows_sys::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RRF_RT_REG_SZ, RegGetValueW};
    let wide = |s: &str| s.encode_utf16().chain(Some(0)).collect::<Vec<u16>>();
    let key = wide(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
    let name = wide("CurrentBuildNumber");
    let mut value = [0u16; 32];
    let mut bytes = 64u32;
    // SAFETY: both names are NUL-terminated, and `bytes` holds the size of `value`, which
    // the call does not exceed.
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            name.as_ptr(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            value.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    (status == 0).then(|| {
        let text = String::from_utf16_lossy(&value);
        ("windows".to_owned(), text.trim_end_matches('\0').to_owned())
    })
}

pub(crate) const LIBC: &str = "msvc";

pub(crate) fn memory_bytes() -> Option<u64> {
    use windows_sys::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    // SAFETY: the structure is plain data and its length field is set as the call requires.
    unsafe {
        let mut status: MEMORYSTATUSEX = std::mem::zeroed();
        status.dwLength = u32::try_from(std::mem::size_of::<MEMORYSTATUSEX>()).ok()?;
        (GlobalMemoryStatusEx(&mut status) != 0).then_some(status.ullTotalPhys)
    }
}

pub(crate) fn locale() -> Option<String> {
    use windows_sys::Win32::Globalization::GetUserDefaultLocaleName;
    let mut name = [0u16; 85];
    // SAFETY: the buffer length passed is the buffer's length.
    let written = unsafe { GetUserDefaultLocaleName(name.as_mut_ptr(), 85) };
    let end = usize::try_from(written).ok()?.checked_sub(1)?;
    Some(String::from_utf16_lossy(&name[..end]))
}

pub(crate) fn is_wsl() -> bool {
    false
}
