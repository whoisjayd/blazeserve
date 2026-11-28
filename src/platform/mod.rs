//! Everything that differs between operating systems. `unix` and `windows` provide the same
//! items; nothing else in the crate asks which system it is built for, apart from the
//! display strings of `doctor` and the benchmark report.

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub(crate) use unix::*;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub(crate) use windows::*;

#[cfg(not(any(unix, windows)))]
compile_error!("BlazeServe has no platform module for this system yet; add one in src/platform/");
