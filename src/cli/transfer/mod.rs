//! Resumable `blaze get` downloads and chunked `blaze put` uploads.

mod discover;
mod download;
#[cfg(feature = "extract")]
mod extract;
mod filename;
mod http;
mod retry;
mod segmented;
mod throttle;
mod upload;

pub use download::{GetArgs, get};
pub use upload::{PutArgs, put};

const READ_BUF: usize = 256 * 1024;
