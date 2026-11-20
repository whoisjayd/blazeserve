//! Resumable `blaze get` downloads and chunked `blaze put` uploads.

mod download;
mod filename;
mod http;
mod retry;
mod segmented;
mod throttle;
mod upload;

pub use download::{GetArgs, get};
pub use upload::{PutArgs, put};

const READ_BUF: usize = 256 * 1024;
