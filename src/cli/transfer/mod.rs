//! Resumable `blaze get` downloads and chunked `blaze put` uploads.

mod discover;
mod download;
mod error;
#[cfg(feature = "extract")]
mod extract;
mod filename;
mod http;
mod limits;
mod retry;
mod segmented;
mod throttle;
mod upload;
mod verify;

#[cfg(fuzzing)]
pub use discover::parse_digest_for_fuzz;
pub use download::{GetArgs, get};
pub use error::TransferError;
#[cfg(fuzzing)]
pub use filename::suggested_name_for_fuzz;
pub use upload::{PutArgs, put};
#[cfg(fuzzing)]
pub use verify::parse_lists_for_fuzz;
pub use verify::{VerifyArgs, verify};

const READ_BUF: usize = 256 * 1024;
