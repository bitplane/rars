//! Recovery diagnostics remain available without recovery execution.

mod checksum;
pub use checksum::{crc64_rar_state, crc64_xz};

mod errors;
pub use errors::{Error, Result};

#[cfg(feature = "recovery")]
mod implementation;
#[cfg(feature = "recovery")]
pub use implementation::*;
