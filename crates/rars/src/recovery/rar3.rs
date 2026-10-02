//! Recovery diagnostics remain available without recovery execution.

mod errors;
pub use errors::{Error, Result};

#[cfg(feature = "recovery")]
mod implementation;
#[cfg(feature = "recovery")]
pub use implementation::*;
