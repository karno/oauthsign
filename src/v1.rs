mod client;
mod signer;
mod values;

pub use signer::{Secrets, Signer};
use std::borrow::Cow;

use hmac::Hmac;
use percent_encoding::AsciiSet;
use sha1::Sha1;

use std::collections::HashMap;
use values::*;

const OAUTH_HEADER: &str = "OAuth";
