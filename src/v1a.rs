use chrono::Utc;
use hmac::{Hmac, Mac};
use percent_encoding::{utf8_percent_encode, AsciiSet};
use sha1::Sha1;
use std::borrow::Cow;

use std::collections::HashMap;
use uuid::Uuid;

use crate::util;

type HmacSha1 = Hmac<Sha1>;

// https://tools.ietf.org/html/rfc5849#section-3.6
// * ALPHA, DIGIT, '-', '.', '_', '~' MUST NOT be encoded.
// * All other characters MUST be encoded.
// * The two hexadecimal characters used to represent encoded
//   characters MUST be uppercase.
const TARGETS_FOR_PARAMS: &AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

const DEFAULT_SIGNATURE: &str = "HMAC-SHA1";
pub const OAUTH_VERSION: &str = "1.0";

const OAUTH_HEADER: &str = "OAuth";
const OAUTH_PARAM_KEY_NONCE: &str = "oauth_nonce";
const OAUTH_PARAM_KEY_CALLBACK: &str = "oauth_callback";
const OAUTH_PARAM_KEY_SIGNATURE_METHOD: &str = "oauth_signature_method";
const OAUTH_PARAM_KEY_TIMESTAMP: &str = "oauth_timestamp";
const OAUTH_PARAM_KEY_VERSION: &str = "oauth_version";
const OAUTH_PARAM_KEY_CONSUMER_KEY: &str = "oauth_consumer_key";

/// OAuth Signature Builder
pub struct OAuthV1SignBuilder<TokenType> {
    oauth_consumer_key: String,
    oauth_nonce: String,
    oauth_signature_method: String,
    oauth_version: Option<String>,
    oauth_timestamp: Option<i64>,
    oauth_token: TokenType,
    encoded_parameters: HashMap<String, String>,
}
