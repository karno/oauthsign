use std::borrow::Cow;

pub const OAUTH_VALUE_VERSION: &str = "1.0";

pub const OAUTH_VALUE_SIGMETHOD_HMACSHA1: &str = "HMAC-SHA1";
pub const OAUTH_VALUE_SIGMETHOD_PLAINTEXT: &str = "PLAINTEXT";
#[derive(Clone, Copy, Debug)]
pub enum SignatureMethod {
    PlainText,
    HmacSha1,
    // TODO: add implementation
    // RsaSha1,
}

impl Into<&'static str> for SignatureMethod {
    fn into(self) -> &'static str {
        match self {
            SignatureMethod::PlainText => OAUTH_VALUE_SIGMETHOD_PLAINTEXT,
            SignatureMethod::HmacSha1 => OAUTH_VALUE_SIGMETHOD_HMACSHA1,
        }
    }
}

pub enum OAuthVersion<'a> {
    None,
    Default,
    Custom(Cow<'a, str>),
}

impl From<Option<&'static str>> for OAuthVersion<'static> {
    fn from(value: Option<&'static str>) -> Self {
        match value {
            Some(OAUTH_VALUE_VERSION) => OAuthVersion::Default,
            Some(item) => OAuthVersion::Custom(Cow::Borrowed(item)),
            None => OAuthVersion::None,
        }
    }
}

impl<'a> From<Option<Cow<'a, str>>> for OAuthVersion<'a> {
    fn from(value: Option<Cow<'a, str>>) -> Self {
        match value {
            Some(Cow::Borrowed(OAUTH_VALUE_VERSION)) => OAuthVersion::Default,
            Some(item) => OAuthVersion::Custom(item),
            None => OAuthVersion::None,
        }
    }
}
impl<'a> From<Cow<'a, str>> for OAuthVersion<'a> {
    fn from(s: Cow<'a, str>) -> Self {
        OAuthVersion::Custom(s)
    }
}

impl<'a> Into<Option<Cow<'a, str>>> for OAuthVersion<'a> {
    fn into(self) -> Option<Cow<'a, str>> {
        match self {
            OAuthVersion::None => None,
            OAuthVersion::Default => Some(Cow::from(OAUTH_VALUE_VERSION)),
            OAuthVersion::Custom(s) => Some(s),
        }
    }
}
