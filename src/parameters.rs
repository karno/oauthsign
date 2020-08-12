use std::borrow::Cow;

pub enum OAuthParameter<'a> {
    StringValue(Cow<'a, str>),
    IntValue(i64),
    FloatValue(f64),
    FileValue(Cow<'a, str>),
    ByteValue(Cow<'a, [u8]>),
    NamedByteValue(Cow<'a, str>, Cow<'a, [u8]>),
}

impl<'a> From<&'a str> for OAuthParameter<'a> {
    fn from(s: &'a str) -> Self {
        OAuthParameter::<'a>::StringValue(s.into())
    }
}

impl From<String> for OAuthParameter<'_> {
    fn from(s: String) -> Self {
        OAuthParameter::StringValue(s.into())
    }
}
impl From<i64> for OAuthParameter<'_> {
    fn from(n: i64) -> Self {
        OAuthParameter::IntValue(n)
    }
}

impl From<f64> for OAuthParameter<'_> {
    fn from(n: f64) -> Self {
        OAuthParameter::FloatValue(n)
    }
}

impl<'a> From<&'a [u8]> for OAuthParameter<'a> {
    fn from(v: &'a [u8]) -> Self {
        OAuthParameter::ByteValue(v.into())
    }
}

impl<'a> From<Vec<u8>> for OAuthParameter<'a> {
    fn from(v: Vec<u8>) -> Self {
        OAuthParameter::ByteValue(v.into())
    }
}
impl<'a> OAuthParameter<'a> {
    pub fn from_file<T: Into<Cow<'a, str>>>(path: T) -> Self {
        OAuthParameter::<'a>::FileValue(path.into())
    }

    pub fn from_bytes<TKey: Into<Cow<'a, str>>, TValue: Into<Cow<'a, [u8]>>>(
        name: TKey,
        bytes: TValue,
    ) -> Self {
        OAuthParameter::NamedByteValue(name.into(), bytes.into())
    }
}

pub enum OAuthSignedParameter {
    StringValue(String),
    ByteValue(String, Vec<u8>),
}

pub struct OAuthSignedContent {
    parameters: Vec<(String, OAuthSignedParameter)>,
    signature: String,
}

impl OAuthSignedContent {}
