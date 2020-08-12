use crate::builder::OAuthSigner;
use crate::parameters::OAuthParameter;
use crate::{util, v1::*};
use chrono::Utc;
use hmac::{Hmac, Mac};
use io::Read;
use percent_encoding::utf8_percent_encode;
use percent_encoding::PercentEncode;
use sha1::Sha1;
use std::{
    borrow::Cow,
    ffi::{OsStr, OsString},
    fs::File,
    io,
    path::Path,
};
use uuid::Uuid;

type HmacSha1 = Hmac<Sha1>;

const OAUTH_PARAM_KEY_CALLBACK: &str = "oauth_callback";
const OAUTH_PARAM_KEY_CONSUMER_KEY: &str = "oauth_consumer_key";
const OAUTH_PARAM_KEY_NONCE: &str = "oauth_nonce";
const OAUTH_PARAM_KEY_SIGNATURE_METHOD: &str = "oauth_signature_method";
const OAUTH_PARAM_KEY_TIMESTAMP: &str = "oauth_timestamp";
const OAUTH_PARAM_KEY_TOKEN: &str = "oauth_nonce";
const OAUTH_PARAM_KEY_VERSION: &str = "oauth_version";

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

// This is also used for generating signatures.
const TARGETS_FOR_SIGN: &AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

const TARGETS_FOR_TWITTER_SIGN: &AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b':'); // 🤔🤔🤔🤔🤔🤔🤔🤔🤔??????????

pub enum EncodedParameter<'a> {
    StringValue(Cow<'a, str>),
    FileValue(Cow<'a, str>, io::Result<String>),
}

impl<'a> EncodedParameter<'a> {
    fn read_file_as_encoded_bytes(path: &str) -> io::Result<String> {
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(base64::encode(&buf))
    }

    pub fn get_str(self) -> io::Result<Cow<'a, str>> {
        match self {
            EncodedParameter::StringValue(s) => Ok(s),
            EncodedParameter::FileValue(k, r) => {
                r.map(|v| Cow::Owned(EncodedParameter::format_multipart_content(k, v)))
            }
        }
    }

    pub fn to_string(self) -> io::Result<String> {
        match self {
            EncodedParameter::StringValue(s) => Ok(s.to_string()),
            EncodedParameter::FileValue(k, r) => {
                r.map(|v| EncodedParameter::format_multipart_content(k, v))
            }
        }
    }

    fn format_multipart_content<'b>(key: Cow<'b, str>, content: String) -> String {
        // TODO: format for multipart content
        content
    }
}

impl<'a> From<OAuthParameter<'a>> for EncodedParameter<'a> {
    fn from(p: OAuthParameter<'a>) -> Self {
        match p {
            OAuthParameter::StringValue(s) => EncodedParameter::StringValue(percent_encode_cow(s)),
            OAuthParameter::IntValue(n) => {
                EncodedParameter::StringValue(percent_encode_cow(n.to_string()))
            }
            OAuthParameter::FloatValue(n) => {
                EncodedParameter::StringValue(percent_encode_cow(n.to_string()))
            }
            OAuthParameter::ByteValue(b) => {
                EncodedParameter::StringValue(percent_encode_cow(base64::encode(&b)))
            }
            OAuthParameter::NamedByteValue(n, b) => EncodedParameter::FileValue(
                percent_encode_cow(n),
                Ok(percent_encode_str(base64::encode(&b))),
            ),
            OAuthParameter::FileValue(path) => {
                let file_bytes = EncodedParameter::read_file_as_encoded_bytes(&path);
                // acquire reference to str
                let os_path = match path {
                    Cow::Borrowed(r) => Cow::from(OsStr::new(r)),
                    Cow::Owned(s) => Cow::from(OsString::from(s)),
                };
                let filename = percent_encode_cow(
                    Path::new(&os_path)
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or(&"")
                        .to_string(),
                );
                EncodedParameter::FileValue(filename, file_bytes)
            }
        }
    }
}

/// Contents signed with OAuth1a.
pub struct SignedContent<'a> {
    pub signature: String,
    pub nonce: Cow<'a, str>,
    pub payload: Vec<(Cow<'a, str>, Cow<'a, str>)>,
    pub timestamp: i64,
}

pub struct Signer<'a, T> {
    token: T,
    consumer_key: Cow<'a, str>,
    endpoint: Cow<'a, str>,
    http_method: Cow<'a, str>,
    nonce: Option<Cow<'a, str>>,
    signature_method: SignatureMethod,
    timestamp: Option<i64>,
    version: OAuthVersion<'a>,
}

impl<'a> Signer<'a, ()> {
    pub fn new<TConsumerKey, TEndpoint, THttpMethod>(
        consumer_key: TConsumerKey,
        endpoint: TEndpoint,
        http_method: THttpMethod,
    ) -> Self
    where
        TConsumerKey: Into<Cow<'a, str>>,
        TEndpoint: Into<Cow<'a, str>>,
        THttpMethod: Into<Cow<'a, str>>,
    {
        Signer {
            token: (),
            consumer_key: consumer_key.into(),
            endpoint: endpoint.into(),
            http_method: http_method.into(),
            signature_method: SignatureMethod::HmacSha1,
            nonce: None,
            timestamp: None,
            version: OAuthVersion::Default,
        }
    }
}

impl<'a> Signer<'a, Cow<'a, str>> {
    pub fn new<TConsumerKey, TEndpoint, THttpMethod, TToken>(
        consumer_key: TConsumerKey,
        endpoint: TEndpoint,
        http_method: THttpMethod,
        token: TToken,
    ) -> Self
    where
        TConsumerKey: Into<Cow<'a, str>>,
        TEndpoint: Into<Cow<'a, str>>,
        THttpMethod: Into<Cow<'a, str>>,
        TToken: Into<Cow<'a, str>>,
    {
        Signer {
            token: token.into(),
            consumer_key: consumer_key.into(),
            endpoint: endpoint.into(),
            http_method: http_method.into(),
            signature_method: SignatureMethod::HmacSha1,
            nonce: None,
            timestamp: None,
            version: OAuthVersion::Default,
        }
    }
}
pub struct Secrets<'a, T> {
    token_secret: T,
    consumer_secret: Cow<'a, str>,
}

impl<'a> Secrets<'a, ()> {
    pub fn new<T>(consumer_secret: T) -> Self
    where
        T: Into<Cow<'a, str>>,
    {
        Secrets {
            token_secret: (),
            consumer_secret: consumer_secret.into(),
        }
    }
}

impl<'a> Secrets<'a, Cow<'a, str>> {
    pub fn new<TConsumerSecret, TTokenSecret>(
        consumer_secret: TConsumerSecret,
        token_secret: TTokenSecret,
    ) -> Self
    where
        TConsumerSecret: Into<Cow<'a, str>>,
        TTokenSecret: Into<Cow<'a, str>>,
    {
        Secrets {
            token_secret: token_secret.into(),
            consumer_secret: consumer_secret.into(),
        }
    }
}

impl<'a> OAuthSigner<'a, Secrets<'a, ()>, io::Result<SignedContent<'a>>> for Signer<'a, ()> {
    fn sign(
        self,
        param: Vec<(Cow<'a, str>, OAuthParameter<'a>)>,
        secrets: &Secrets<'a, ()>,
    ) -> io::Result<SignedContent<'a>> {
        sign_oauthv1(
            self.endpoint,
            self.http_method,
            (self.consumer_key, &secrets.consumer_secret),
            None,
            self.signature_method,
            self.nonce,
            self.version,
            self.timestamp,
            param,
        )
    }
}

impl<'a> OAuthSigner<'a, Secrets<'a, Cow<'a, str>>, io::Result<SignedContent<'a>>>
    for Signer<'a, Cow<'a, str>>
{
    fn sign(
        self,
        param: Vec<(Cow<'a, str>, OAuthParameter<'a>)>,
        secrets: &Secrets<'a, Cow<'a, str>>,
    ) -> io::Result<SignedContent<'a>> {
        sign_oauthv1(
            self.endpoint,
            self.http_method,
            (self.consumer_key, &secrets.consumer_secret),
            Some((self.token, &secrets.token_secret)),
            self.signature_method,
            self.nonce,
            self.version,
            self.timestamp,
            param,
        )
    }
}

fn sign_oauthv1<'a>(
    endpoint: Cow<'a, str>,
    http_method: Cow<'a, str>,
    consumer_key_and_secret: (Cow<'a, str>, &str),
    token_and_secret: Option<(Cow<'a, str>, &str)>,
    signature_method: SignatureMethod,
    nonce: Option<Cow<'a, str>>,
    version: OAuthVersion<'a>,
    timestamp: Option<i64>,
    parameters: Vec<(Cow<'a, str>, OAuthParameter<'a>)>,
) -> io::Result<SignedContent<'a>> {
    // destructure & setup variables
    let (c_key, c_secret) = consumer_key_and_secret;
    let (token, token_secret) = token_and_secret
        .map(|(t, s)| (Some(t), Some(s)))
        .unwrap_or((None, None));
    let timestamp = timestamp.unwrap_or_else(|| Utc::now().timestamp());
    // generate nonce when it is not specified
    let nonce = nonce.unwrap_or_else(|| Cow::from(format!("{}", Uuid::new_v4())));
    let sampled_nonce = nonce.clone();

    // prepare parameters
    let basic_params_encoded = build_basic_params(
        c_key,
        token,
        signature_method,
        nonce,
        timestamp,
        version.into(),
    );
    let user_params_encoded = parameters
        .into_iter()
        .map(|(k, v)| EncodedParameter::from(v).get_str().map(|v| (k, v)))
        .collect::<io::Result<Vec<(Cow<'a, str>, Cow<str>)>>>()?;
    // join two paramters and sort by alphabetical order
    let mut payload =
        [basic_params_encoded, user_params_encoded].concat::<(Cow<'a, str>, Cow<str>)>();
    payload.sort();

    let signature = match signature_method {
        SignatureMethod::PlainText => generate_signature_plaintext(c_secret, token_secret),
        SignatureMethod::HmacSha1 => {
            generate_signature_hmacsha1(c_secret, token_secret, &http_method, &endpoint, &payload)
        }
    };
    Ok(SignedContent {
        signature,
        nonce: sampled_nonce,
        payload,
        timestamp,
    })
}

fn build_basic_params<'a>(
    consumer_key: Cow<'a, str>,
    token: Option<Cow<'a, str>>,
    signature_method: SignatureMethod,
    nonce: Cow<'a, str>,
    timestamp: i64,
    version: Option<Cow<'a, str>>,
) -> Vec<(Cow<'a, str>, Cow<'a, str>)> {
    // build authorization basic parameters
    let params = vec![
        // owned parameters
        (
            OAUTH_PARAM_KEY_TIMESTAMP,
            Some(Cow::Owned(format!("{}", timestamp))),
        ),
        // borrowed parameters
        (OAUTH_PARAM_KEY_CONSUMER_KEY, Some(consumer_key)),
        (
            OAUTH_PARAM_KEY_SIGNATURE_METHOD,
            Some(Cow::Borrowed(signature_method.into())),
        ),
        (OAUTH_PARAM_KEY_NONCE, Some(nonce)),
        // noneable borrowed parameters
        (OAUTH_PARAM_KEY_VERSION, version),
        (OAUTH_PARAM_KEY_TOKEN, token),
    ];

    return params
        .into_iter()
        // trim None value
        .filter_map(|(k, v)| v.map(|v| (Cow::from(k), percent_encode_cow(v))))
        .collect();
}

fn generate_signature_plaintext<'a>(consumer_secret: &str, token_secret: Option<&str>) -> String {
    format!("{}&{}", consumer_secret, token_secret.unwrap_or(""))
}

fn generate_signature_hmacsha1<'a>(
    consumer_secret: &str,
    token_secret: Option<&str>,
    http_method: &str,
    endpoint: &str,
    encoded_params: &Vec<(Cow<'a, str>, Cow<'a, str>)>,
) -> String {
    // prepare contents to sign -----------------------------------------------
    // preprocess parameters
    let http_method = http_method.to_ascii_uppercase();
    let encoded_params = encoded_params
        .into_iter()
        .filter(|(k, _)| k != "realm")
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<String>>()
        .join("&");
    // encode parameters
    // (get/post parameters should be encoded twice.)
    let params = percent_encode(&encoded_params);
    let http_method = percent_encode(&http_method);
    let endpoint = percent_encode(endpoint);
    // join contents to sign
    let base_str = format!("{}&{}&{}", http_method, endpoint, params);

    // prepare sign key -------------------------------------------------------
    // preprocess sign key parameters
    let token_secret = token_secret.unwrap_or("");
    // encode sign key
    let consumer_secret = percent_encode(consumer_secret);
    let token_secret = percent_encode(token_secret);
    // join keys to sign
    let sign_key = format!("{}&{}", consumer_secret, token_secret);

    // generate signature -----------------------------------------------------
    // NOTE: HmacSha1 never fails, so I use `unwrap` here.
    let mut mac = HmacSha1::new_varkey(sign_key.as_bytes()).unwrap();
    mac.input(base_str.as_bytes());
    let hash = mac.result().code();
    return base64::encode(&hash);
}

fn percent_encode_str<'a, T: Into<Cow<'a, str>>>(input: T) -> String {
    percent_encode(&(input.into())).to_string()
}

fn percent_encode_cow<'a, T: Into<Cow<'a, str>>>(input: T) -> Cow<'a, str> {
    match input.into() {
        Cow::Borrowed(r) => Cow::from(percent_encode(r)),
        Cow::Owned(v) => Cow::from(percent_encode(&v).to_string()),
    }
}

fn percent_encode<'a>(input: &'a str) -> PercentEncode<'a> {
    utf8_percent_encode(input, TARGETS_FOR_PARAMS)
}

mod test {
    use super::*;
    use crate::util;
    use crate::v1::SignatureMethod::HmacSha1;

    #[test]
    fn test_sign_rfc5849() {
        let url = url::Url::parse("https://photos.example.net/initiate").unwrap();
        let (endpoint, mut query) = util::url_to_endpoint_and_queries(&url);
        let method = "post";
        let c_key = "dpf43f3p2l4k3l03";
        let c_secret = "kd94hf93k423kf44";
        let nonce = "wIjqoS";
        let timestamp: i64 = 137_131_200;
        // setup query
        query.push(("realm", "photos"));
        query.push(("oauth_callback", "http://printer.example.com/ready"));
        let query = query;

        let sign = sign_oauthv1(
            endpoint.into(),
            method.into(),
            (c_key.into(), c_secret),
            None,
            HmacSha1,
            Some(nonce.into()),
            OAuthVersion::None,
            Some(timestamp),
            query
                .into_iter()
                .map(|(k, v)| (Cow::from(k), OAuthParameter::from(v)))
                .collect(),
        )
        .unwrap();
        println!("{:#?}", sign.signature);
        assert_eq!("74KNZJeDHnMBp0EMJ9ZHt/XKycU=", sign.signature);
    }
}
