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
const OAUTH_VERSION: &str = "1.0";

const OAUTH_HEADER: &str = "OAuth";
const OAUTH_PARAM_KEY_NONCE: &str = "oauth_nonce";
const OAUTH_PARAM_KEY_CALLBACK: &str = "oauth_callback";
const OAUTH_PARAM_KEY_SIGNATURE_METHOD: &str = "oauth_signature_method";
const OAUTH_PARAM_KEY_TIMESTAMP: &str = "oauth_timestamp";
const OAUTH_PARAM_KEY_VERSION: &str = "oauth_version";
const OAUTH_PARAM_KEY_CONSUMER_KEY: &str = "oauth_consumer_key";

/// OAuth Signature Builder
pub struct OAuthSignBuilder<TokenType> {
    oauth_consumer_key: String,
    oauth_nonce: String,
    oauth_signature_method: String,
    oauth_version: Option<String>,
    oauth_timestamp: Option<i64>,
    oauth_token: TokenType,
    encoded_parameters: HashMap<String, String>,
}

/// OAuthSignBuilder that not bound with an Access Token.
impl OAuthSignBuilder<()> {
    /// Constructor of OAuthSignBuilder with OAuth consumer_key.
    pub fn new<K: Into<String> + ?Sized>(consumer_key: K) -> Self {
        // set with default values.
        OAuthSignBuilder {
            oauth_consumer_key: consumer_key.into(),
            oauth_nonce: format!("{}", Uuid::new_v4()),
            oauth_signature_method: DEFAULT_SIGNATURE.into(),
            oauth_version: Some(OAUTH_VERSION.into()),
            oauth_timestamp: None,
            oauth_token: (),
            encoded_parameters: std::collections::HashMap::new(),
        }
    }

    /// Generate OAuth signature to specified URL.
    pub fn sign_to_url(&self, url: &url::Url, http_method: &str, consumer_secret: &str) -> String {
        let (endpoint, url_encoded_query) = util::url_to_endpoint_and_queries(url);
        self.sign_impl(
            endpoint,
            url_encoded_query,
            http_method,
            consumer_secret,
            None,
        )
    }

    /// Generate OAuth signature with specified endpoint and query.
    pub fn sign(&self, endpoint: &str, http_method: &str, consumer_secret: &str) -> String {
        self.sign_impl(endpoint, HashMap::new(), http_method, consumer_secret, None)
    }

    pub fn sign_with_query(
        &self,
        endpoint: &str,
        url_encoded_query: &str,
        http_method: &str,
        consumer_secret: &str,
    ) -> String {
        self.sign_impl(
            endpoint,
            util::query_to_hashmap(url_encoded_query),
            http_method,
            consumer_secret,
            None,
        )
    }
}

// token-installed impl
impl OAuthSignBuilder<String> {
    pub fn new_with_token(consumer_key: impl Into<String>, oauth_token: impl Into<String>) -> Self {
        // set with default values.
        OAuthSignBuilder {
            oauth_consumer_key: consumer_key.into(),
            oauth_nonce: format!("{}", Uuid::new_v4()),
            oauth_signature_method: DEFAULT_SIGNATURE.into(),
            oauth_version: Some(OAUTH_VERSION.into()),
            oauth_timestamp: None,
            oauth_token: oauth_token.into(),
            encoded_parameters: std::collections::HashMap::new(),
        }
    }

    pub fn sign_to_url(
        &self,
        url: &url::Url,
        http_method: &str,
        consumer_secret: &str,
        token_secret: &str,
    ) -> String {
        let (endpoint, url_encoded_query) = util::url_to_endpoint_and_queries(url);
        self.sign_impl(
            endpoint,
            url_encoded_query,
            http_method,
            consumer_secret,
            Some((&self.oauth_token, token_secret)),
        )
    }

    pub fn sign(
        &self,
        endpoint: &str,
        url_encoded_query: &str,
        http_method: &str,
        consumer_secret: &str,
        token_secret: &str,
    ) -> String {
        self.sign_impl(
            endpoint,
            util::query_to_hashmap(url_encoded_query),
            http_method,
            consumer_secret,
            Some((&self.oauth_token, token_secret)),
        )
    }
}

impl<TokenType> OAuthSignBuilder<TokenType> {
    pub fn oauth_nonce(&mut self, nonce: impl Into<String>) -> &mut OAuthSignBuilder<TokenType> {
        self.oauth_nonce = nonce.into();
        self
    }

    pub fn oauth_signature_method(
        &mut self,
        signature_method: impl Into<String>,
    ) -> &mut OAuthSignBuilder<TokenType> {
        self.oauth_signature_method = signature_method.into();
        self
    }

    pub fn oauth_version(
        &mut self,
        version: Option<impl Into<String>>,
    ) -> &mut OAuthSignBuilder<TokenType> {
        self.oauth_version = version.map(|v| v.into());
        self
    }

    pub fn oauth_timestamp(&mut self, timestamp: i64) -> &mut OAuthSignBuilder<TokenType> {
        self.oauth_timestamp = Some(timestamp);
        self
    }

    pub fn oauth_token(self, token: impl Into<String>) -> OAuthSignBuilder<String> {
        OAuthSignBuilder {
            oauth_consumer_key: self.oauth_consumer_key,
            oauth_nonce: self.oauth_nonce,
            oauth_signature_method: self.oauth_signature_method,
            oauth_version: self.oauth_version,
            oauth_timestamp: self.oauth_timestamp,
            oauth_token: token.into(),
            encoded_parameters: self.encoded_parameters,
        }
    }

    pub fn add_param(&mut self, key: &str, value: &str) -> &mut OAuthSignBuilder<TokenType> {
        self.encoded_parameters.insert(
            utf8_percent_encode(key, TARGETS_FOR_PARAMS).to_string(),
            utf8_percent_encode(value, TARGETS_FOR_PARAMS).to_string(),
        );
        self
    }

    pub fn add_param_encoded(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> &mut OAuthSignBuilder<TokenType> {
        self.encoded_parameters.insert(key.into(), value.into());
        self
    }

    /// Encode the parameter (core method).
    ///
    /// # Parameters
    /// - endpoint: access endpoint.
    /// - url_encoded_query: query on the URL, must be encoded.
    /// - http_method: HTTP method, ex)"GET", "POST", ...
    /// - consumer_secret: consumer secret key.
    /// - token_and_secret: access token and secret.
    /// # Returns
    /// authorization signature (not encoded).
    /// # Note
    /// all of parameters except of url_encoded_query should be URL encoded.
    fn sign_impl(
        &self,
        endpoint: &str,
        url_encoded_query: HashMap<&str, &str>,
        http_method: &str,
        consumer_secret: &str,
        token_and_secret: Option<(&str, &str)>,
    ) -> String {
        // destructuring token and secret
        let (token, token_secret) = token_and_secret
            .map(|(t, s)| (Some(t), Some(s)))
            .unwrap_or((None, None));

        // build authorization basic parameters
        let timestamp = format!(
            "{}",
            self.oauth_timestamp
                .unwrap_or_else(|| Utc::now().timestamp())
        );
        let mut basic_params = vec![
            ("oauth_consumer_key", &self.oauth_consumer_key),
            ("oauth_signature_method", &self.oauth_signature_method),
            ("oauth_timestamp", &timestamp),
            ("oauth_nonce", &self.oauth_nonce),
        ];
        if let Some(oauth_version) = &self.oauth_version {
            basic_params.push(("oauth_version", oauth_version));
        }
        let stringify_token = token.map(|t| t.to_string());
        if let Some(oauth_token) = &stringify_token {
            basic_params.push(("oauth_token", &oauth_token));
        }
        let basic_params = basic_params
            .iter()
            .map(|(k, v)| {
                (
                    utf8_percent_encode(&k, TARGETS_FOR_PARAMS),
                    utf8_percent_encode(&v, TARGETS_FOR_PARAMS),
                )
            })
            .map(|(k, v)| (Cow::from(k), Cow::from(v)))
            .collect::<Vec<(Cow<str>, Cow<str>)>>();
        let query_params = url_encoded_query
            .iter()
            .map(|(&k, &v)| (Cow::from(k), Cow::from(v)))
            .collect::<Vec<(Cow<str>, Cow<str>)>>();
        let post_params = self
            .encoded_parameters
            .iter()
            .map(|(k, v)| (Cow::from(k), Cow::from(v)))
            .collect::<Vec<(Cow<str>, Cow<str>)>>();

        // join above three parameters
        let mut params = [basic_params, query_params, post_params].concat::<(Cow<str>, Cow<str>)>();

        // then, alphabetic sort by key
        params.sort();

        // create signature string to sign
        let param_str = params
            .iter()
            .filter(|(k, _)| k != "realm") // "realm" is a special parameter
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("&");
        // println!("param: {:#?}", param_str);

        // create signature to sign
        let http_method = http_method.to_ascii_uppercase();
        let encoded_http_method = utf8_percent_encode(&http_method, TARGETS_FOR_PARAMS);
        let encoded_endpoint = utf8_percent_encode(endpoint, TARGETS_FOR_PARAMS);
        let encoded_params = utf8_percent_encode(&param_str, TARGETS_FOR_PARAMS);
        let base_str = format!(
            "{}&{}&{}",
            encoded_http_method, encoded_endpoint, encoded_params
        );
        // println!("base: {:#?}", base_str);

        // create sign key
        let token_secret = token_secret.unwrap_or("");
        let encoded_cs = utf8_percent_encode(consumer_secret, TARGETS_FOR_PARAMS);
        let encoded_ts = utf8_percent_encode(token_secret, TARGETS_FOR_PARAMS);
        let sign_key = format!("{}&{}", encoded_cs, encoded_ts);
        // println!("sign_key: {:#?}", sign_key);

        // generate sign
        let mut mac = HmacSha1::new_varkey(sign_key.as_bytes())
            .expect("this message is dummy; SHA-1 accepts any size of keys.");
        mac.input(base_str.as_bytes());
        let hash = mac.result().code();
        base64::encode(&hash)
    }
}

#[test]
fn test_builder() {
    let builder = OAuthSignBuilder::new("ck")
        .add_param("param1", "value1_ud_plus+hy-qu'dq\"1-9!@#$%^&*()_+-NS=[]");
}

#[test]
fn test_signing() {
    // https://developer.twitter.com/ja/docs/basics/authentication/guides/creating-a-signature
    let endpoint = url::Url::parse("https://api.twitter.com/1.1/statuses/update.json").unwrap();
    let method = "post";
    let c_key = "xvz1evFS4wEEPTGEFPHBog";
    let c_secret = "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw";
    let nonce = "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg";
    let timestamp = 1_318_622_958;
    let token = "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb";
    let token_secret = "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE";
    let sign = OAuthSignBuilder::new_with_token(c_key, token)
        .oauth_nonce(nonce)
        .oauth_timestamp(timestamp)
        .add_param("include_entities", "true")
        .add_param(
            "status",
            "Hello Ladies + Gentlemen, a signed OAuth request!",
        )
        .sign_to_url(&endpoint, method, c_secret, token_secret);
    println!("{:#?}", sign);
    assert_eq!(sign, "hCtSmYh+iHYCEqBWrE7C7hYmtUk=");

    // https://tools.ietf.org/html/rfc5849
    let endpoint = url::Url::parse("https://photos.example.net/initiate").unwrap();
    let method = "post";
    let c_key = "dpf43f3p2l4k3l03";
    let c_secret = "kd94hf93k423kf44";
    let nonce = "wIjqoS";
    let timestamp = 137_131_200;

    let sign = OAuthSignBuilder::new(c_key)
        .oauth_nonce(nonce)
        .oauth_version(None as Option<String>)
        .oauth_timestamp(timestamp)
        .add_param("realm", "photos")
        .add_param("oauth_callback", "http://printer.example.com/ready")
        .sign_to_url(&endpoint, method, c_secret);
    println!("{:#?}", sign);
    assert_eq!(sign, "74KNZJeDHnMBp0EMJ9ZHt/XKycU=");
}
