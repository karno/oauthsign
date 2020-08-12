use crate::v1;

/// OAuth V1 Signature Generator
pub struct OAuthV1Client<T> {
    oauth_token: T,
    oauth_consumer_key: String,
    oauth_nonce: String,
    oauth_signature_method: String,
    oauth_version: Option<String>,
    oauth_timestamp: Option<i64>,
}
