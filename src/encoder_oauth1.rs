use hmac::Hmac;
use percent_encoding::{utf8_percent_encode, AsciiSet};
use sha1::Sha1;

type HmacSha1 = Hmac<Sha1>;

type Params<'a> = std::collections::HashMap<&'a str, &'a str>;

const ENC_TARGET_FOR_SIGN: &AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'*')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_');
