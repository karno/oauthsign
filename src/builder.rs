use crate::parameters::OAuthParameter;
use core::marker::PhantomData;
use std::borrow::Cow;

pub trait OAuthSigner<'a, TSecret, TSigned> {
    fn sign(self, param: Vec<(Cow<'a, str>, OAuthParameter<'a>)>, secret: &TSecret) -> TSigned;
}

pub struct OAuthSignBuilder<'a, TSigner, TSecret, TSigned>
where
    TSigner: OAuthSigner<'a, TSecret, TSigned>,
{
    oauth_signer: TSigner,
    parameters: Vec<(Cow<'a, str>, OAuthParameter<'a>)>,
    phantom_secret: PhantomData<TSecret>,
    phantom_signed: PhantomData<TSigned>,
}

impl<'a, TSigner, TSecret, TSigned> OAuthSignBuilder<'a, TSigner, TSecret, TSigned>
where
    TSigner: OAuthSigner<'a, TSecret, TSigned>,
{
    fn new(signer: TSigner) -> Self {
        OAuthSignBuilder {
            oauth_signer: signer,
            parameters: Vec::new(),
            phantom_secret: PhantomData::<TSecret>,
            phantom_signed: PhantomData::<TSigned>,
        }
    }

    fn param<T: Into<Cow<'a, str>>>(&mut self, key: T, value: OAuthParameter<'a>) -> &mut Self {
        self.parameters.push((key.into(), value));
        self
    }

    fn param_file<T: Into<Cow<'a, str>>>(&mut self, key: T, path: &'a str) -> &mut Self {
        self.parameters
            .push((key.into(), OAuthParameter::<'a>::from_file(path)));
        self
    }

    fn param_bytes<TKey: Into<Cow<'a, str>>, TName: Into<Cow<'a, str>>>(
        &mut self,
        key: TKey,
        name: TName,
        bytes: &'a [u8],
    ) -> &mut Self {
        self.parameters.push((
            key.into(),
            OAuthParameter::<'a>::from_bytes(name.into(), bytes),
        ));
        self
    }

    fn sign(self, secrets: &TSecret) -> TSigned {
        self.oauth_signer.sign(self.parameters, secrets)
    }
}
