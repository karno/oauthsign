pub mod v1;
pub mod v1a;
pub mod v2;

mod util;

use serde::Serialize;

pub trait OAuthSignBuilder {
    fn query<T: Serialize + ?Sized>(self, query: T) -> Self;

    fn query_pair<K: Into<String> + ?Sized, V: Into<String> + ?Sized>(
        self,
        key: K,
        value: V,
    ) -> Self {
        self.query(&[(key.into(), value.into())])
    }
}
