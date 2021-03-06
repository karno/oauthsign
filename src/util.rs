pub fn url_to_endpoint_and_queries(url: &url::Url) -> (&str, Vec<(&str, &str)>) {
    // queries save into hashmap.
    let vec = match url.query() {
        Some(query) => destructure_query(query),
        None => Vec::new(),
    };
    let body = url.as_str().split('?').next();
    (body.unwrap_or_else(|| url.as_str()), vec)
}

pub fn destructure_query(query: &str) -> Vec<(&str, &str)> {
    query
        .trim_start_matches('?')
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|s| s.splitn(2, '=').collect::<Vec<&str>>())
        .filter(|v| v.len() == 2)
        .map(|v| (v[0], v[1]))
        .collect()
}

mod test {

    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_url_to_endpoint_and_queries() {
        let s = "http://example.com/example+.html?quever?=salting=parsing&&&&&vir!@$========%^&*()_=askparity++++==&パラメータ=テストパラメータ";
        let u = url::Url::parse(s).unwrap();
        let (core, vec) = url_to_endpoint_and_queries(&u);
        let map: HashMap<&str, &str> = vec.into_iter().collect();
        assert_eq!(core, "http://example.com/example+.html");
        assert_eq!(map["quever?"], "salting=parsing");
        assert_eq!(map["vir!@$"], "=======%^");
        assert_eq!(map["*()_"], "askparity++++==");
        assert_eq!(
            map["%E3%83%91%E3%83%A9%E3%83%A1%E3%83%BC%E3%82%BF"],
            "%E3%83%86%E3%82%B9%E3%83%88%E3%83%91%E3%83%A9%E3%83%A1%E3%83%BC%E3%82%BF"
        );
        let n = "https://example.com/";
        let nu = url::Url::parse(n).unwrap();
        let (core, map2) = url_to_endpoint_and_queries(&nu);
        assert_eq!(core, n);
        assert_eq!(map2.len(), 0);
    }
    #[test]
    fn test_query_to_hashmap() {
        let map = destructure_query(
            "parameter=value&!%40%23%24%25^%26*()_%2B=!%40%23%24%25^%26*()_%2B%3D",
        )
        .into_iter()
        .collect::<HashMap<&str, &str>>();
        assert_eq!(map.len(), 2);
        assert_eq!(map["parameter"], "value");
        assert_eq!(
            map["!%40%23%24%25^%26*()_%2B"],
            "!%40%23%24%25^%26*()_%2B%3D"
        );
        let map2 =
            destructure_query("quever?=salting=parsing&&&&&vir!@$========%^&*()_=askparity++++==")
                .into_iter()
                .collect::<HashMap<&str, &str>>();
        assert_eq!(map2.len(), 3);
        assert_eq!(map2["quever?"], "salting=parsing");
        assert_eq!(map2["vir!@$"], "=======%^");
        assert_eq!(map2["*()_"], "askparity++++==");
        let map3 = destructure_query("");
        assert_eq!(map3.len(), 0);
    }
}
