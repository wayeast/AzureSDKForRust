use azure_sdk_core::{
    errors::AzureError,
    headers,
    util::{format_header_value, HeaderMapExt, RequestBuilderExt},
};
use base64;
use chrono;
use hyper::{self, header, HeaderMap, Method};
use hyper_rustls::HttpsConnector;
use ring::{digest::SHA256, hmac};
use std::fmt::Write;
use url;

#[derive(Debug, Clone, Copy)]
pub enum ServiceType {
    Blob,
    // Queue, File,
    Table,
}

const AZURE_VERSION: &str = "2018-03-28";

pub const HEADER_VERSION: &str = "x-ms-version"; //=> [String] }
pub const HEADER_DATE: &str = "x-ms-date"; //=> [String] }

fn generate_authorization(h: &HeaderMap, u: &url::Url, method: &Method, hmac_key: &str, service_type: ServiceType) -> String {
    let str_to_sign = string_to_sign(h, u, method, service_type);

    // debug!("\nstr_to_sign == {:?}\n", str_to_sign);
    // debug!("str_to_sign == {}", str_to_sign);

    let auth = encode_str_to_sign(&str_to_sign, hmac_key);
    // debug!("auth == {:?}", auth);

    format!("SharedKey {}:{}", get_account(u), auth)
}

fn encode_str_to_sign(str_to_sign: &str, hmac_key: &str) -> String {
    let key = hmac::SigningKey::new(&SHA256, &base64::decode(hmac_key).unwrap());
    let sig = hmac::sign(&key, str_to_sign.as_bytes());

    // let res = hmac.result();
    // debug!("{:?}", res.code());

    base64::encode(sig.as_ref())
}

#[inline]
fn add_if_exists<K: header::AsHeaderName>(h: &HeaderMap, key: K) -> &str {
    match h.get(key) {
        Some(ce) => ce.to_str().unwrap(),
        None => "",
    }
}

#[allow(unknown_lints)]
fn string_to_sign(h: &HeaderMap, u: &url::Url, method: &Method, service_type: ServiceType) -> String {
    match service_type {
        ServiceType::Table => {
            let mut s = String::new();
            write!(
                s,
                "{}\n{}\n{}\n{}\n{}",
                method.as_str(),
                add_if_exists(h, headers::CONTENT_MD5),
                add_if_exists(h, header::CONTENT_TYPE),
                add_if_exists(h, HEADER_DATE),
                canonicalized_resource_table(u)
            )
            .unwrap();
            s
        }
        _ => {
            // content lenght must only be specified if != 0
            // this is valid from 2015-02-21
            let cl = h
                .get_as_str(header::CONTENT_LENGTH)
                .map(|s| if s == "0" { "" } else { s })
                .unwrap_or("");
            let mut s = String::new();
            write!(
                s,
                "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}{}",
                method.as_str(),
                add_if_exists(h, header::CONTENT_ENCODING),
                add_if_exists(h, header::CONTENT_LANGUAGE),
                cl,
                add_if_exists(h, headers::CONTENT_MD5),
                add_if_exists(h, header::CONTENT_TYPE),
                add_if_exists(h, header::DATE),
                add_if_exists(h, header::IF_MODIFIED_SINCE),
                add_if_exists(h, header::IF_MATCH),
                add_if_exists(h, header::IF_NONE_MATCH),
                add_if_exists(h, header::IF_UNMODIFIED_SINCE),
                add_if_exists(h, header::RANGE),
                canonicalize_header(h),
                canonicalized_resource(u)
            )
            .unwrap();
            s
        }
    }

    // expected
    // GET\n /*HTTP Verb*/
    // \n    /*Content-Encoding*/
    // \n    /*Content-Language*/
    // \n    /*Content-Length (include value when zero)*/
    // \n    /*Content-MD5*/
    // \n    /*Content-Type*/
    // \n    /*Date*/
    // \n    /*If-Modified-Since */
    // \n    /*If-Match*/
    // \n    /*If-None-Match*/
    // \n    /*If-Unmodified-Since*/
    // \n    /*Range*/
    // x-ms-date:Sun, 11 Oct 2009 21:49:13 GMT\nx-ms-version:2009-09-19\n
    //                                  /*CanonicalizedHeaders*/
    // /myaccount /mycontainer\ncomp:metadata\nrestype:container\ntimeout:20
    //                                  /*CanonicalizedResource*/
    //
    //
}

fn canonicalize_header(h: &HeaderMap) -> String {
    let mut v_headers = h
        .iter()
        .filter(|(k, _v)| k.as_str().starts_with("x-ms"))
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>();
    v_headers.sort();

    let mut can = String::new();

    for header_name in v_headers {
        let s = h.get_as_str(header_name).unwrap();
        can = can + header_name + ":" + s + "\n";
    }
    can
}

#[inline]
fn get_account(u: &url::Url) -> &str {
    match u.host().unwrap().clone() {
        url::Host::Domain(dm) => {
            // debug!("dom == {:?}", dm);

            let first_dot = dm.find('.').unwrap();
            &dm[0..first_dot]
        }
        url::Host::Ipv4(_) => {
            // this must be the emulator
            "devstoreaccount1"
        }
        _ => panic!("only Domains are supported in canonicalized_resource"),
    }
}

// For table
fn canonicalized_resource_table(u: &url::Url) -> String {
    format!("/{}{}", get_account(u), u.path())
}

fn canonicalized_resource(u: &url::Url) -> String {
    let mut can_res: String = String::new();
    can_res += "/";

    let account = get_account(u);
    can_res += &account;

    let paths = u.path_segments().unwrap();

    {
        let mut path = String::new();
        for p in paths {
            path.push_str("/");
            path.push_str(&*p);
        }

        can_res += &path;
    }
    can_res += "\n";

    // query parameters
    let query_pairs = u.query_pairs(); //.into_owned();
    {
        let mut qps = Vec::new();
        {
            for qp in query_pairs {
                trace!("adding to qps {:?}", qp);

                // add only once
                if !(qps.iter().any(|x: &String| x == &qp.0)) {
                    qps.push(qp.0.into_owned());
                }
            }
        }

        qps.sort();

        for qparam in qps {
            // find correct parameter
            let ret = lexy_sort(&query_pairs, &qparam);

            // debug!("adding to can_res {:?}", ret);

            can_res = can_res + &qparam.to_lowercase() + ":";

            for (i, item) in ret.iter().enumerate() {
                if i > 0 {
                    can_res += ","
                }
                can_res += item;
            }

            can_res += "\n";
        }
    };

    can_res[0..can_res.len() - 1].to_owned()
}

fn lexy_sort(vec: &url::form_urlencoded::Parse, query_param: &str) -> Vec<(String)> {
    let mut v_values: Vec<String> = Vec::new();

    for item in vec.filter(|x| x.0 == *query_param) {
        v_values.push(item.1.into_owned())
    }
    v_values.sort();

    v_values
}

#[allow(unknown_lints)]
pub fn perform_request<F>(
    client: &hyper::Client<HttpsConnector<hyper::client::HttpConnector>>,
    uri: &str,
    http_method: &Method,
    azure_key: &str,
    headers_func: F,
    request_body: Option<&[u8]>,
    service_type: ServiceType,
) -> Result<hyper::client::ResponseFuture, AzureError>
where
    F: FnOnce(&mut ::http::request::Builder),
{
    let dt = chrono::Utc::now();
    let time = format!("{}", dt.format("%a, %d %h %Y %T GMT"));

    let url = url::Url::parse(uri)?;

    // for header in additional_headers.iter() {
    //     debug!("{:?}", header.value_string());
    //     h.set();
    // }
    let mut request = hyper::Request::builder();
    request.method(http_method.clone()).uri(uri);

    // let's add content length to avoid "chunking" errors.
    match request_body {
        Some(ref b) => request.header(header::CONTENT_LENGTH, &b.len().to_string() as &str),
        None => request.header_static(header::CONTENT_LENGTH, "0"),
    };

    // This will give the caller the ability to add custom headers.
    // The closure is needed to because request.headers_mut().set_raw(...) requires
    // a Cow with 'static lifetime...
    headers_func(&mut request);

    request.header_bytes(HEADER_DATE, time).header_static(HEADER_VERSION, AZURE_VERSION);

    let b = request_body.map(|v| Vec::from(v).into()).unwrap_or_else(hyper::Body::empty);
    let mut request = request.body(b)?;

    // We sign the request only if it is not already signed (with the signature of an
    // SAS token for example)
    if url.query_pairs().find(|p| p.0 == "sig").is_none() {
        let auth = generate_authorization(request.headers(), &url, http_method, azure_key, service_type);
        request.headers_mut().insert(header::AUTHORIZATION, format_header_value(auth)?);
    }

    Ok(client.request(request))
}

#[inline]
pub fn get_default_json_mime() -> &'static str {
    "application/json; charset=utf-8"
}

#[inline]
pub fn get_json_mime_nometadata() -> &'static str {
    "application/json; odata=nometadata"
}

mod test {
    extern crate chrono;
    extern crate hyper;
    extern crate url;

    #[test]
    fn test_canonicalize_header() {
        use super::*;

        let dt = chrono::DateTime::parse_from_rfc2822("Fri, 28 Nov 2014 21:00:09 +0900").unwrap();
        let time = format!("{}", dt.format("%a, %d %h %Y %T GMT%Z"));

        println!("time == {}", time);

        let mut h = hyper::header::HeaderMap::new();

        h.insert(HEADER_DATE, format_header_value(time).unwrap());
        h.insert(HEADER_VERSION, header::HeaderValue::from_static("2015-04-05"));

        assert_eq!(
            super::canonicalize_header(&h),
            "x-ms-date:Fri, 28 Nov 2014 21:00:09 GMT+09:00\nx-ms-version:2015-04-05\n"
        );
    }

    #[test]
    fn str_to_sign_test() {
        use super::*;

        let mut headers: HeaderMap = HeaderMap::new();
        headers.insert(header::ACCEPT, header::HeaderValue::from_static(get_json_mime_nometadata()));
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static(get_default_json_mime()));

        let u: url::Url = url::Url::parse("https://mindrust.table.core.windows.net/TABLES").unwrap();
        let method: Method = Method::POST;
        let service_type: ServiceType = ServiceType::Table;

        let dt = chrono::DateTime::parse_from_rfc2822("Wed,  3 May 2017 14:04:56 +0000").unwrap();
        let time = format!("{}", dt.format("%a, %d %h %Y %T GMT"));

        headers.insert(HEADER_DATE, format_header_value(time).unwrap());
        headers.insert(HEADER_VERSION, header::HeaderValue::from_static(AZURE_VERSION));

        let s = string_to_sign(&headers, &u, &method, service_type);

        assert_eq!(
            s,
            "POST

application/json; charset=utf-8
Wed, 03 May 2017 14:04:56 GMT
/mindrust/TABLES"
        );
    }

    #[test]
    fn test_canonicalize_resource_10() {
        let url = url::Url::parse("https://mindrust.table.core.windows.net/TABLES").unwrap();
        assert_eq!(super::canonicalized_resource(&url), "/mindrust/TABLES");
    }

    #[test]
    fn test_canonicalize_resource_1() {
        let url = url::Url::parse(
            "http://myaccount.blob.core.windows.\
             net/mycontainer?restype=container&comp=metadata",
        )
        .unwrap();
        assert_eq!(
            super::canonicalized_resource(&url),
            "/myaccount/mycontainer\ncomp:metadata\nrestype:container"
        );
    }

    #[test]
    fn test_canonicalize_resource_2() {
        let url = url::Url::parse(
            "http://myaccount.blob.core.windows.\
             net/mycontainer?restype=container&comp=list&include=snapshots&\
             include=metadata&include=uncommittedblobs",
        )
        .unwrap();
        assert_eq!(
            super::canonicalized_resource(&url),
            "/myaccount/mycontainer\ncomp:list\ninclude:metadata,snapshots,\
             uncommittedblobs\nrestype:container"
        );
    }

    #[test]
    fn test_canonicalize_resource_3() {
        let url = url::Url::parse(
            "https://myaccount-secondary.blob.core.windows.\
             net/mycontainer/myblob",
        )
        .unwrap();
        assert_eq!(super::canonicalized_resource(&url), "/myaccount-secondary/mycontainer/myblob");
    }

    #[test]
    fn test_encode_str_to_sign_1() {
        let str_to_sign = "53d7e14aee681a00340300032015-01-01T10:00:00.0000000".to_owned();
        let hmac_key = "pXeTVaaaaU9XxH6fPcPlq8Y9D9G3Cdo5Eh2nMSgKj/DWqeSFFXDdmpz5Trv+L2hQNM+nGa704R\
                        f8Z22W9O1jdQ=="
            .to_owned();

        assert_eq!(
            super::encode_str_to_sign(&str_to_sign, &hmac_key),
            "gZzaRaIkvC9jYRY123tq3xXZdsMAcgAbjKQo8y0p0Fs=".to_owned()
        );
    }

    #[test]
    fn test_encode_str_to_sign_2() {
        let str_to_sign = "This is the data to sign".to_owned();
        let hmac_key = "pXeTVaaaaU9XxH6fPcPlq8Y9D9G3Cdo5Eh2nMSgKj/DWqeSFFXDdmpz5Trv+L2hQNM+nGa704R\
                        f8Z22W9O1jdQ=="
            .to_owned();

        assert_eq!(
            super::encode_str_to_sign(&str_to_sign, &hmac_key),
            "YuKoXELO9M9HXeeGaSXBr4Nk+CgPAEQhcwJ6tVtBRCw=".to_owned()
        );
    }

    #[test]
    fn test_encode_str_to_sign_3() {
        let str_to_sign = "This is the data to sign".to_owned();
        let hmac_key = "pXeTVaaaaU9XxH6fPcPlq8Y9D9G3Cdo5Eh2nMSgKj/DWqeSFFXDdmpz5Trv+L2hQNM+nGa704R\
                        f8Z22W9O1jdQ=="
            .to_owned();

        assert_eq!(
            super::encode_str_to_sign(&str_to_sign, &hmac_key),
            "YuKoXELO9M9HXeeGaSXBr4Nk+CgPAEQhcwJ6tVtBRCw=".to_owned()
        );
    }
}
