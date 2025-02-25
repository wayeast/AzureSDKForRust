use crate::{enumerations::ParsingError, range::ParseError};
use base64;
use chrono;
use futures::future::{done, err, ok, Either};
use futures::{Future, Stream};
use http;
use http::header::ToStrError;
use hyper::{self, Body, StatusCode};
use serde_json;
use serde_xml_rs;
use std;
use std::io::Error as IOError;
use std::num;
use std::num::ParseIntError;
use std::str;
use std::str::ParseBoolError;
use std::string;
use url::ParseError as URLParseError;
use uuid;
use xml::BuilderError as XMLError;

quick_error! {
    #[derive(Debug)]
     pub enum AzurePathParseError {
        PathSeparatorNotFoundError {
            display("Path separator not found")
        }
        MultiplePathSeparatorsFoundError {
            display("Multiple path separators found")
        }
        MissingContainerError {
            display("Missing container name")
        }
        MissingBlobError {
            display("Missing blob name")
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct UnexpectedHTTPResult {
    expected: StatusCode,
    received: StatusCode,
    body: String,
}

impl UnexpectedHTTPResult {
    pub fn new(expected: StatusCode, received: StatusCode, body: &str) -> UnexpectedHTTPResult {
        UnexpectedHTTPResult {
            expected,
            received,
            body: body.to_owned(),
        }
    }

    pub fn status_code(&self) -> StatusCode {
        self.received
    }
}

impl std::fmt::Display for UnexpectedHTTPResult {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Unexpected HTTP result (expected: {}, received: {})",
            self.expected, self.received
        )
    }
}

impl std::error::Error for UnexpectedHTTPResult {
    fn description(&self) -> &str {
        "Unexpected HTTP result"
    }

    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum Not512ByteAlignedError {
        StartRange(u: u64) {
            display("start range not 512-byte aligned: {}", u)
        }
        EndRange(u: u64) {
            display("end range not 512-byte aligned: {}", u)
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum Parse512AlignedError {
        SplitNotFound {
            display("split not found")
        }
        ParseIntError(p :ParseIntError) {
            from()
            display("parse int error: {}", p)
            cause(p)
        }
        Not512ByteAlignedError(nb: Not512ByteAlignedError)  {
            from()
            display("not 512 byte aligned error: {}", nb)
            cause(nb)
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum AzureError {
        PageNot512ByteAlignedError(start: u64, end: u64) {
            display("{}-{} is not 512 byte aligned", start, end)
        }
         Not512ByteAlignedError(size: u64) {
            display("{} is not 512 byte aligned", size)
        }
        Base64DecodeError(err: base64::DecodeError) {
            from()
            display("base64 decode error: {}", err)
            cause(err)
        }
        DigestNot16BytesLong(len : u64) {
            display("digest length {} bytes instead of 16", len)
        }
        ParseBoolError(err: ParseBoolError) {
            from()
            display("parse bool error: {}", err)
            cause(err)
        }
        ToStrError(err: ToStrError) {
            from()
            display("to str error: {}", err)
            cause(err)
        }
        JSONError(err: serde_json::Error) {
            from()
            display("json error: {}", err)
            cause(err)
        }
        HyperError(err: hyper::error::Error){
            from()
            display("Hyper error: {}", err)
            cause(err)
        }
        IOError(err: IOError){
            from()
            display("IO error: {}", err)
            cause(err)
        }
        XMLError(err: XMLError){
            from()
            display("XML error: {}", err)
            cause(err)
        }
        UnexpectedXMLError(err: String) {
            display("UnexpectedXMLError: {}", err)
        }
        AzurePathParseError(err: AzurePathParseError){
            from()
            display("Azure Path parse error: {}", err)
            cause(err)
        }
        UnexpectedHTTPResult(err: UnexpectedHTTPResult){
            from()
            display("UnexpectedHTTPResult error")
        }
        HeaderNotFound(msg: String) {
            display("Header not found: {}", msg)
        }
        ResponseParsingError(err: TraversingError){
            from()
            display("Traversing error: {}", err)
            cause(err)
        }
        ParseIntError(err: num::ParseIntError){
            from()
            display("Parse int error: {}", err)
            cause(err)
        }
        ParseError(err: ParseError){
            from()
            display("Parse error")
        }
        GenericError
        GenericErrorWithText(err: String) {
            display("Generic error: {}", err)
        }
        ParsingError(err: ParsingError){
            from()
            display("Parsing error")
        }
        InputParametersError(msg: String) {
            display("Input parameters error: {}", msg)
        }
        URLParseError(err: URLParseError){
            from()
            display("URL parse error: {}", err)
            cause(err)
        }
        HttpPrepareError(err: http::Error) {
            from()
            display("Error preparing HTTP request: {}", err) // todo: revisit usages / message here
            cause(err)
        }
        ParseUuidError(err: uuid::parser::ParseError){
            from()
            display("Parse uuid error: {}", err)
            cause(err)
        }
        // URIParseError(err: hyper::error::UriError) {
        //     from()
        //     display("URI parse error: {}", err)
        //     cause(err)
        // }
        ChronoParserError(err: chrono::ParseError) {
            from()
            display("Chrono parser error: {}", err)
            cause(err)
        }
        UTF8Error(err: str::Utf8Error) {
            from()
            display("UTF8 conversion error: {}", err)
            cause(err)
        }
        FromUtf8Error(err: string::FromUtf8Error) {
            from()
            display("FromUTF8 error: {}", err)
            cause(err)
        }
        SerdeXMLDeserializationError(err:serde_xml_rs::Error) {
            from()
            display("XML deserialization error: {}", err)
            cause(err)
        }
        MissingHeaderError(header: String) {
            display("A required header is missing: {}", header)
        }
    }
}

quick_error! {
    #[derive(Debug)]
    pub enum TraversingError {
        PathNotFound(msg: String) {
            display("Path not found: {}", msg)
        }
        MultipleNode(msg: String) {
            display("Multiple node: {}", msg)
        }
        EnumerationNotMatched(msg: String) {
            display("Enumeration not matched: {}", msg)
        }
        BooleanNotMatched(s: String) {
            display("Input string cannot be converted in boolean: {}", s)
        }
        UnexpectedNodeTypeError(expected: String) {
            display("Unexpected node type received: expected {}", expected)
        }
        DateTimeParseError(err: chrono::format::ParseError){
            from()
            display("DateTime parse error: {}", err)
            cause(err)
        }
        TextNotFound
        ParseIntError(err: num::ParseIntError){
            from()
            display("Parse int error: {}", err)
            cause(err)
        }
        GenericParseError(msg: String) {
            display("Generic parse error: {}", msg)
        }
        ParsingError(err: ParsingError){
            from()
            display("Parsing error: {:?}", err)
        }
   }
}

impl From<()> for AzureError {
    fn from(_: ()) -> AzureError {
        AzureError::GenericError
    }
}

#[inline]
pub fn extract_status_headers_and_body(
    resp: hyper::client::ResponseFuture,
) -> impl Future<Item = (hyper::StatusCode, hyper::HeaderMap, hyper::Chunk), Error = AzureError> {
    resp.from_err().and_then(|res| {
        let (head, body) = res.into_parts();
        let status = head.status;
        let headers = head.headers;
        body.concat2().from_err().and_then(move |body| Ok((status, headers, body)))
    })
}

#[inline]
pub fn check_status_extract_headers_and_body(
    resp: hyper::client::ResponseFuture,
    expected_status_code: hyper::StatusCode,
) -> impl Future<Item = (hyper::HeaderMap, hyper::Chunk), Error = AzureError> {
    extract_status_headers_and_body(resp).and_then(move |(status, headers, body)| {
        if status == expected_status_code {
            Ok((headers, body))
        } else {
            Err(AzureError::UnexpectedHTTPResult(UnexpectedHTTPResult {
                expected: expected_status_code,
                received: status,
                body: str::from_utf8(&body)?.to_owned(),
            }))
        }
    })
}

#[inline]
pub fn check_status_extract_headers_and_body_as_string(
    resp: hyper::client::ResponseFuture,
    expected_status_code: hyper::StatusCode,
) -> impl Future<Item = (hyper::HeaderMap, String), Error = AzureError> {
    check_status_extract_headers_and_body(resp, expected_status_code).and_then(move |(headers, body)| {
        let body = str::from_utf8(&body)?.to_owned();
        Ok((headers, body))
    })
}

#[inline]
pub fn extract_status_and_body(resp: hyper::client::ResponseFuture) -> impl Future<Item = (StatusCode, String), Error = AzureError> {
    resp.from_err().and_then(|res| {
        let status = res.status();
        res.into_body()
            .concat2()
            .from_err()
            .and_then(move |body| Ok((status, str::from_utf8(&body)?.to_owned())))
    })
}

#[inline]
pub fn check_status_extract_body(
    resp: hyper::client::ResponseFuture,
    expected_status_code: hyper::StatusCode,
) -> impl Future<Item = String, Error = AzureError> {
    extract_status_and_body(resp).and_then(move |(status, body)| {
        if status == expected_status_code {
            Ok(body)
        } else {
            Err(AzureError::UnexpectedHTTPResult(UnexpectedHTTPResult {
                expected: expected_status_code,
                received: status,
                body,
            }))
        }
    })
}

pub fn check_status_extract_body_2(
    resp: hyper::Response<Body>,
    expected_status: StatusCode,
) -> impl Future<Item = String, Error = AzureError> {
    let received_status = resp.status();

    resp.into_body().concat2().from_err().and_then(move |body| {
        done(String::from_utf8(body.to_vec())).from_err().and_then(move |s| {
            println!("body: {}", s);
            if received_status != expected_status {
                Either::A(
                    err(AzureError::UnexpectedHTTPResult(UnexpectedHTTPResult {
                        expected: expected_status,
                        received: received_status,
                        body: s,
                    }))
                    .from_err(),
                )
            } else {
                Either::B(ok(s))
            }
        })
    })
}
