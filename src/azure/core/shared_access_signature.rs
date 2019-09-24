use super::COMPLETE_ENCODE_SET;
use base64::{decode, encode};
use chrono::{DateTime, Duration, Utc};
use hmac_sha256::HMAC;
use std::fmt;
use url::percent_encoding::{
    DEFAULT_ENCODE_SET,
    utf8_percent_encode,
};

#[derive(Copy, Clone)]
pub enum SasVersion {
    V20181109,
    V20150405,
    V20130815,
    V20120212,
}

impl fmt::Display for SasVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SasVersion::V20181109 => write!(f, "2018-11-09"),
            SasVersion::V20150405 => write!(f, "2015-04-05"),
            SasVersion::V20130815 => write!(f, "2013-08-15"),
            SasVersion::V20120212 => write!(f, "2012-02-12"),
        }
    }
}

#[derive(Copy, Clone)]
pub enum SasService {
    Blob,
    Queue,
    Table,
    File,
}

impl fmt::Display for SasService {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SasService::Blob => write!(f, "b"),
            SasService::Queue => write!(f, "q"),
            SasService::Table => write!(f, "t"),
            SasService::File => write!(f, "f"),
        }
    }
}

#[derive(Copy, Clone)]
pub enum SasProtocol {
    Https,
    HttpHttps,
}

impl fmt::Display for SasProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SasProtocol::Https => write!(f, "https"),
            SasProtocol::HttpHttps => write!(f, "http,https"),
        }
    }
}

#[derive(Copy, Clone)]
pub enum SasResource {
    Blob,
    Queue,
    Table,
    File,
}

impl fmt::Display for SasResource {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SasResource::Blob => write!(f, "b"),
            SasResource::Queue => write!(f, "q"),
            SasResource::Table => write!(f, "t"),
            SasResource::File => write!(f, "f"),
        }
    }
}

#[derive(Copy, Clone)]
pub enum SasResourceType {
    Service,
    Container,
    Object,
}

impl fmt::Display for SasResourceType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SasResourceType::Service => write!(f, "s"),
            SasResourceType::Container => write!(f, "c"),
            SasResourceType::Object => write!(f, "o"),
        }
    }
}

#[derive(Copy, Clone)]
pub enum SasPermissions {
    Read,
    Write,
    Delete,
    List,
    Add,
    Create,
    Update,
    Process,
}

impl fmt::Display for SasPermissions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SasPermissions::Read => write!(f, "r"),
            SasPermissions::Write => write!(f, "w"),
            SasPermissions::Delete => write!(f, "d"),
            SasPermissions::List => write!(f, "l"),
            SasPermissions::Add => write!(f, "a"),
            SasPermissions::Create => write!(f, "c"),
            SasPermissions::Update => write!(f, "u"),
            SasPermissions::Process => write!(f, "p"),
        }
    }
}

pub struct SharedAccessSignature {
    account: String,
    key: String,

    signed_version: SasVersion,
    signed_resource: SasResource,
    signed_resource_type: SasResourceType,
    signed_start: Option<DateTime<Utc>>,
    signed_expiry: DateTime<Utc>,
    signed_permissions: SasPermissions,
    signed_ip: Option<String>,
    signed_protocol: Option<SasProtocol>,
}

impl SharedAccessSignature {
    pub fn new(account: &str, key: &str) -> SharedAccessSignatureBuilder {
        SharedAccessSignatureBuilder {
            account: account.to_string(),
            key: key.to_string(),
            ..Default::default()
        }
    }

    pub fn set_start(&mut self, start: DateTime<Utc>) {
        self.signed_start = Some(start);
    }

    pub fn set_ip(&mut self, ip: String) {
        self.signed_ip = Some(ip);
    }

    pub fn set_protocol(&mut self, protocol: SasProtocol) {
        self.signed_protocol = Some(protocol);
    }

    fn format_date(d: DateTime<Utc>) -> String {
        d.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }

    fn signature(&self) -> String {
        match self.signed_version {
            SasVersion::V20181109 => {
                let string_to_sign = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    self.account,
                    self.signed_permissions,
                    self.signed_resource,
                    self.signed_resource_type,
                    self.signed_start.map_or(
                        "".to_string(),
                        |v| SharedAccessSignature::format_date(v)
                    ),
                    SharedAccessSignature::format_date(self.signed_expiry),
                    self.signed_ip.clone().unwrap_or("".to_string()),
                    self.signed_protocol.as_ref().map_or(
                        "".to_string(),
                        |v| v.to_string()
                    ),
                    self.signed_version,
                );
                let sig_bytes = HMAC::mac(
                    string_to_sign.as_bytes(),
                    &decode(&self.key).unwrap(),
                );
                encode(&sig_bytes)
            },
            _ => {
                // TODO: support other version tags?
                unimplemented!("Versions older than 2018-11-09 not supported");
            },
        }
    }

    pub fn token(&self) -> String {
        let mut elements: Vec<String> = vec![
            format!("sv={}", self.signed_version),
            format!("ss={}", self.signed_resource),
            format!("srt={}", self.signed_resource_type),
            format!("se={}", utf8_percent_encode(&SharedAccessSignature::format_date(self.signed_expiry), DEFAULT_ENCODE_SET)),
            format!("sp={}", self.signed_permissions),
        ];
        
        if let Some(start) = &self.signed_start {
            elements.push(format!("st={}", utf8_percent_encode(&SharedAccessSignature::format_date(*start), DEFAULT_ENCODE_SET)))
        }
        if let Some(ip) = &self.signed_ip {
            elements.push(format!("sip={}", ip))
        }
        if let Some(protocol) = &self.signed_protocol {
            elements.push(format!("spr={}", protocol))
        }
        let sig = SharedAccessSignature::signature(self);
        elements.push(format!("sig={}", utf8_percent_encode(&sig, COMPLETE_ENCODE_SET)));

        elements.join("&")
    }
}

impl PartialEq for SharedAccessSignature {
    fn eq(&self, other: &Self) -> bool {
        self.signature() == other.signature()
    }
}

impl std::fmt::Debug for SharedAccessSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "SharedAccessSignature {{{}}}", self.signature())
    }
}

pub struct SharedAccessSignatureBuilder {
    account: String,
    key: String,

    signed_version: SasVersion,
    signed_resource: SasResource,
    signed_resource_type: SasResourceType,
    signed_start: Option<DateTime<Utc>>,
    signed_expiry: DateTime<Utc>,
    signed_permissions: SasPermissions,
    signed_ip: Option<String>,
    signed_protocol: Option<SasProtocol>,
}

impl Default for SharedAccessSignatureBuilder {
    fn default() -> Self {
        Self {
            account: "".to_string(),
            key: "".to_string(),

            signed_version: SasVersion::V20181109,
            signed_resource: SasResource::Blob,
            signed_resource_type: SasResourceType::Object,
            signed_start: None,
            signed_expiry: Utc::now() + Duration::hours(4),
            signed_permissions: SasPermissions::Read,
            signed_ip: None,
            signed_protocol: None,
        }
    }
}

impl SharedAccessSignatureBuilder {
    pub fn with_version(&mut self, version: SasVersion) -> &mut Self {
        self.signed_version = version;
        self
    }

    pub fn with_resource(&mut self, resource: SasResource) -> &mut Self {
        self.signed_resource = resource;
        self
    }

    pub fn with_resource_type(&mut self, resource_type: SasResourceType) -> &mut Self {
        self.signed_resource_type = resource_type;
        self
    }

    pub fn with_start(&mut self, start: DateTime<Utc>) -> &mut Self {
        self.signed_start = Some(start);
        self
    }

    pub fn with_expiry(&mut self, expiry: DateTime<Utc>) -> &mut Self {
        self.signed_expiry = expiry;
        self
    }

    pub fn with_permissions(&mut self, permissions: SasPermissions) -> &mut Self {
        self.signed_permissions = permissions;
        self
    }

    pub fn with_ip(&mut self, ip: String) -> &mut Self {
        self.signed_ip = Some(ip);
        self
    }

    pub fn with_protocol(&mut self, protocol: SasProtocol) -> &mut Self {
        self.signed_protocol = Some(protocol);
        self
    }

    pub fn finish(&self) -> SharedAccessSignature {
        SharedAccessSignature {
            account: self.account.clone(),
            key: self.key.clone(),

            signed_version: self.signed_version,
            signed_resource: self.signed_resource,
            signed_resource_type: self.signed_resource_type,
            signed_start: self.signed_start,
            signed_expiry: self.signed_expiry,
            signed_permissions: self.signed_permissions,
            signed_ip: self.signed_ip.clone(),
            signed_protocol: self.signed_protocol.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn test_builder() {
        let sas = SharedAccessSignature::new("abc123", "gobbledygook")
            .with_resource(SasResource::Queue)
            .with_resource_type(SasResourceType::Container)
            .with_start(Utc.ymd(2019, 6, 1).and_hms(10, 10, 11))
            .with_expiry(Utc.ymd(2019, 6, 1).and_hms(14, 10, 11))
            .with_permissions(SasPermissions::Write)
            .with_protocol(SasProtocol::HttpHttps)
            .finish();
        let expected = SharedAccessSignature {
            account: "abc123".to_string(),
            key: "gobbledygook".to_string(),

            signed_version: SasVersion::V20181109,
            signed_resource: SasResource::Queue,
            signed_resource_type: SasResourceType::Container,
            signed_start: Some(Utc.ymd(2019, 6, 1).and_hms(10, 10, 11)),
            signed_expiry: Utc.ymd(2019, 6, 1).and_hms(14, 10, 11),
            signed_permissions: SasPermissions::Write,
            signed_ip: None,
            signed_protocol: Some(SasProtocol::HttpHttps),
        };
        assert_eq!(sas, expected);
    }

    #[test]
    fn test_sas_signature() {
        let sas = SharedAccessSignature {
            account: "abc123".to_string(),
            key: "gobbledygook".to_string(),

            signed_version: SasVersion::V20181109,
            signed_resource: SasResource::Blob,
            signed_resource_type: SasResourceType::Object,
            signed_start: None,
            signed_expiry: Utc.ymd(2019, 6, 1).and_hms(14, 10, 11),
            signed_permissions: SasPermissions::Read,
            signed_ip: None,
            signed_protocol: Some(SasProtocol::Https),
        };
        // TODO: get gold standard signature
        assert_eq!(
            sas.signature(),
            "Cp/NfP1q7XNa9VvzP4CjA7sVeaIP9nmAYtNJl52pJkc="
        );
    }

    #[test]
    fn test_sas_signature_with_start() {
        let sas = SharedAccessSignature {
            account: "abc123".to_string(),
            key: "gobbledygook".to_string(),

            signed_version: SasVersion::V20181109,
            signed_resource: SasResource::Blob,
            signed_resource_type: SasResourceType::Object,
            signed_start: Some(Utc.ymd(2019, 6, 1).and_hms(06, 10, 11)),
            signed_expiry: Utc.ymd(2019, 6, 1).and_hms(14, 10, 11),
            signed_permissions: SasPermissions::Read,
            signed_ip: None,
            signed_protocol: Some(SasProtocol::Https),
        };
        // TODO: get gold standard signature
        assert_eq!(
            sas.signature(),
            "YpdVZ5RzPGngCEsVyp0OhzJYMvb8fpupzyLXWttspNc="
        );
    }

    #[test]
    fn test_sas_token() {
        let sas = SharedAccessSignature {
            account: "abc123".to_string(),
            key: "gobbledygook".to_string(),

            signed_version: SasVersion::V20181109,
            signed_resource: SasResource::Blob,
            signed_resource_type: SasResourceType::Object,
            signed_start: None,
            signed_expiry: Utc.ymd(2019, 6, 1).and_hms(14, 10, 11),
            signed_permissions: SasPermissions::Read,
            signed_ip: None,
            signed_protocol: Some(SasProtocol::Https),
        };

        println!("token: '{}'", sas.token());
        assert_eq!(
            sas.token(),
            "sv=2018-11-09&ss=b&srt=o&se=2019-06-01T14:10:11Z&sp=r&spr=https&sig=Cp%2FNfP1q7XNa9VvzP4CjA7sVeaIP9nmAYtNJl52pJkc%3D"
        );
    }
}
