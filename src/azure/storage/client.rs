use super::rest_client::{perform_request, ServiceType};
use crate::azure::core::errors::AzureError;
use crate::azure::core::No;
use crate::azure::core::shared_access_signature::{
    SharedAccessSignature,
    SasResource,
    SasResourceType,
    SasPermissions,
    SasProtocol,
};
use crate::azure::core::COMPLETE_ENCODE_SET;
use chrono::{DateTime, Utc};
use crate::azure::storage::{blob, container};
use hyper::{self, Method};
use hyper_tls;
use std::borrow::Borrow;
use url::Url;
use url::percent_encoding::utf8_percent_encode;

pub trait Blob {
    fn list_blobs<'a>(&'a self) -> blob::requests::ListBlobBuilder<'a, No>;
    fn get_blob<'a>(&'a self) -> blob::requests::GetBlobBuilder<'a, No, No>;
    fn put_block_blob<'a>(&'a self) -> blob::requests::PutBlockBlobBuilder<'a, No, No, No>;
    fn put_page_blob<'a>(&'a self) -> blob::requests::PutPageBlobBuilder<'a, No, No, No>;
    fn put_append_blob<'a>(&'a self) -> blob::requests::PutAppendBlobBuilder<'a, No, No>;
    fn update_page<'a>(&'a self) -> blob::requests::UpdatePageBuilder<'a, No, No, No, No>;
    fn clear_page<'a>(&'a self) -> blob::requests::ClearPageBuilder<'a, No, No, No>;
    fn put_block<'a>(&'a self) -> blob::requests::PutBlockBuilder<'a, No, No, No, No>;
    fn get_block_list<'a>(&'a self) -> blob::requests::GetBlockListBuilder<'a, No, No, No>;
    fn put_block_list<'a, T: Borrow<[u8]> + 'a>(&'a self) -> blob::requests::PutBlockListBuilder<'a, T, No, No, No>;
    fn acquire_blob_lease<'a>(&'a self) -> blob::requests::AcquireBlobLeaseBuilder<'a, No, No, No>;
    fn renew_blob_lease<'a>(&'a self) -> blob::requests::RenewBlobLeaseBuilder<'a, No, No, No>;
    fn change_blob_lease<'a>(&'a self) -> blob::requests::ChangeBlobLeaseBuilder<'a, No, No, No, No>;
    fn release_blob_lease<'a>(&'a self) -> blob::requests::ReleaseBlobLeaseBuilder<'a, No, No, No>;
    fn break_blob_lease<'a>(&'a self) -> blob::requests::BreakBlobLeaseBuilder<'a, No, No, No>;
    fn delete_blob_snapshot<'a>(&'a self) -> blob::requests::DeleteBlobSnapshotBuilder<'a, No, No, No>;
    fn delete_blob<'a>(&'a self) -> blob::requests::DeleteBlobBuilder<'a, No, No, No>;
    fn stream_list_blobs<'a>(&'a self) -> blob::ListBlobStreamBuilder<'a, No>;
    fn stream_blob<'a>(&'a self) -> blob::BlobStreamBuilder<'a, No, No, No>;
    fn generate_shared_access_token(
        &self,
        resource_type: SasResourceType,
        permissions: SasPermissions,
        expiry: DateTime<Utc>,
        start: Option<DateTime<Utc>>,
        ip: Option<&str>,
        protocol: Option<SasProtocol>,
    ) -> String;
    fn make_signed_blob_url(
        &self,
        container: &str,
        blob: &str,
        signed_token: &str,
    ) -> String;
}

pub trait Container {
    fn create_container<'a>(&'a self) -> container::requests::CreateBuilder<'a, No, No>;
    fn delete_container<'a>(&'a self) -> container::requests::DeleteBuilder<'a, No>;
    fn list_containers<'a>(&'a self) -> container::requests::ListBuilder<'a>;
    fn get_container_acl<'a>(&'a self) -> container::requests::GetACLBuilder<'a, No>;
    fn set_container_acl<'a>(&'a self) -> container::requests::SetACLBuilder<'a, No, No>;
    fn get_container_properties<'a>(&'a self) -> container::requests::GetPropertiesBuilder<'a, No>;
    fn acquire_container_lease<'a>(&'a self) -> container::requests::AcquireLeaseBuilder<'a, No, No>;
    fn renew_container_lease<'a>(&'a self) -> container::requests::RenewLeaseBuilder<'a, No, No>;
    fn release_container_lease<'a>(&'a self) -> container::requests::ReleaseLeaseBuilder<'a, No, No>;
    fn break_container_lease<'a>(&'a self) -> container::requests::BreakLeaseBuilder<'a, No>;
}

#[derive(Debug, Clone)]
pub struct Client {
    account: String,
    key: String,
    hc: hyper::Client<hyper_tls::HttpsConnector<hyper::client::HttpConnector>>,
    blob_uri: String,
    table_uri: String,
}

impl Blob for Client {
    fn list_blobs<'a>(&'a self) -> blob::requests::ListBlobBuilder<'a, No> {
        blob::requests::ListBlobBuilder::new(self)
    }

    fn get_blob<'a>(&'a self) -> blob::requests::GetBlobBuilder<'a, No, No> {
        blob::requests::GetBlobBuilder::new(self)
    }

    fn put_block_blob<'a>(&'a self) -> blob::requests::PutBlockBlobBuilder<'a, No, No, No> {
        blob::requests::PutBlockBlobBuilder::new(self)
    }

    fn put_page_blob<'a>(&'a self) -> blob::requests::PutPageBlobBuilder<'a, No, No, No> {
        blob::requests::PutPageBlobBuilder::new(self)
    }

    fn put_append_blob<'a>(&'a self) -> blob::requests::PutAppendBlobBuilder<'a, No, No> {
        blob::requests::PutAppendBlobBuilder::new(self)
    }

    fn update_page<'a>(&'a self) -> blob::requests::UpdatePageBuilder<'a, No, No, No, No> {
        blob::requests::UpdatePageBuilder::new(self)
    }

    fn clear_page<'a>(&'a self) -> blob::requests::ClearPageBuilder<'a, No, No, No> {
        blob::requests::ClearPageBuilder::new(self)
    }

    fn put_block<'a>(&'a self) -> blob::requests::PutBlockBuilder<'a, No, No, No, No> {
        blob::requests::PutBlockBuilder::new(self)
    }

    fn get_block_list<'a>(&'a self) -> blob::requests::GetBlockListBuilder<'a, No, No, No> {
        blob::requests::GetBlockListBuilder::new(self)
    }

    fn put_block_list<'a, T: Borrow<[u8]> + 'a>(&'a self) -> blob::requests::PutBlockListBuilder<'a, T, No, No, No> {
        blob::requests::PutBlockListBuilder::new(self)
    }

    fn acquire_blob_lease<'a>(&'a self) -> blob::requests::AcquireBlobLeaseBuilder<'a, No, No, No> {
        blob::requests::AcquireBlobLeaseBuilder::new(self)
    }

    fn renew_blob_lease<'a>(&'a self) -> blob::requests::RenewBlobLeaseBuilder<'a, No, No, No> {
        blob::requests::RenewBlobLeaseBuilder::new(self)
    }

    fn change_blob_lease<'a>(&'a self) -> blob::requests::ChangeBlobLeaseBuilder<'a, No, No, No, No> {
        blob::requests::ChangeBlobLeaseBuilder::new(self)
    }

    fn release_blob_lease<'a>(&'a self) -> blob::requests::ReleaseBlobLeaseBuilder<'a, No, No, No> {
        blob::requests::ReleaseBlobLeaseBuilder::new(self)
    }

    fn break_blob_lease<'a>(&'a self) -> blob::requests::BreakBlobLeaseBuilder<'a, No, No, No> {
        blob::requests::BreakBlobLeaseBuilder::new(self)
    }

    fn delete_blob_snapshot<'a>(&'a self) -> blob::requests::DeleteBlobSnapshotBuilder<'a, No, No, No> {
        blob::requests::DeleteBlobSnapshotBuilder::new(self)
    }

    fn delete_blob<'a>(&'a self) -> blob::requests::DeleteBlobBuilder<'a, No, No, No> {
        blob::requests::DeleteBlobBuilder::new(self)
    }

    fn stream_list_blobs<'a>(&'a self) -> blob::ListBlobStreamBuilder<'a, No> {
        blob::ListBlobStreamBuilder::new(self)
    }

    fn stream_blob<'a>(&'a self) -> blob::BlobStreamBuilder<'a, No, No, No> {
        blob::BlobStreamBuilder::new(self)
    }

    fn generate_shared_access_token(
        &self,
        resource_type: SasResourceType,
        permissions: SasPermissions,
        expiry: DateTime<Utc>,
        start: Option<DateTime<Utc>>,
        ip: Option<&str>,
        protocol: Option<SasProtocol>,
    ) -> String
    {
        let mut sas = SharedAccessSignature::new(&self.account, &self.key)
            .with_resource(SasResource::Blob)
            .with_resource_type(resource_type)
            .with_permissions(permissions)
            .with_expiry(expiry)
            .finish();
        if let Some(start) = start {
            sas.set_start(start);
        }
        if let Some(ip) = ip {
            sas.set_ip(ip.to_string());
        }
        if let Some(protocol) = protocol {
            sas.set_protocol(protocol);
        }

        sas.token()
    }

    fn make_signed_blob_url(
        &self,
        container: &str,
        blob: &str,
        signed_token: &str,
    ) -> String
    {
        format!(
            "{}/{}/{}?{}",
            self.blob_uri(),
            utf8_percent_encode(container, COMPLETE_ENCODE_SET),
            utf8_percent_encode(blob, COMPLETE_ENCODE_SET),
            signed_token,
        )
    }
}

impl Container for Client {
    fn create_container<'a>(&'a self) -> container::requests::CreateBuilder<'a, No, No> {
        container::requests::CreateBuilder::new(self)
    }

    fn delete_container<'a>(&'a self) -> container::requests::DeleteBuilder<'a, No> {
        container::requests::DeleteBuilder::new(self)
    }

    fn list_containers<'a>(&'a self) -> container::requests::ListBuilder<'a> {
        container::requests::ListBuilder::new(self)
    }

    fn get_container_acl<'a>(&'a self) -> container::requests::GetACLBuilder<'a, No> {
        container::requests::GetACLBuilder::new(self)
    }

    fn set_container_acl<'a>(&'a self) -> container::requests::SetACLBuilder<'a, No, No> {
        container::requests::SetACLBuilder::new(self)
    }

    fn get_container_properties<'a>(&'a self) -> container::requests::GetPropertiesBuilder<'a, No> {
        container::requests::GetPropertiesBuilder::new(self)
    }

    fn acquire_container_lease<'a>(&'a self) -> container::requests::AcquireLeaseBuilder<'a, No, No> {
        container::requests::AcquireLeaseBuilder::new(self)
    }

    fn renew_container_lease<'a>(&'a self) -> container::requests::RenewLeaseBuilder<'a, No, No> {
        container::requests::RenewLeaseBuilder::new(self)
    }

    fn release_container_lease<'a>(&'a self) -> container::requests::ReleaseLeaseBuilder<'a, No, No> {
        container::requests::ReleaseLeaseBuilder::new(self)
    }

    fn break_container_lease<'a>(&'a self) -> container::requests::BreakLeaseBuilder<'a, No> {
        container::requests::BreakLeaseBuilder::new(self)
    }
}

impl Client {
    pub fn new(account: &str, key: &str) -> Result<Client, AzureError> {
        Client::azure(account, key)
    }

    pub fn azure(account: &str, key: &str) -> Result<Client, AzureError> {
        let client = hyper::Client::builder().build(hyper_tls::HttpsConnector::new(4)?);

        Ok(Client {
            account: account.to_owned(),
            key: key.to_owned(),
            hc: client,
            blob_uri: format!("https://{}.blob.core.windows.net", account),
            table_uri: format!("https://{}.table.core.windows.net", account),
        })
    }

    pub fn emulator(blob_storage_url: &Url, table_storage_url: &Url) -> Result<Client, AzureError> {
        let client = hyper::Client::builder().build(hyper_tls::HttpsConnector::new(4)?);

        let blob_uri = format!("{}devstoreaccount1", blob_storage_url.as_str());
        debug!("blob_uri == {}", blob_uri);
        let table_uri = format!("{}devstoreaccount1", table_storage_url.as_str());
        debug!("table_uri == {}", table_uri);

        Ok(Client {
            account: "devstoreaccount1".to_owned(),
            key: "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==".to_owned(),
            hc: client,
            blob_uri,
            table_uri,
        })
    }

    pub fn account(&self) -> &str {
        &self.account
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    #[inline]
    pub(crate) fn blob_uri(&self) -> &str {
        &self.blob_uri
    }

    #[inline]
    pub(crate) fn table_uri(&self) -> &str {
        &self.table_uri
    }

    pub(crate) fn perform_request<F>(
        &self,
        uri: &str,
        method: &Method,
        headers_func: F,
        request_body: Option<&[u8]>,
    ) -> Result<hyper::client::ResponseFuture, AzureError>
    where
        F: FnOnce(&mut ::http::request::Builder),
    {
        perform_request(&self.hc, uri, method, &self.key, headers_func, request_body, ServiceType::Blob)
    }

    pub(crate) fn perform_table_request<F>(
        &self,
        segment: &str,
        method: &Method,
        headers_func: F,
        request_str: Option<&[u8]>,
    ) -> Result<hyper::client::ResponseFuture, AzureError>
    where
        F: FnOnce(&mut ::http::request::Builder),
    {
        debug!("segment: {}, method: {:?}", segment, method,);
        perform_request(
            &self.hc,
            (self.get_uri_prefix(ServiceType::Table) + segment).as_str(),
            method,
            &self.key,
            headers_func,
            request_str,
            ServiceType::Table,
        )
    }

    /// Uri scheme + authority e.g. http://myaccount.table.core.windows.net/
    pub(crate) fn get_uri_prefix(&self, service_type: ServiceType) -> String {
        match service_type {
            ServiceType::Blob => format!("{}/", self.blob_uri()),
            ServiceType::Table => format!("{}/", self.table_uri()),
        }
    }
}
