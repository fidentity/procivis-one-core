use std::collections::HashMap;

use one_core::model::did::{DidType, ExactDidFilterColumn, KeyRole, SortableDidColumn};
use one_core::service::did::dto::{DidListItemResponseDTO, GetDidListResponseDTO};
use one_dto_mapper::{From, Into, convert_inner};

use super::common::SortDirection;
use crate::OneCore;
use crate::error::BindingError;
use crate::utils::TimestampFormat;

#[uniffi::export(async_runtime = "tokio")]
impl OneCore {
    /// Deprecated. Use the `createIdentifier` method.
    #[uniffi::method]
    pub async fn create_did(&self, request: DidRequestBindingDTO) -> Result<String, BindingError> {
        let core = self.use_core().await?;
        Ok(core
            .did_service
            .create_did(request.try_into()?)
            .await?
            .to_string())
    }

    /// Deprecated. Use the `listIdentifiers` method.
    #[uniffi::method]
    pub async fn list_dids(
        &self,
        query: DidListQueryBindingDTO,
    ) -> Result<DidListBindingDTO, BindingError> {
        let core = self.use_core().await?;

        Ok(core
            .did_service
            .get_did_list(query.try_into()?)
            .await?
            .into())
    }
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(DidListItemResponseDTO)]
#[uniffi(name = "DidListItem")]
pub struct DidListItemBindingDTO {
    #[from(with_fn_ref = "ToString::to_string")]
    pub id: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub created_date: String,
    #[from(with_fn_ref = "TimestampFormat::format_timestamp")]
    pub last_modified: String,
    pub name: String,
    #[from(with_fn_ref = "ToString::to_string")]
    pub did: String,
    pub did_type: DidTypeBindingEnum,
    pub did_method: String,
    pub deactivated: bool,
}

#[derive(Clone, Debug, Into, From, uniffi::Enum)]
#[into(DidType)]
#[from(DidType)]
#[uniffi(name = "DidType")]
pub enum DidTypeBindingEnum {
    Local,
    Remote,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "DidListQuery")]
pub struct DidListQueryBindingDTO {
    pub page: u32,
    pub page_size: u32,

    pub sort: Option<SortableDidColumnBindingEnum>,
    pub sort_direction: Option<SortDirection>,

    pub organisation_id: String,
    pub name: Option<String>,
    pub did: Option<String>,
    pub r#type: Option<DidTypeBindingEnum>,
    pub deactivated: Option<bool>,
    pub exact: Option<Vec<ExactDidFilterColumnBindingEnum>>,
    pub key_algorithms: Option<Vec<String>>,
    pub key_roles: Option<Vec<KeyRoleBindingEnum>>,
    pub key_storages: Option<Vec<String>>,
    pub key_ids: Option<Vec<String>>,
    pub did_methods: Option<Vec<String>>,
}

#[derive(Clone, Debug, From, uniffi::Record)]
#[from(GetDidListResponseDTO)]
#[uniffi(name = "DidList")]
pub struct DidListBindingDTO {
    #[from(with_fn = convert_inner)]
    pub values: Vec<DidListItemBindingDTO>,
    pub total_pages: u64,
    pub total_items: u64,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(SortableDidColumn)]
#[uniffi(name = "SortableDidColumn")]
pub enum SortableDidColumnBindingEnum {
    Name,
    CreatedDate,
    Method,
    Type,
    Did,
    Deactivated,
}

#[derive(Clone, Debug, PartialEq, Into, uniffi::Enum)]
#[into(ExactDidFilterColumn)]
#[uniffi(name = "DidListQueryExactColumn")]
pub enum ExactDidFilterColumnBindingEnum {
    Name,
    Did,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "CreateDidRequest")]
pub struct DidRequestBindingDTO {
    pub organisation_id: String,
    pub name: String,
    pub did_method: String,
    pub keys: DidRequestKeysBindingDTO,
    pub params: HashMap<String, String>,
}

#[derive(Clone, Debug, uniffi::Record)]
#[uniffi(name = "DidRequestKeys")]
pub struct DidRequestKeysBindingDTO {
    pub authentication: Vec<String>,
    pub assertion_method: Vec<String>,
    pub key_agreement: Vec<String>,
    pub capability_invocation: Vec<String>,
    pub capability_delegation: Vec<String>,
}

#[derive(Clone, Debug, Into, uniffi::Enum)]
#[into(KeyRole)]
#[uniffi(name = "KeyRole")]
pub enum KeyRoleBindingEnum {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation,
}
