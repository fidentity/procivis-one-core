use one_dto_mapper::convert_inner;
use shared_types::OrganisationId;

use super::dto::{
    CreateIdentifierDidRequestDTO, GetIdentifierListItemResponseDTO, GetIdentifierListResponseDTO,
    GetIdentifierResponseDTO, IdentifierFilterParamsDTO, ResolvedTrustEntrySourceResponseDTO,
};
use super::error::IdentifierServiceError;
use crate::error::ContextWithErrorCode;
use crate::model::identifier::{
    ExactIdentifierFilterColumn, GetIdentifierList, Identifier, IdentifierFilterValue,
    IdentifierType,
};
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::trust_list_subscription::TrustListSubscription;
use crate::service::did::dto::CreateDidRequestDTO;

impl TryFrom<Identifier> for GetIdentifierResponseDTO {
    type Error = IdentifierServiceError;
    fn try_from(value: Identifier) -> Result<Self, Self::Error> {
        let organisation_id = value.organisation.map(|org| org.id);

        let mut certificates = None;
        let mut certificate_authorities = None;
        match value.r#type {
            IdentifierType::Did => {
                if value.did.is_none() {
                    return Err(IdentifierServiceError::MappingError(
                        "DID is required for identifier type Did".to_string(),
                    ));
                }
            }
            IdentifierType::Key => {
                if value.key.is_none() {
                    return Err(IdentifierServiceError::MappingError(
                        "Key is required for identifier type Key".to_string(),
                    ));
                }
            }
            IdentifierType::Certificate => {
                let mut certs = vec![];
                for certificate in
                    value
                        .certificates
                        .ok_or(IdentifierServiceError::MappingError(format!(
                            "Certificates required for identifier type {}",
                            value.r#type
                        )))?
                {
                    certs.push(
                        certificate
                            .try_into()
                            .error_while("converting certificate")?,
                    );
                }
                certificates = Some(certs);
            }
            IdentifierType::CertificateAuthority => {
                let mut certs = vec![];
                for certificate in
                    value
                        .certificates
                        .ok_or(IdentifierServiceError::MappingError(format!(
                            "Certificates required for identifier type {}",
                            value.r#type
                        )))?
                {
                    certs.push(
                        certificate
                            .try_into()
                            .error_while("converting certificate")?,
                    );
                }
                certificate_authorities = Some(certs);
            }
        }

        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            organisation_id,
            r#type: value.r#type,
            is_remote: value.is_remote,
            state: value.state,
            did: value
                .did
                .map(TryInto::try_into)
                .transpose()
                .error_while("converting DID")?,
            key: value
                .key
                .map(TryInto::try_into)
                .transpose()
                .error_while("converting key")?,
            certificates,
            certificate_authorities,
        })
    }
}

impl From<Identifier> for GetIdentifierListItemResponseDTO {
    fn from(value: Identifier) -> Self {
        Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            r#type: value.r#type,
            is_remote: value.is_remote,
            state: value.state,
            organisation_id: value.organisation.map(|org| org.id),
        }
    }
}

impl From<GetIdentifierList> for GetIdentifierListResponseDTO {
    fn from(value: GetIdentifierList) -> Self {
        Self {
            values: convert_inner(value.values),
            total_pages: value.total_pages,
            total_items: value.total_items,
        }
    }
}

pub(super) fn to_create_did_request(
    identifier_name: &str,
    request: CreateIdentifierDidRequestDTO,
    organisation_id: OrganisationId,
) -> CreateDidRequestDTO {
    CreateDidRequestDTO {
        name: request.name.unwrap_or(identifier_name.to_string()),
        organisation_id,
        did_method: request.method,
        keys: request.keys,
        params: request.params,
    }
}

impl TryFrom<TrustListSubscription> for ResolvedTrustEntrySourceResponseDTO {
    type Error = IdentifierServiceError;

    fn try_from(value: TrustListSubscription) -> Result<Self, Self::Error> {
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            role: value.role,
            reference: value.reference,
            r#type: value.r#type,
            state: value.state,
            trust_collection: value.trust_collection.map(Into::into).ok_or(
                IdentifierServiceError::MappingError("missing trust collection".to_string()),
            )?,
        })
    }
}

impl From<IdentifierFilterParamsDTO> for ListFilterCondition<IdentifierFilterValue> {
    fn from(value: IdentifierFilterParamsDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id =
            IdentifierFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            IdentifierFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactIdentifierFilterColumn::Name),
                value: name,
            })
        });

        let ids = value.ids.map(IdentifierFilterValue::Ids);
        let types = value
            .types
            .map(|types| IdentifierFilterValue::Types(convert_inner(types)));
        let state = value
            .states
            .map(|states| IdentifierFilterValue::States(convert_inner(states)));
        let did_methods = value.did_methods.map(IdentifierFilterValue::DidMethods);
        let is_remote = value.is_remote.map(IdentifierFilterValue::IsRemote);
        let key_algorithms = value
            .key_algorithms
            .map(IdentifierFilterValue::KeyAlgorithms);
        let key_roles = value
            .key_roles
            .map(|key_roles| IdentifierFilterValue::KeyRoles(convert_inner(key_roles)));
        let key_storages = value.key_storages.map(IdentifierFilterValue::KeyStorages);

        let created_date_after = value.created_date_after.map(|date| {
            IdentifierFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            IdentifierFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = value.last_modified_after.map(|date| {
            IdentifierFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            IdentifierFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        organisation_id
            & name
            & ids
            & types
            & state
            & did_methods
            & is_remote
            & key_algorithms
            & key_roles
            & key_storages
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}
