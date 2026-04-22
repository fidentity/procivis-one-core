use shared_types::DidValue;
use uuid::Uuid;

use super::dto::{
    CreateTrustAnchorRequestDTO, GetTrustAnchorEntityListResponseDTO, TrustAnchorFilterParamsDTO,
    TrustAnchorFilterValue,
};
use super::error::TrustAnchorServiceError;
use crate::error::ContextWithErrorCode;
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, StringMatch, StringMatchType, ValueComparison,
};
use crate::model::trust_anchor::{ExactTrustAnchorFilterColumn, TrustAnchor};
use crate::model::trust_entity::{TrustEntity, TrustEntityType};
use crate::provider::did_method::error::DidMethodError;

pub(super) fn trust_anchor_from_request(
    request: CreateTrustAnchorRequestDTO,
    core_base_url: Option<&String>,
) -> Result<TrustAnchor, TrustAnchorServiceError> {
    let id = Uuid::new_v4().into();
    let now = crate::clock::now_utc();
    let publisher_reference = if let Some(publisher_reference) = request.publisher_reference {
        publisher_reference
    } else {
        format!(
            "{}/ssi/trust/v1/{id}",
            core_base_url
                .as_ref()
                .ok_or_else(|| TrustAnchorServiceError::MappingError(
                    "Missing core_base_url".to_string()
                ))?,
        )
    };

    Ok(TrustAnchor {
        id,
        name: request.name,
        created_date: now,
        last_modified: now,
        r#type: request.r#type,
        is_publisher: request.is_publisher.unwrap_or(false),
        publisher_reference,
    })
}

impl TryFrom<TrustEntity> for GetTrustAnchorEntityListResponseDTO {
    type Error = TrustAnchorServiceError;

    fn try_from(value: TrustEntity) -> Result<Self, Self::Error> {
        let did = if value.r#type == TrustEntityType::Did {
            Some(
                DidValue::from_did_url(&value.entity_key)
                    .map_err(DidMethodError::DidValueError)
                    .error_while("parsing DID")?,
            )
        } else {
            None
        };
        Ok(Self {
            id: value.id,
            created_date: value.created_date,
            last_modified: value.last_modified,
            name: value.name,
            logo: value.logo,
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role,
            state: value.state,
            r#type: value.r#type,
            entity_key: value.entity_key,
            content: value.content,
            did,
        })
    }
}

impl From<TrustAnchorFilterParamsDTO> for ListFilterCondition<TrustAnchorFilterValue> {
    fn from(filter: TrustAnchorFilterParamsDTO) -> Self {
        let exact = filter.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let name = filter.name.map(|name| {
            TrustAnchorFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactTrustAnchorFilterColumn::Name),
                value: name,
            })
        });

        let is_publisher = filter
            .is_publisher
            .map(TrustAnchorFilterValue::is_publisher);

        let r#type = filter.r#type.map(|r#type| {
            TrustAnchorFilterValue::Type(StringMatch {
                r#match: get_string_match_type(ExactTrustAnchorFilterColumn::Type),
                value: r#type,
            })
        });

        let created_date_after = filter.created_date_after.map(|date| {
            TrustAnchorFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = filter.created_date_before.map(|date| {
            TrustAnchorFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        let last_modified_after = filter.last_modified_after.map(|date| {
            TrustAnchorFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = filter.last_modified_before.map(|date| {
            TrustAnchorFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        ListFilterCondition::<TrustAnchorFilterValue>::from(name)
            & is_publisher
            & r#type
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}
