use one_core::service::error::ServiceError;
use one_core::service::trust_entity::dto::CreateTrustEntityRequestDTO;
use one_dto_mapper::try_convert_inner;

use super::dto::CreateTrustEntityRequestRestDTO;

impl TryFrom<CreateTrustEntityRequestRestDTO> for CreateTrustEntityRequestDTO {
    type Error = ServiceError;

    fn try_from(value: CreateTrustEntityRequestRestDTO) -> Result<Self, Self::Error> {
        Ok(Self {
            name: value.name,
            logo: try_convert_inner(value.logo)?,
            website: value.website,
            terms_url: value.terms_url,
            privacy_url: value.privacy_url,
            role: value.role.into(),
            trust_anchor_id: value.trust_anchor_id,
            did_id: value.did_id,
            identifier_id: value.identifier_id,
            r#type: value.r#type.map(Into::into),
            content: value
                .content
                .map(|s| String::from_utf8_lossy(s.as_bytes()).to_string()),
            organisation_id: value.organisation_id,
        })
    }
}
