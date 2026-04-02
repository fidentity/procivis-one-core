use super::dto::{TrustEntryFilterParamsDTO, TrustListPublicationFilterParamsDTO};
use crate::model::list_filter::{
    ComparisonType, ListFilterCondition, ListFilterValue, StringMatch, StringMatchType,
    ValueComparison,
};
use crate::model::trust_entry::TrustEntryFilterValue;
use crate::model::trust_list_publication::TrustListPublicationFilterValue;
use crate::service::trust_list_publication::dto::ExactTrustListFilterColumn;

impl From<TrustListPublicationFilterParamsDTO>
    for ListFilterCondition<TrustListPublicationFilterValue>
{
    fn from(value: TrustListPublicationFilterParamsDTO) -> Self {
        let exact = value.exact.unwrap_or_default();
        let get_string_match_type = |column| {
            if exact.contains(&column) {
                StringMatchType::Equals
            } else {
                StringMatchType::StartsWith
            }
        };

        let organisation_id =
            TrustListPublicationFilterValue::OrganisationId(value.organisation_id).condition();

        let name = value.name.map(|name| {
            TrustListPublicationFilterValue::Name(StringMatch {
                r#match: get_string_match_type(ExactTrustListFilterColumn::Name),
                value: name,
            })
        });

        let ids = value.ids.map(TrustListPublicationFilterValue::Ids);

        let types = value.types.map(TrustListPublicationFilterValue::Type);

        let roles = value.roles.map(TrustListPublicationFilterValue::Role);

        let created_date_after = value.created_date_after.map(|date| {
            TrustListPublicationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            TrustListPublicationFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });
        let last_modified_after = value.last_modified_after.map(|date| {
            TrustListPublicationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            TrustListPublicationFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        organisation_id
            & name
            & ids
            & types
            & roles
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}

impl From<TrustEntryFilterParamsDTO> for ListFilterCondition<TrustEntryFilterValue> {
    fn from(value: TrustEntryFilterParamsDTO) -> Self {
        let ids = value.ids.map(TrustEntryFilterValue::Ids);

        let identifier_ids = value
            .identifier_ids
            .map(TrustEntryFilterValue::IdentifierIds);

        let states = value.states.map(TrustEntryFilterValue::State);

        let created_date_after = value.created_date_after.map(|date| {
            TrustEntryFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let created_date_before = value.created_date_before.map(|date| {
            TrustEntryFilterValue::CreatedDate(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });
        let last_modified_after = value.last_modified_after.map(|date| {
            TrustEntryFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::GreaterThanOrEqual,
                value: date,
            })
        });
        let last_modified_before = value.last_modified_before.map(|date| {
            TrustEntryFilterValue::LastModified(ValueComparison {
                comparison: ComparisonType::LessThanOrEqual,
                value: date,
            })
        });

        ListFilterCondition::<TrustEntryFilterValue>::from(ids)
            & identifier_ids
            & states
            & created_date_after
            & created_date_before
            & last_modified_after
            & last_modified_before
    }
}
