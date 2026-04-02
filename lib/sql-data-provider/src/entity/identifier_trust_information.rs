use sea_orm::entity::prelude::*;
use sea_orm::{ActiveModelBehavior, DeriveEntityModel, DeriveRelation, EnumIter};
use shared_types::{
    BlobId, IdentifierId, IdentifierTrustInformationId, TrustCollectionId, TrustListSubscriberId,
    TrustListSubscriptionId,
};
use time::OffsetDateTime;

use crate::entity::trust_list_publication::TrustRoleEnum;
use crate::entity::trust_list_subscription::TrustListSubscriptionState;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "identifier_trust_information")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: IdentifierTrustInformationId,
    pub created_date: OffsetDateTime,
    pub last_modified: OffsetDateTime,
    pub valid_from: Option<OffsetDateTime>,
    pub valid_to: Option<OffsetDateTime>,
    pub intended_use: Option<String>,
    pub allowed_issuance_types: Option<String>,
    pub allowed_verification_types: Option<String>,

    pub identifier_id: IdentifierId,
    pub blob_id: BlobId,
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::identifier::Entity",
        from = "Column::IdentifierId",
        to = "super::identifier::Column::Id"
    )]
    Identifier,
}

impl Related<super::identifier::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Identifier.def()
    }
}
