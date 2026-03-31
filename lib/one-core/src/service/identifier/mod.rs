use std::sync::Arc;

use crate::config::core_config;
use crate::error::ErrorCode;
use crate::proto::identifier_creator::IdentifierCreator;
use crate::proto::session_provider::SessionProvider;
use crate::provider::trust_list_subscriber::provider::TrustListSubscriberProvider;
use crate::repository::identifier_repository::IdentifierRepository;
use crate::repository::key_repository::KeyRepository;
use crate::repository::organisation_repository::OrganisationRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;

pub mod dto;
pub mod error;
pub(crate) mod mapper;
pub mod service;
#[cfg(test)]
mod test;
mod validator;

#[derive(Clone)]
pub struct IdentifierService {
    identifier_repository: Arc<dyn IdentifierRepository>,
    key_repository: Arc<dyn KeyRepository>,
    organisation_repository: Arc<dyn OrganisationRepository>,
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    config: Arc<core_config::CoreConfig>,
    identifier_creator: Arc<dyn IdentifierCreator>,
    session_provider: Arc<dyn SessionProvider>,
    trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
}

impl IdentifierService {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        identifier_repository: Arc<dyn IdentifierRepository>,
        key_repository: Arc<dyn KeyRepository>,
        organisation_repository: Arc<dyn OrganisationRepository>,
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        identifier_creator: Arc<dyn IdentifierCreator>,
        config: Arc<core_config::CoreConfig>,
        session_provider: Arc<dyn SessionProvider>,
        trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
    ) -> Self {
        Self {
            identifier_repository,
            key_repository,
            organisation_repository,
            trust_list_subscription_repository,
            trust_collection_repository,
            identifier_creator,
            config,
            session_provider,
            trust_list_subscriber_provider,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum IdentifierError {
    #[error("Identifier not found")]
    NotFound,
    #[error("Identifier with DID ID {0} not found")]
    NotFoundByDidId(uuid::Uuid),
}

impl IdentifierError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::NotFound => ErrorCode::BR_0207,
            Self::NotFoundByDidId(_) => ErrorCode::BR_0207,
        }
    }
}
