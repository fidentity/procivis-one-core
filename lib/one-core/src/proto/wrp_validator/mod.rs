use std::sync::Arc;

use shared_types::OrganisationId;

use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::model::list_filter::ListFilterValue;
use crate::model::trust_collection::{TrustCollectionFilterValue, TrustCollectionListQuery};
use crate::model::trust_list_role::TrustListRoleEnum;
use crate::model::trust_list_subscription::{
    TrustListSubscription, TrustListSubscriptionFilterValue, TrustListSubscriptionListQuery,
    TrustListSubscriptionState,
};
use crate::proto::wallet_provider_client::WalletProviderClient;
use crate::provider::trust_list_subscriber::TrustEntityResponse;
use crate::provider::trust_list_subscriber::provider::TrustListSubscriberProvider;
use crate::repository::holder_wallet_unit_repository::HolderWalletUnitRepository;
use crate::repository::trust_collection_repository::TrustCollectionRepository;
use crate::repository::trust_list_subscription_repository::TrustListSubscriptionRepository;
use crate::service::error::MissingProviderError;

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
#[expect(unused)]
pub(crate) trait WRPValidator: Send + Sync {
    /// Resolve WRPAC trust information
    async fn get_access_certificate_trust(
        &self,
        pem_chain: &str,
        organisation_id: OrganisationId,
    ) -> Result<TrustEntityResponse, Error>;
}

#[derive(Debug, thiserror::Error)]
#[expect(unused)]
pub(crate) enum Error {
    #[error("Trust management disabled")]
    TrustManagementDisabled,

    #[error("Access certificate not trusted")]
    AccessCertificateNotTrusted,

    #[error("URL parsing error: `{0}`")]
    URLParsing(#[from] url::ParseError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for Error {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::TrustManagementDisabled => ErrorCode::BR_0412,
            Self::AccessCertificateNotTrusted => ErrorCode::BR_0410,
            Self::URLParsing(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

pub(crate) struct WRPValidatorImpl {
    trust_collection_repository: Arc<dyn TrustCollectionRepository>,
    trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
    trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
    holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
    wallet_provider_client: Arc<dyn WalletProviderClient>,
}

impl WRPValidatorImpl {
    pub(crate) fn new(
        trust_collection_repository: Arc<dyn TrustCollectionRepository>,
        trust_list_subscription_repository: Arc<dyn TrustListSubscriptionRepository>,
        trust_list_subscriber_provider: Arc<dyn TrustListSubscriberProvider>,
        holder_wallet_unit_repository: Arc<dyn HolderWalletUnitRepository>,
        wallet_provider_client: Arc<dyn WalletProviderClient>,
    ) -> Self {
        Self {
            trust_collection_repository,
            trust_list_subscription_repository,
            trust_list_subscriber_provider,
            holder_wallet_unit_repository,
            wallet_provider_client,
        }
    }
}

#[async_trait::async_trait]
impl WRPValidator for WRPValidatorImpl {
    async fn get_access_certificate_trust(
        &self,
        pem_chain: &str,
        organisation_id: OrganisationId,
    ) -> Result<TrustEntityResponse, Error> {
        self.check_trust_management_enabled(organisation_id).await?;

        let subscriptions = self
            .get_trust_subscriptions_for_role(TrustListRoleEnum::WrpAcProvider, organisation_id)
            .await?;

        for subscription in subscriptions {
            if let Some(entity) = self
                .check_subscription_match(subscription, pem_chain)
                .await?
            {
                return Ok(entity);
            }
        }

        Err(Error::AccessCertificateNotTrusted)
    }
}

impl WRPValidatorImpl {
    #[expect(unused)]
    async fn check_trust_management_enabled(
        &self,
        organisation_id: OrganisationId,
    ) -> Result<(), Error> {
        let holder_wallet_unit = self
            .holder_wallet_unit_repository
            .get_holder_wallet_unit_by_org_id(&organisation_id)
            .await
            .error_while("getting holder wallet unit")?
            // if holder wallet unit not registered, it means the trust management was not setup, thus disabled
            .ok_or(Error::TrustManagementDisabled)?;

        let metadata = self
            .wallet_provider_client
            .get_wallet_provider_metadata(holder_wallet_unit.into())
            .await
            .error_while("getting wallet provider metadata")?;

        if !metadata.feature_flags.trust_ecosystems_enabled {
            // trust management disabled via provider metadata
            return Err(Error::TrustManagementDisabled);
        }

        Ok(())
    }

    #[expect(unused)]
    async fn get_trust_subscriptions_for_role(
        &self,
        role: TrustListRoleEnum,
        organisation_id: OrganisationId,
    ) -> Result<Vec<TrustListSubscription>, Error> {
        let collections = self
            .trust_collection_repository
            .list(TrustCollectionListQuery {
                filtering: Some(
                    TrustCollectionFilterValue::OrganisationId(organisation_id).condition()
                        & TrustCollectionFilterValue::Remote(true)
                        & TrustCollectionFilterValue::Empty(false),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting trust collections")?
            .values
            .into_iter()
            .map(|c| c.id)
            .collect();

        Ok(self
            .trust_list_subscription_repository
            .list(TrustListSubscriptionListQuery {
                filtering: Some(
                    TrustListSubscriptionFilterValue::TrustCollectionId(collections).condition()
                        & TrustListSubscriptionFilterValue::State(vec![
                            TrustListSubscriptionState::Active,
                        ])
                        & TrustListSubscriptionFilterValue::Role(vec![role]),
                ),
                ..Default::default()
            })
            .await
            .error_while("getting trust list subscriptions")?
            .values)
    }

    #[expect(unused)]
    async fn check_subscription_match(
        &self,
        subscription: TrustListSubscription,
        pem_chain: &str,
    ) -> Result<Option<TrustEntityResponse>, Error> {
        let subscriber = self
            .trust_list_subscriber_provider
            .get(&subscription.r#type)
            .ok_or(MissingProviderError::TrustListSubscriber(
                subscription.r#type,
            ))
            .error_while("getting trust list subscriber")?;

        Ok(subscriber
            .resolve_certificate(&subscription.reference.parse()?, pem_chain)
            .await
            .error_while("resolving access certificate trust")?)
    }
}
