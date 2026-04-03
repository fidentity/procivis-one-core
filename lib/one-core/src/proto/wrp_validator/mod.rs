use error::WRPValidatorError;
use shared_types::OrganisationId;

use crate::provider::signer::registration_certificate::model::Payload;
use crate::provider::trust_list_subscriber::TrustEntityResponse;

pub(crate) mod error;
pub(crate) mod validator;
mod x509;

#[expect(unused)]
pub(crate) struct AccessCertificateTrustResult {
    pub trust_entity: TrustEntityResponse,
    pub rp_id: String,
}

#[expect(unused)]
pub(crate) struct RegistrationCertificateResult {
    pub trust_entity: Option<TrustEntityResponse>,
    pub payload: Payload,
}

#[cfg_attr(any(test, feature = "mock"), mockall::automock)]
#[async_trait::async_trait]
pub(crate) trait WRPValidator: Send + Sync {
    /// Resolve WRPAC trust information
    async fn get_access_certificate_trust(
        &self,
        pem_chain: &str,
        organisation_id: OrganisationId,
    ) -> Result<AccessCertificateTrustResult, WRPValidatorError>;

    #[expect(unused)]
    async fn validate_registration_certificate(
        &self,
        wrprc_jwt: &str,
        expected_rp_id: &str,
        validate_trust: Option<OrganisationId>,
    ) -> Result<RegistrationCertificateResult, WRPValidatorError>;
}
