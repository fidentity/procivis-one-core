use crate::model::holder_wallet_unit::HolderWalletUnit;
use crate::model::wallet_unit::WalletProviderType;
use crate::service::wallet_provider::dto::IssueWalletUnitAttestationResponseDTO;
use crate::service::wallet_unit::dto::WalletProviderDTO;

#[derive(Clone, Debug)]
pub enum IssueWalletAttestationResponse {
    Active(IssueWalletUnitAttestationResponseDTO),
    Revoked,
}

#[derive(Clone, Debug)]
pub struct MetadataTarget {
    pub r#type: WalletProviderType,
    pub metadata_url: String,
}

impl From<WalletProviderDTO> for MetadataTarget {
    fn from(value: WalletProviderDTO) -> Self {
        Self {
            r#type: value.r#type,
            metadata_url: value.url,
        }
    }
}

impl From<HolderWalletUnit> for MetadataTarget {
    fn from(value: HolderWalletUnit) -> Self {
        let HolderWalletUnit {
            wallet_provider_url,
            wallet_provider_type,
            wallet_provider_name,
            ..
        } = value;
        Self {
            r#type: wallet_provider_type,
            metadata_url: format!(
                "{wallet_provider_url}/ssi/wallet-provider/v1/{wallet_provider_name}"
            ),
        }
    }
}
