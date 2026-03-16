use crate::model::revocation_list::RevocationListEntryState;
use crate::service::signature::dto::SignatureState;
use crate::service::signature::error::SignatureServiceError;

impl TryFrom<RevocationListEntryState> for SignatureState {
    type Error = SignatureServiceError;

    fn try_from(value: RevocationListEntryState) -> Result<Self, Self::Error> {
        match value {
            RevocationListEntryState::Active => Ok(Self::Active),
            RevocationListEntryState::Revoked => Ok(Self::Revoked),
            RevocationListEntryState::Suspended => Err(SignatureServiceError::MappingError(
                format!("Invalid signature revocation status: {:?}", value),
            )),
        }
    }
}
