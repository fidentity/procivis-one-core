use crate::config::core_config::DatatypeType;
use crate::provider::issuance_protocol::error::IssuanceProtocolError;

pub(super) fn to_swiyu_data_type(
    data_type: DatatypeType,
) -> Result<&'static str, IssuanceProtocolError> {
    Ok(match data_type {
        // Swiyu handling of data and booleans is different in the iOS and Android wallets so it is
        // declared as string.
        DatatypeType::String | DatatypeType::Date | DatatypeType::Boolean => "string",
        DatatypeType::Number => "numeric",
        DatatypeType::SwiyuPicture => "image/jpeg",
        _ => {
            return Err(IssuanceProtocolError::Failed(format!(
                "Unsupported data type: {data_type:?}"
            )));
        }
    })
}
