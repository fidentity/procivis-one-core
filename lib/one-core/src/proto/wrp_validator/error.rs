use crate::error::{ErrorCode, ErrorCodeMixin, NestedError};

#[derive(Debug, thiserror::Error)]
pub(crate) enum WRPValidatorError {
    #[error("Trust management disabled")]
    TrustManagementDisabled,

    #[error("Access certificate not trusted")]
    AccessCertificateNotTrusted,
    #[error("Missing organisation identifier")]
    MissingOrganisationIdentifier,

    #[error("No certificates specified in the chain")]
    EmptyChain,
    #[error("PEM error: `{0}`")]
    PEMError(#[from] x509_parser::error::PEMError),
    #[error("X509 nom error: `{0}`")]
    X509NomError(#[from] x509_parser::nom::Err<x509_parser::error::X509Error>),
    #[error("X509 error: `{0}`")]
    X509ParserError(#[from] x509_parser::error::X509Error),
    #[error("OID parse error: `{0}`")]
    OidParseError(#[from] asn1_rs::OidParseError),

    #[error("URL parsing error: `{0}`")]
    URLParsing(#[from] url::ParseError),

    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for WRPValidatorError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::TrustManagementDisabled => ErrorCode::BR_0412,
            Self::AccessCertificateNotTrusted => ErrorCode::BR_0410,
            Self::EmptyChain
            | Self::MissingOrganisationIdentifier
            | Self::PEMError(_)
            | Self::X509NomError(_)
            | Self::X509ParserError(_)
            | Self::OidParseError(_) => ErrorCode::BR_0224,
            Self::URLParsing(_) => ErrorCode::BR_0047,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}
