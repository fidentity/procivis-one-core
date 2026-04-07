use std::collections::{HashMap, HashSet};
use std::slice::from_ref;

use ct_codecs::{Base64, Encoder};
use one_dto_mapper::try_convert_inner;
use standardized_types::etsi_119_602::{
    LoTEPayload, MultiLangString, TrustedEntity, TrustedEntityInformation,
};
use standardized_types::jwk::PublicJwk;
use x509_parser::error::X509Error;
use x509_parser::oid_registry::OID_X509_EXT_SUBJECT_KEY_IDENTIFIER;

use super::model::PreprocessedLote;
use crate::error::{ContextWithErrorCode, ErrorCode, ErrorCodeMixin, NestedError};
use crate::mapper::x509::x5c_into_pem_chain;
use crate::proto::certificate_validator::parse::extract_leaf_pem_from_chain;
use crate::proto::certificate_validator::{CertificateValidationOptions, CertificateValidator};
use crate::provider::key_algorithm::provider::KeyAlgorithmProvider;

#[derive(Debug, thiserror::Error)]
pub enum LotePreprocessingError {
    #[error("Invalid trust list content: {0}")]
    InvalidContent(Box<dyn std::error::Error + Send + Sync>),
    #[error("Missing certificates on entity `{entity:?}` in service `{service:?}`")]
    MissingCertificates {
        entity: Vec<MultiLangString>,
        service: Vec<MultiLangString>,
    },
    #[error(
        "Attribute `{attribute}` on entity `{entity:?}` in service `{service:?}` is not present in any certificate"
    )]
    InconsistentDigitalIdentityInformation {
        attribute: String,
        entity: Vec<MultiLangString>,
        service: Vec<MultiLangString>,
    },
    #[error("Encoding error: `{0}`")]
    Encoding(#[from] ct_codecs::Error),
    #[error(transparent)]
    Nested(#[from] NestedError),
}

impl ErrorCodeMixin for LotePreprocessingError {
    fn error_code(&self) -> ErrorCode {
        match self {
            Self::InvalidContent(_)
            | Self::MissingCertificates { .. }
            | Self::InconsistentDigitalIdentityInformation { .. } => ErrorCode::BR_0393,
            Self::Encoding(_) => ErrorCode::BR_0397,
            Self::Nested(nested) => nested.error_code(),
        }
    }
}

impl From<serde_json::Error> for LotePreprocessingError {
    fn from(err: serde_json::Error) -> Self {
        LotePreprocessingError::InvalidContent(Box::new(err))
    }
}

impl From<X509Error> for LotePreprocessingError {
    fn from(err: X509Error) -> Self {
        LotePreprocessingError::InvalidContent(Box::new(err))
    }
}

impl From<asn1_rs::Err<X509Error>> for LotePreprocessingError {
    fn from(err: asn1_rs::Err<X509Error>) -> Self {
        LotePreprocessingError::InvalidContent(Box::new(err))
    }
}

pub(super) async fn preprocess_lote(
    lote: LoTEPayload,
    certificate_validator: &dyn CertificateValidator,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<PreprocessedLote, LotePreprocessingError> {
    let lote_type = try_convert_inner(lote.list_and_scheme_information.lote_type.clone())
        .unwrap_or_else(|err| {
            tracing::warn!("Discarding unsupported LoTE type: `{err}`");
            None
        });
    let mut preprocessed_lote = PreprocessedLote {
        role: lote_type,
        trusted_entities: Vec::new(),
        certificate_fingerprints: HashMap::new(),
    };
    let Some(trusted_entities) = lote.trusted_entities_list else {
        return Ok(preprocessed_lote);
    };
    for (idx, trusted_entity) in trusted_entities.into_iter().enumerate() {
        let PreprocessingResult {
            entity,
            fingerprints,
        } = preprocess_trusted_entity(
            trusted_entity,
            certificate_validator,
            key_algorithm_provider,
        )
        .await?;
        preprocessed_lote.trusted_entities.push(entity);
        for fingerprint in fingerprints {
            preprocessed_lote
                .certificate_fingerprints
                .insert(fingerprint, idx);
        }
    }
    Ok(preprocessed_lote)
}

struct PreprocessingResult {
    entity: TrustedEntityInformation,
    fingerprints: Vec<String>,
}

async fn preprocess_trusted_entity(
    trusted_entity: TrustedEntity,
    certificate_validator: &dyn CertificateValidator,
    key_algorithm_provider: &dyn KeyAlgorithmProvider,
) -> Result<PreprocessingResult, LotePreprocessingError> {
    let mut fingerprints = HashSet::new();
    let mut subject_key_identifiers = HashSet::new();
    let mut subject_names = HashSet::new();
    let mut public_keys = HashSet::new();
    for service in trusted_entity.trusted_entity_services {
        let Some(identity) = service.service_information.service_digital_identity else {
            continue;
        };

        let Some(lote_certs) = &identity.x509_certificates else {
            return Err(LotePreprocessingError::MissingCertificates {
                entity: trusted_entity.trusted_entity_information.te_name.clone(),
                service: service.service_information.service_name.clone(),
            });
        };
        if lote_certs.is_empty() {
            return Err(LotePreprocessingError::MissingCertificates {
                entity: trusted_entity.trusted_entity_information.te_name.clone(),
                service: service.service_information.service_name.clone(),
            });
        }

        for cert in lote_certs {
            let pem_chain = x5c_into_pem_chain(from_ref(&cert.val))
                .error_while("encoding certificate to PEM")?;

            // General validation
            let validated_cert = certificate_validator
                .parse_pem_chain(
                    &pem_chain,
                    CertificateValidationOptions::signature_and_revocation(None),
                )
                .await
                .error_while("validating certificate")?;
            fingerprints.insert(validated_cert.attributes.fingerprint);

            let pem = extract_leaf_pem_from_chain(pem_chain.as_bytes())
                .error_while("parsing certificate value")?;
            let cert = pem.parse_x509()?;
            let der_b64 = Base64::encode_to_string(cert.public_key().raw)?;
            public_keys.insert(der_b64);
            if let Some(ski_ext) =
                cert.get_extension_unique(&OID_X509_EXT_SUBJECT_KEY_IDENTIFIER)?
            {
                let subject_key_identifier = Base64::encode_to_string(ski_ext.value)?;
                subject_key_identifiers.insert(subject_key_identifier);
            }
            subject_names.insert(cert.subject.to_string());
        }

        // validate consistency
        if let Some(skis) = &identity.x509_skis {
            for ski in skis {
                if !subject_key_identifiers.contains(ski) {
                    return Err(
                        LotePreprocessingError::InconsistentDigitalIdentityInformation {
                            attribute: format!("Subject key identifier `{ski}`"),
                            entity: trusted_entity.trusted_entity_information.te_name.clone(),
                            service: service.service_information.service_name.clone(),
                        },
                    );
                }
            }
        }
        if let Some(names) = &identity.x509_subject_names {
            for name in names {
                if !subject_names.contains(name) {
                    return Err(
                        LotePreprocessingError::InconsistentDigitalIdentityInformation {
                            attribute: format!("Subject name `{name}`"),
                            entity: trusted_entity.trusted_entity_information.te_name.clone(),
                            service: service.service_information.service_name.clone(),
                        },
                    );
                }
            }
        }
        if let Some(jwks) = &identity.public_key_values {
            for jwk in jwks {
                let public_key: PublicJwk = serde_json::from_value(jwk.clone())?;
                let parsed_key = key_algorithm_provider
                    .parse_jwk(&public_key)
                    .error_while("parsing public JWK")?;
                let der_b64 = Base64::encode_to_string(
                    parsed_key
                        .key
                        .public_key_as_der()
                        .error_while("encoding public key to DER")?,
                )?;
                if !public_keys.contains(&der_b64) {
                    return Err(
                        LotePreprocessingError::InconsistentDigitalIdentityInformation {
                            attribute: format!("Public key `{jwk}`"),
                            entity: trusted_entity.trusted_entity_information.te_name.clone(),
                            service: service.service_information.service_name.clone(),
                        },
                    );
                }
            }
        }
    }

    if fingerprints.is_empty() {
        return Err(LotePreprocessingError::InvalidContent(
            format!(
                "No digital identity information for entity `{:?}`",
                trusted_entity.trusted_entity_information.te_name
            )
            .into(),
        ));
    }

    Ok(PreprocessingResult {
        entity: trusted_entity.trusted_entity_information,
        fingerprints: fingerprints.into_iter().collect(),
    })
}
