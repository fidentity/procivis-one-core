use asn1_rs::Oid;
use x509_parser::pem::Pem;

use super::WRPValidatorError;

pub(super) fn rp_id_from_pem_chain(pem_chain: &str) -> Result<String, WRPValidatorError> {
    let leaf_pem = Pem::iter_from_buffer(pem_chain.as_bytes())
        .next()
        .ok_or(WRPValidatorError::EmptyChain)??;

    let certificate = leaf_pem.parse_x509()?;

    const OID_ORG_ID: [u64; 4] = [2, 5, 4, 97];

    let org_id = certificate
        .subject()
        .iter_by_oid(&Oid::from(&OID_ORG_ID)?)
        .next()
        .ok_or(WRPValidatorError::MissingOrganisationIdentifier)?
        .as_str()?;

    Ok(org_id.to_string())
}
