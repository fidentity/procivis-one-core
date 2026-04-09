use asn1_rs::Oid;
use x509_parser::pem::Pem;
use x509_parser::prelude::ParsedExtension;

use super::WRPValidatorError;

const OID_SERIAL_NUMBER: [u64; 4] = [2, 5, 4, 5];
const OID_ORG_ID: [u64; 4] = [2, 5, 4, 97];

const OID_CERTIFICATE_POLICIES_EXTENSION: [u64; 4] = [2, 5, 29, 32];
const OID_CERTIFICATE_POLICY_NATURAL_PERSON: [u64; 6] = [0, 4, 0, 194112, 1, 0];
const OID_CERTIFICATE_POLICY_LEGAL_PERSON: [u64; 6] = [0, 4, 0, 194112, 1, 1];

pub(super) fn rp_id_from_pem_chain(pem_chain: &str) -> Result<String, WRPValidatorError> {
    let leaf_pem = Pem::iter_from_buffer(pem_chain.as_bytes())
        .next()
        .ok_or(WRPValidatorError::EmptyChain)??;

    let certificate = leaf_pem.parse_x509()?;
    let subject = certificate.subject();

    let policies = certificate
        .get_extension_unique(&Oid::from(&OID_CERTIFICATE_POLICIES_EXTENSION)?)?
        .ok_or(WRPValidatorError::MissingOrganisationIdentifier)?;

    let ParsedExtension::CertificatePolicies(policies) = policies.parsed_extension() else {
        return Err(WRPValidatorError::MissingOrganisationIdentifier);
    };
    let policies: Vec<_> = policies
        .iter()
        .map(|policy| policy.policy_id.to_owned())
        .collect();

    let identifier = if policies.contains(&Oid::from(&OID_CERTIFICATE_POLICY_NATURAL_PERSON)?) {
        // ETSI 119 475 Table 3: identifier (natural person) → serialNumber (clause 5.1.5)
        subject.iter_by_oid(&Oid::from(&OID_SERIAL_NUMBER)?).next()
    } else if policies.contains(&Oid::from(&OID_CERTIFICATE_POLICY_LEGAL_PERSON)?) {
        // ETSI 119 475 Table 1: identifier (legal person) → organizationIdentifier (clause 5.1.3)
        subject.iter_by_oid(&Oid::from(&OID_ORG_ID)?).next()
    } else {
        return Err(WRPValidatorError::MissingOrganisationIdentifier);
    };

    Ok(identifier
        .ok_or(WRPValidatorError::MissingOrganisationIdentifier)?
        .as_str()?
        .to_string())
}

#[cfg(test)]
mod tests {
    use similar_asserts::assert_eq;

    use super::rp_id_from_pem_chain;

    const NATURAL_PERSON: &str = r#"-----BEGIN CERTIFICATE-----
MIIDAzCCAqugAwIBAgIRAfgZjZvWyEMdh9hZcC5L3vUwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAwwHQ0EgY2VydDAeFw0yNjA0MDkwODQ1NThaFw0zMTA0MDgwODQ1NTha
MHExCzAJBgNVBAYMAkNIMR0wGwYDVQRRDBRodHRwczovL3NvbWUtdXJsLmNvbTEU
MBIGA1UEAwwLY29tbW9uIG5hbWUxDjAMBgNVBAUMBW9yZ0lkMQwwCgYDVQQqDANN
YXgxDzANBgNVBAQMBk11c3RlcjAqMAUGAytlcAMhAEoEScmT7ovJTy1wxJgjDya+
jToTZbglVNJlE/Ulq+9fo4IBsDCCAawwHwYDVR0jBBgwFoAUNyjNsnb8v1K0L0Bt
EPf0uTxrQuAwRgYDVR0RBD8wPYYUaHR0cHM6Ly9zb21lLXVyaS5jb22gFAYDVQQU
oA0MCys0MTIzNDU2Nzg5gQ90ZXN0ZXJAdGVzdC5jb20wDgYDVR0PAQH/BAQDAgOI
MCUGA1UdJQQeMBwGCCsGAQUFBwMCBgcogYxdBQEGBgcogbU0BAEGMGIGA1UdHwRb
MFkwV6BVoFOGUWh0dHA6Ly8xMjcuMC4wLjE6NjEzNTgvc3NpL3Jldm9jYXRpb24v
djEvY3JsLzg2ZjY4NTdjLTRlNGQtNDNiZC04NzliLWZiYTUyMjA2N2VlZjAdBgNV
HQ4EFgQUYSDrfq7B9LW8JqFf8Goypix19fswDwYDVR0TAQH/BAUwAwEBADAUBgNV
HSAEDTALMAkGBwQAi+xAAQAwYAYIKwYBBQUHAQEEVDBSMFAGCCsGAQUFBzACpkQW
Qmh0dHA6Ly8xMjcuMC4wLjE6NjEzNTgvc3NpL2NhLzMwMzc0M2UxLTYzYzctNDAz
My05OTUwLWRkZGU2ZTQxN2UyOTAKBggqhkjOPQQDAgNGADBDAiAOXUDvoNYh6os0
MET+cTAhlpnzMZzZciWyRY7poIhybgIfNaBOINmvSSI6tZZZzdp+cQswXKlhYnC4
15XEHVrAsA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBiTCCAS+gAwIBAgIUEiXvMbJt3TJwCJ56URr8IqLUqeowCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHQ0EgY2VydDAeFw0yNDA1MDkwODQ1NThaFw0zNTExMDgwODQ1
NThaMBIxEDAOBgNVBAMMB0NBIGNlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARx38tO0JCdq3ZecMSW6a+BAAzllydQxVOQ+KDjnwLXJ4mkJj1IIq/NCNlwhap9
vyj6nVh9D8TMwgj/Ft7j8ZVAo2MwYTAfBgNVHSMEGDAWgBQ3KM2ydvy/UrQvQG0Q
9/S5PGtC4DAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDcozbJ2/L9StC9AbRD3
9Lk8a0LgMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgBbQUKzrX
fQ0/dtdRF6pNnX+uPATW5lz0SKX5VmzrJA0CIQCHG/0OYHHvkyfsKay0BnIpEBEc
4goBKclrxu4HRPWr/Q==
-----END CERTIFICATE-----"#;

    const LEGAL_PERSON: &str = r#"-----BEGIN CERTIFICATE-----
MIIC+jCCAp+gAwIBAgIRAQrC1dwJkUxlszrpRjXZv+QwCgYIKoZIzj0EAwIwEjEQ
MA4GA1UEAwwHQ0EgY2VydDAeFw0yNjA0MDkwODQzMDhaFw0zMTA0MDgwODQzMDha
MGUxCzAJBgNVBAYMAkNIMR0wGwYDVQRRDBRodHRwczovL3NvbWUtdXJsLmNvbTEU
MBIGA1UEAwwLY29tbW9uIG5hbWUxDjAMBgNVBGEMBW9yZ0lkMREwDwYDVQQKDAhP
cmcgbmFtZTAqMAUGAytlcAMhAEoEScmT7ovJTy1wxJgjDya+jToTZbglVNJlE/Ul
q+9fo4IBsDCCAawwHwYDVR0jBBgwFoAUNyjNsnb8v1K0L0BtEPf0uTxrQuAwRgYD
VR0RBD8wPYYUaHR0cHM6Ly9zb21lLXVyaS5jb22gFAYDVQQUoA0MCys0MTIzNDU2
Nzg5gQ90ZXN0ZXJAdGVzdC5jb20wDgYDVR0PAQH/BAQDAgOIMCUGA1UdJQQeMBwG
CCsGAQUFBwMCBgcogYxdBQEGBgcogbU0BAEGMGIGA1UdHwRbMFkwV6BVoFOGUWh0
dHA6Ly8xMjcuMC4wLjE6NjEzNDYvc3NpL3Jldm9jYXRpb24vdjEvY3JsLzJiYzE2
MjllLWM2YWItNGNlNy1hMTlkLWYwN2Q1M2YwYzU3NzAdBgNVHQ4EFgQUYSDrfq7B
9LW8JqFf8Goypix19fswDwYDVR0TAQH/BAUwAwEBADAUBgNVHSAEDTALMAkGBwQA
i+xAAQEwYAYIKwYBBQUHAQEEVDBSMFAGCCsGAQUFBzACpkQWQmh0dHA6Ly8xMjcu
MC4wLjE6NjEzNDYvc3NpL2NhL2Q3NzgxNGI1LWIxZGMtNDIwNS1iZDlmLTA5OGE4
ZTRjNDlkZDAKBggqhkjOPQQDAgNJADBGAiEAuS3o1nlzchI4I0ag0qUxpAUD8/ot
qs3spp6Rlr/mP9wCIQDVavmou3AtikpwkUWe+ZM5HbrwAi6k6lt5nxTPk3tf0A==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIBiDCCAS+gAwIBAgIUEiXvMbJt3TJwCJ56URr8IqLUqeowCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHQ0EgY2VydDAeFw0yNDA1MDkwODQzMDhaFw0zNTExMDgwODQz
MDhaMBIxEDAOBgNVBAMMB0NBIGNlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AARx38tO0JCdq3ZecMSW6a+BAAzllydQxVOQ+KDjnwLXJ4mkJj1IIq/NCNlwhap9
vyj6nVh9D8TMwgj/Ft7j8ZVAo2MwYTAfBgNVHSMEGDAWgBQ3KM2ydvy/UrQvQG0Q
9/S5PGtC4DAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDcozbJ2/L9StC9AbRD3
9Lk8a0LgMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgb03wMpPQ
RTR8h4so2dqOjgIvuaCwEI9OQVS6F0W5HbUCIFzPiE5kAATzkMNAbzumvMuA3bL/
KqyEej23GXbZ9gL6
-----END CERTIFICATE-----"#;

    #[test]
    fn test_natual_person_access_certificate() {
        let rp_id = rp_id_from_pem_chain(NATURAL_PERSON).unwrap();
        assert_eq!(rp_id, "orgId");
    }

    #[test]
    fn test_legal_person_access_certificate() {
        let rp_id = rp_id_from_pem_chain(LEGAL_PERSON).unwrap();
        assert_eq!(rp_id, "orgId");
    }
}
