// ETSI TS 119 475 v1.2.1 (2026-03), Annex C
// (without "sub" and "iat")
const PAYLOAD: &str = r#"
{
  "name": "Example Company",
  "sub_ln": "Example Company GmbH",
  "country": "DE",
  "registry_uri": "https://registrar.com",
  "srv_description": [
    [
      {
        "lang": "en-US",
        "value": "Awesome Service by Example Company"
      },
      {
        "lang": "de-DE",
        "value": "Super Dienst von Example Company"
      }
    ]
  ],
  "entitlements": [
    "https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider"
  ],
  "privacy_policy": "https://example.com/privacy-policy",
  "info_uri": "https://example.com/info",
  "support_uri": "https://example.com/support",
  "supervisory_authority": {
    "email": "supervisory@dpa.com",
    "phone": "+49 123 4567890",
    "uri": "https://dpa.com/supervisory-authority"
  },
  "policy_id": [
    "0.4.0.19475.3.1"
  ],
  "certificate_policy": "https://registrar.com/certificate-policy",
  "status": {
    "status_list": {
      "idx": 0,
      "uri": "https://example.com/statuslists/1"
    }
  },
  "purpose": [
    {
      "lang": "en-US",
      "value": "Required for checking the minimum age"
    },
    {
      "lang": "de-DE",
      "value": "Benötigt für die Überprüfung des Mindestalters"
    }
  ],
  "credentials": [
    {
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [
          "urn:eudi:pid:de:1"
        ]
      },
      "claim": [
        {
          "path": [
            "age_equal_or_over",
            "18"
          ]
        }
      ]
    },
    {
      "format": "mso_mdoc",
      "meta": {
        "doctype_value": "eu.europa.ec.eudi.pid.1"
      },
      "claim": [
        {
          "path": [
            "eu.europa.ec.eudi.pid.1",
            "age_over_18"
          ]
        }
      ]
    }
  ],
  "provides_attestations": [
    {
      "format": "dc+sd-jwt",
      "meta": {
        "vct_values": [
          "https://example.com/attestations/age_over_18"
        ]
      }
    }
  ],
  "intermediary": {
    "sub": "LEIXG-INTERMEDIARY-1234567890",
    "name": "Intermediary Services Ltd."
  }
}
"#;

#[test]
fn deserialize_example_registration_certificate() {
    serde_json::from_str::<super::model::Payload>(PAYLOAD).unwrap();
}

#[test]
fn deserialize_subject_cannot_have_legal_and_natural_names() {
    const DOCUMENT: &str = r#"{"id": "XYZ", "first_name": "Janusz", "last_name": "Tytanowy", "legal_name": "Januszex sp. z o.o"}"#;
    assert!(
        serde_json::from_str::<super::model::Subject>(DOCUMENT)
            .unwrap_err()
            .is_data()
    );
}

#[test]
fn deserialize_subject_natural_person_must_have_first_name() {
    const DOCUMENT: &str = r#"{"id": "XYZ", "last_name": "Tytanowy"}"#;
    assert!(
        serde_json::from_str::<super::model::Subject>(DOCUMENT)
            .unwrap_err()
            .is_data()
    );
}

#[test]
fn deserialize_subject_natural_person_must_have_last_name() {
    const DOCUMENT: &str = r#"{"id": "XYZ", "first_name": "Janusz"}"#;
    assert!(
        serde_json::from_str::<super::model::Subject>(DOCUMENT)
            .unwrap_err()
            .is_data()
    );
}

#[test]
fn deserialize_serialize_entitlement() {
    const ENTITLEMENTS: &[&str] = &[
        "\"id-etsi-wrpa-entitlement 1\"",
        "\"https://uri.etsi.org/19475/Entitlement/Service_Provider\"",
        "\"id-etsi-wrpa-entitlement 2\"",
        "\"https://uri.etsi.org/19475/Entitlement/QEAA_Provider\"",
        "\"id-etsi-wrpa-entitlement 3\"",
        "\"https://uri.etsi.org/19475/Entitlement/Non_Q_EAA_Provider\"",
        "\"id-etsi-wrpa-entitlement 4\"",
        "\"https://uri.etsi.org/19475/Entitlement/PUB_EAA_Provider\"",
        "\"id-etsi-wrpa-entitlement 5\"",
        "\"https://uri.etsi.org/19475/Entitlement/PID_Provider\"",
        "\"id-etsi-wrpa-entitlement 6\"",
        "\"https://uri.etsi.org/19475/Entitlement/QCert_for_ESeal_Provider\"",
        "\"id-etsi-wrpa-entitlement 7\"",
        "\"https://uri.etsi.org/19475/Entitlement/QCert_for_ESig_Provider\"",
        "\"id-etsi-wrpa-entitlement 8\"",
        "\"https://uri.etsi.org/19475/Entitlement/rQSealCDs_Provider\"",
        "\"id-etsi-wrpa-entitlement 9\"",
        "\"https://uri.etsi.org/19475/Entitlement/rQSigCDs_Provider\"",
        "\"id-etsi-wrpa-entitlement 10\"",
        "\"https://uri.etsi.org/19475/Entitlement/ESig_ESeal_Creation_Provider\"",
    ];

    for input in ENTITLEMENTS {
        let deserialized: super::model::Entitlement = serde_json::from_str(input).unwrap();
        let serialized = serde_json::to_string(&deserialized).unwrap();
        similar_asserts::assert_eq!(serialized.as_str(), *input);
    }
}

#[test]
fn deserialize_claim_value_ok() {
    const DOCUMENT: &str = r#"{"path": ["first", "second"], "values": ["string", 10, -40, false]}"#;
    serde_json::from_str::<super::model::Claim>(DOCUMENT).unwrap();
}

#[test]
fn deserialize_claim_value_invalid() {
    const DOCUMENT: &str = r#"{"path": [], "values": [21.37]}"#;
    assert!(
        serde_json::from_str::<super::model::Claim>(DOCUMENT)
            .unwrap_err()
            .is_data()
    );
}
