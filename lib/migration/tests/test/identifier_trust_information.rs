use crate::fixtures::{ColumnType, get_schema};

#[tokio::test]
async fn test_db_schema_identifier_trust_information() {
    let schema = get_schema().await;

    let columns = vec![
        "id",
        "identifier_id",
        "blob_id",
        "created_date",
        "last_modified",
        "valid_from",
        "valid_to",
        "intended_use",
        "allowed_issuance_types",
        "allowed_verification_types",
    ];

    let trust_information = schema
        .table("identifier_trust_information")
        .columns(&columns)
        .index(
            "index-IdentifierTrustInformation-IdentifierId-BlobId-Unique",
            true,
            &["identifier_id", "blob_id"],
        );
    trust_information
        .column("id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .default(None)
        .primary_key();
    trust_information
        .column("created_date")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_information
        .column("last_modified")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(false)
        .default(None);
    trust_information
        .column("valid_from")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    trust_information
        .column("valid_to")
        .r#type(ColumnType::TimestampMilliseconds)
        .nullable(true);
    trust_information
        .column("intended_use")
        .r#type(ColumnType::String(None))
        .nullable(true);
    trust_information
        .column("allowed_issuance_types")
        .r#type(ColumnType::String(Some(512)))
        .nullable(true);
    trust_information
        .column("allowed_verification_types")
        .r#type(ColumnType::String(Some(512)))
        .nullable(true);
    trust_information
        .column("identifier_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .foreign_key(
            "fk-IdentifierTrustInformation-Identifier",
            "identifier",
            "id",
        );
    trust_information
        .column("blob_id")
        .r#type(ColumnType::Uuid)
        .nullable(false)
        .foreign_key(
            "fk-IdentifierTrustInformation-BlobStorage",
            "blob_storage",
            "id",
        );
}
