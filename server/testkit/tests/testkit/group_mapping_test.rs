#![deny(warnings)]
//! Integration tests for PR-GROUPS-PIPELINE (feature 008-dex-groups-pipeline) —
//! admin CRUD on upstream-to-netidm group mappings.
//!
//! Covers User Story 1 acceptance scenarios and FR-001..FR-008:
//!   * Add/list/remove round-trip on an OAuth2 upstream client.
//!   * Add/list/remove round-trip on a SAML upstream client (mirrors).
//!   * Accepts a netidm group either by name (resolved at the CLI / test
//!     setup) or by UUID — the client SDK takes a `Uuid` directly, so both
//!     CLI input forms feed into the same SDK call.
//!   * Duplicate-add is rejected (FR-007a) — error surfaces, storage
//!     unchanged.
//!   * Unknown netidm group UUID in an add call is stored verbatim (the
//!     server does not pre-validate group existence), consistent with
//!     research.md D7 and FR-006's CLI-side enforcement.
//!   * Remove of a non-existent mapping is idempotent: no error, no change.

use netidm_client::saml::SamlClientConfig;
use netidm_proto::constants::{
    ATTR_DISPLAYNAME, ATTR_NAME, ATTR_OAUTH2_AUTHORISATION_ENDPOINT, ATTR_OAUTH2_CLIENT_ID,
    ATTR_OAUTH2_CLIENT_SECRET, ATTR_OAUTH2_GROUP_MAPPING, ATTR_OAUTH2_REQUEST_SCOPES,
    ATTR_OAUTH2_TOKEN_ENDPOINT, ATTR_SAML_GROUP_MAPPING,
};
use netidm_proto::v1::Entry;
use netidmd_testkit::{test, ADMIN_TEST_PASSWORD, ADMIN_TEST_USER};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Create an OAuth2 upstream connector usable as the test subject.
///
/// Constructed directly (rather than via `idm_oauth2_client_create_github`)
/// so we pass scopes that match the server's `OAUTHSCOPE_RE` regex
/// (`^[0-9a-zA-Z_]+$`) — GitHub's real scopes (`read:user`, `user:email`)
/// contain `:` and are rejected by the schema validator on write.
async fn setup_oauth2_client(
    rsclient: &netidm_client::NetidmClient,
    name: &str,
) -> Result<(), netidm_client::ClientError> {
    let mut entry = Entry {
        attrs: BTreeMap::new(),
    };
    entry
        .attrs
        .insert(ATTR_NAME.to_string(), vec![name.to_string()]);
    entry
        .attrs
        .insert(ATTR_DISPLAYNAME.to_string(), vec![name.to_string()]);
    entry.attrs.insert(
        ATTR_OAUTH2_CLIENT_ID.to_string(),
        vec!["test-client-id".to_string()],
    );
    entry.attrs.insert(
        ATTR_OAUTH2_CLIENT_SECRET.to_string(),
        vec!["test-client-secret".to_string()],
    );
    entry.attrs.insert(
        ATTR_OAUTH2_AUTHORISATION_ENDPOINT.to_string(),
        vec!["https://upstream.example.com/auth".to_string()],
    );
    entry.attrs.insert(
        ATTR_OAUTH2_TOKEN_ENDPOINT.to_string(),
        vec!["https://upstream.example.com/token".to_string()],
    );
    entry.attrs.insert(
        ATTR_OAUTH2_REQUEST_SCOPES.to_string(),
        vec!["openid".to_string(), "profile".to_string()],
    );
    rsclient
        .perform_post_request::<Entry, ()>("/v1/oauth2/_client", entry)
        .await
}

/// Create a netidm group and return its UUID.
async fn create_group(rsclient: &netidm_client::NetidmClient, name: &str) -> Uuid {
    rsclient
        .idm_group_create(name, None)
        .await
        .expect("Failed to create netidm group");
    let entry = rsclient
        .idm_group_get(name)
        .await
        .expect("Failed to look up created group")
        .expect("created group not found in subsequent lookup");
    let uuid_str = entry
        .attrs
        .get(netidm_proto::constants::ATTR_UUID)
        .and_then(|v| v.first())
        .expect("group entry missing uuid");
    Uuid::parse_str(uuid_str).expect("group uuid unparseable")
}

// ============================================================================
// OAuth2 upstream client tests
// ============================================================================

/// US1 Acceptance 1, 2, 3, 5 — add a mapping (by UUID), list, remove.
#[test]
async fn tk_test_oauth2_client_group_mapping_crud(rsclient: &netidm_client::NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin");

    setup_oauth2_client(rsclient, "test-oauth2-crud")
        .await
        .expect("Failed to create test OAuth2 upstream");

    let admins_uuid = create_group(rsclient, "test-mapping-admins").await;

    // Initially no mappings.
    let mappings = rsclient
        .idm_oauth2_client_list_group_mappings("test-oauth2-crud")
        .await
        .expect("list-mappings failed on empty connector");
    assert!(
        mappings.is_empty(),
        "expected no mappings on fresh connector"
    );

    // Add one.
    rsclient
        .idm_oauth2_client_add_group_mapping("test-oauth2-crud", "approovia/admins", admins_uuid)
        .await
        .expect("add-group-mapping failed");

    // List shows exactly the mapping we added.
    let mappings = rsclient
        .idm_oauth2_client_list_group_mappings("test-oauth2-crud")
        .await
        .expect("list-mappings failed after add");
    assert_eq!(mappings.len(), 1, "expected one mapping after add");
    assert_eq!(mappings[0].0, "approovia/admins");
    assert_eq!(mappings[0].1, admins_uuid);

    // Remove it.
    rsclient
        .idm_oauth2_client_remove_group_mapping("test-oauth2-crud", "approovia/admins")
        .await
        .expect("remove-group-mapping failed");

    let mappings = rsclient
        .idm_oauth2_client_list_group_mappings("test-oauth2-crud")
        .await
        .expect("list-mappings failed after remove");
    assert!(mappings.is_empty(), "expected no mappings after remove");
}

/// US1 Acceptance 6 / FR-007a — duplicate add is rejected; storage unchanged.
#[test]
async fn tk_test_oauth2_client_group_mapping_duplicate_add_rejected(
    rsclient: &netidm_client::NetidmClient,
) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin");

    setup_oauth2_client(rsclient, "test-oauth2-dup")
        .await
        .expect("Failed to create test OAuth2 upstream");

    let first_uuid = create_group(rsclient, "test-mapping-first").await;
    let second_uuid = create_group(rsclient, "test-mapping-second").await;

    // First add succeeds.
    rsclient
        .idm_oauth2_client_add_group_mapping("test-oauth2-dup", "same-upstream", first_uuid)
        .await
        .expect("first add-group-mapping failed");

    // Second add with same upstream name and different target must fail.
    let err = rsclient
        .idm_oauth2_client_add_group_mapping("test-oauth2-dup", "same-upstream", second_uuid)
        .await
        .expect_err("duplicate-upstream add should fail");
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("already exists") || rendered.contains("InvalidAttribute"),
        "expected duplicate-mapping error to reference existence/InvalidAttribute; got {rendered}"
    );

    // Verify storage unchanged: still one mapping, still pointing at first_uuid.
    let mappings = rsclient
        .idm_oauth2_client_list_group_mappings("test-oauth2-dup")
        .await
        .expect("list-mappings failed");
    assert_eq!(mappings.len(), 1, "duplicate add must not mutate storage");
    assert_eq!(mappings[0].0, "same-upstream");
    assert_eq!(mappings[0].1, first_uuid);
}

/// Remove of a non-existent mapping is idempotent and silent (no error, no
/// side effect). Mirrors the contract in contracts/cli-commands.md.
#[test]
async fn tk_test_oauth2_client_group_mapping_remove_nonexistent_idempotent(
    rsclient: &netidm_client::NetidmClient,
) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin");

    setup_oauth2_client(rsclient, "test-oauth2-idempotent")
        .await
        .expect("Failed to create test OAuth2 upstream");

    rsclient
        .idm_oauth2_client_remove_group_mapping("test-oauth2-idempotent", "never-existed")
        .await
        .expect("remove of non-existent mapping must succeed");

    let mappings = rsclient
        .idm_oauth2_client_list_group_mappings("test-oauth2-idempotent")
        .await
        .expect("list after no-op remove must succeed");
    assert!(mappings.is_empty());
}

/// Upstream names are preserved verbatim even when they contain colons.
/// Exercises the "split on last `:`" parsing rule (research.md D1) through
/// the full write/read round-trip.
#[test]
async fn tk_test_oauth2_client_group_mapping_upstream_name_with_colons(
    rsclient: &netidm_client::NetidmClient,
) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin");

    setup_oauth2_client(rsclient, "test-oauth2-colon")
        .await
        .expect("Failed to create test OAuth2 upstream");

    let uuid = create_group(rsclient, "test-mapping-colon-target").await;

    // Upstream name contains colons (Azure-style fully-qualified).
    let upstream = "team:infra:lead";

    rsclient
        .idm_oauth2_client_add_group_mapping("test-oauth2-colon", upstream, uuid)
        .await
        .expect("add-group-mapping with colon in upstream name must succeed");

    let mappings = rsclient
        .idm_oauth2_client_list_group_mappings("test-oauth2-colon")
        .await
        .expect("list-mappings failed");
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].0, upstream);
    assert_eq!(mappings[0].1, uuid);

    // And the raw stored form is `<upstream>:<uuid>` (not truncated at the
    // first colon).
    let entry = rsclient
        .idm_oauth2_client_get("test-oauth2-colon")
        .await
        .expect("get upstream client failed")
        .expect("upstream client not found");
    let stored = entry
        .attrs
        .get(ATTR_OAUTH2_GROUP_MAPPING)
        .expect("oauth2_group_mapping attr missing");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0], format!("{upstream}:{uuid}"));
}

// ============================================================================
// SAML upstream client tests (Acceptance 4 — mirror of OAuth2 cases)
// ============================================================================

/// Create a SAML upstream connector usable as the test subject.
async fn setup_saml_client(
    rsclient: &netidm_client::NetidmClient,
    name: &str,
) -> Result<(), netidm_client::ClientError> {
    // Note: the server validates idp_certificate as Utf8String and rejects
    // control characters (including the newlines in a real PEM). For test
    // setup we use a single-line placeholder; the real-world PEM parsing
    // happens later in the SAML handler path, out of scope here.
    let cfg = SamlClientConfig {
        name,
        display_name: name,
        idp_sso_url: "https://idp.example.com/saml/sso",
        idp_certificate: "-----BEGIN CERTIFICATE----- MIIBtestfixture -----END CERTIFICATE-----",
        entity_id: "https://sp.example.com",
        acs_url: "https://sp.example.com/acs",
        name_id_format: None,
        email_attr: None,
        displayname_attr: None,
        groups_attr: None,
        jit_provisioning: false,
    };
    rsclient.idm_saml_client_create(cfg).await
}

/// US1 Acceptance 4 — SAML mapping CRUD mirrors OAuth2.
#[test]
async fn tk_test_saml_client_group_mapping_crud(rsclient: &netidm_client::NetidmClient) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin");

    setup_saml_client(rsclient, "test-saml-crud")
        .await
        .expect("Failed to create test SAML upstream");

    let admins_uuid = create_group(rsclient, "test-saml-mapping-admins").await;

    let mappings = rsclient
        .idm_saml_client_list_group_mappings("test-saml-crud")
        .await
        .expect("SAML list-mappings failed on empty connector");
    assert!(mappings.is_empty());

    rsclient
        .idm_saml_client_add_group_mapping("test-saml-crud", "corp/admins", admins_uuid)
        .await
        .expect("SAML add-group-mapping failed");

    let mappings = rsclient
        .idm_saml_client_list_group_mappings("test-saml-crud")
        .await
        .expect("SAML list-mappings failed after add");
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].0, "corp/admins");
    assert_eq!(mappings[0].1, admins_uuid);

    rsclient
        .idm_saml_client_remove_group_mapping("test-saml-crud", "corp/admins")
        .await
        .expect("SAML remove-group-mapping failed");

    let mappings = rsclient
        .idm_saml_client_list_group_mappings("test-saml-crud")
        .await
        .expect("SAML list-mappings failed after remove");
    assert!(mappings.is_empty());

    // Check the stored attribute name is the SAML-specific one, not OAuth2.
    let entry = rsclient
        .idm_saml_client_get("test-saml-crud")
        .await
        .expect("SAML get failed")
        .expect("SAML entry missing");
    assert!(
        entry
            .attrs
            .get(ATTR_SAML_GROUP_MAPPING)
            .is_none_or(|v| v.is_empty()),
        "SAML entry should have no saml_group_mapping values after remove"
    );
}

/// SAML duplicate-add is rejected (FR-007a).
#[test]
async fn tk_test_saml_client_group_mapping_duplicate_add_rejected(
    rsclient: &netidm_client::NetidmClient,
) {
    rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await
        .expect("Failed to authenticate as admin");

    setup_saml_client(rsclient, "test-saml-dup")
        .await
        .expect("Failed to create test SAML upstream");

    let first_uuid = create_group(rsclient, "test-saml-dup-first").await;
    let second_uuid = create_group(rsclient, "test-saml-dup-second").await;

    rsclient
        .idm_saml_client_add_group_mapping("test-saml-dup", "same-name", first_uuid)
        .await
        .expect("first SAML add failed");

    let err = rsclient
        .idm_saml_client_add_group_mapping("test-saml-dup", "same-name", second_uuid)
        .await
        .expect_err("duplicate-upstream SAML add must fail");
    let rendered = format!("{err:?}");
    assert!(
        rendered.contains("already exists") || rendered.contains("InvalidAttribute"),
        "expected duplicate-mapping error; got {rendered}"
    );

    let mappings = rsclient
        .idm_saml_client_list_group_mappings("test-saml-dup")
        .await
        .expect("list failed");
    assert_eq!(mappings.len(), 1);
    assert_eq!(mappings[0].1, first_uuid);
}
