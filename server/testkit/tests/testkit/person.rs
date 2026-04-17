use netidm_client::{ClientError, NetidmClient, StatusCode};
use netidm_proto::constants::ATTR_MAIL;
use netidmd_testkit::{create_user, ADMIN_TEST_PASSWORD, ADMIN_TEST_USER};
use serde_json::Value;

#[netidmd_testkit::test]
async fn test_v1_person_id_patch(rsclient: &NetidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    create_user(rsclient, "foo", "foogroup").await;

    let post_body = serde_json::json!({"attrs": { ATTR_MAIL : ["crab@example.com"]}});

    let response: Value = match rsclient
        .perform_patch_request("/v1/person/foo", post_body)
        .await
    {
        Ok(val) => val,
        Err(err) => panic!("Failed to patch person: {err:?}"),
    };
    eprintln!("response: {response:#?}");
}

#[netidmd_testkit::test]
async fn test_v1_person_id_ssh_pubkeys_post(rsclient: &NetidmClient) {
    let res = rsclient
        .auth_simple_password(ADMIN_TEST_USER, ADMIN_TEST_PASSWORD)
        .await;
    assert!(res.is_ok());

    create_user(rsclient, "foo", "foogroup").await;

    let post_body = serde_json::json!([
        "ssh-key-tag-goes-here",
        "ed25519 im_a_real_ssh_public_key_just_trust_me comment"
    ]);

    let response: ClientError = match rsclient
        .perform_post_request::<serde_json::Value, String>("/v1/person/foo/_ssh_pubkeys", post_body)
        .await
    {
        Ok(val) => panic!("Expected failure to post person ssh pubkeys: {val:?}"),
        Err(err) => err,
    };
    eprintln!("response: {response:#?}");
    assert!(matches!(
        response,
        ClientError::Http(StatusCode::BAD_REQUEST, _, _)
    ));
}
