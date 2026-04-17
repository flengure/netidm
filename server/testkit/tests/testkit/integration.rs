//! Integration tests using browser automation

use compact_jwt::{traits::JwsVerifiable, JwsCompact};
use netidm_client::NetidmClient;
use netidmd_lib::constants::EntryClass;
use netidmd_testkit::login_put_admin_idm_admins;

use std::str::FromStr;

#[netidmd_testkit::test]
async fn test_domain_reset_token_key(rsclient: &NetidmClient) {
    login_put_admin_idm_admins(rsclient).await;

    let token = rsclient.get_token().await.expect("No bearer token present");

    let jwt = JwsCompact::from_str(&token).expect("Failed to parse jwt");

    let key_id = jwt.kid().expect("token does not have a key id");

    assert!(rsclient.idm_domain_revoke_key(key_id).await.is_ok());
}

#[netidmd_testkit::test]
async fn test_idm_domain_set_ldap_basedn(rsclient: &NetidmClient) {
    login_put_admin_idm_admins(rsclient).await;
    assert!(rsclient
        .idm_domain_set_ldap_basedn("dc=krabsarekool,dc=example,dc=com")
        .await
        .is_ok());
    assert!(rsclient
        .idm_domain_set_ldap_basedn("krabsarekool")
        .await
        .is_err());
}

#[netidmd_testkit::test]
async fn test_idm_domain_set_ldap_max_queryable_attrs(rsclient: &NetidmClient) {
    login_put_admin_idm_admins(rsclient).await;
    assert!(rsclient
        .idm_domain_set_ldap_max_queryable_attrs(20)
        .await
        .is_ok());
    assert!(rsclient
        .idm_domain_set_ldap_max_queryable_attrs(10)
        .await
        .is_ok()); // Ideally this should be "is_err"
}

#[netidmd_testkit::test]
/// Checks that a built-in group idm_all_persons has the "builtin" class as expected.
async fn test_all_persons_has_builtin_class(rsclient: &NetidmClient) {
    login_put_admin_idm_admins(rsclient).await;
    let res = rsclient
        .idm_group_get("idm_all_persons")
        .await
        .expect("Failed to get idm_all_persons");
    eprintln!("res: {res:?}");

    assert!(res
        .unwrap()
        .attrs
        .get("class")
        .unwrap()
        .contains(&EntryClass::Builtin.as_ref().into()));
}

// /// run a test command as the admin user
// fn test_cmd_admin(token_cache_path: &str, rsclient: &NetidmClient, cmd: &str) -> Output {
//     let split_cmd: Vec<&str> = cmd.split_ascii_whitespace().collect();
//     test_cmd_admin_split(token_cache_path, rsclient, &split_cmd)
// }
// /// run a test command as the admin user
// fn test_cmd_admin_split(token_cache_path: &str, rsclient: &NetidmClient, cmd: &[&str]) -> Output {
//     println!(
//         "##################################\nrunning {}\n##################################",
//         cmd.join(" ")
//     );
//     let res = cli_netidm!()
//         .env("NETIDM_PASSWORD", ADMIN_TEST_PASSWORD)
//         .args(cmd)
//         .output()
//         .unwrap();
//     println!("############ result ##################");
//     println!("status: {:?}", res.status);
//     println!("stdout: {}", String::from_utf8_lossy(&res.stdout));
//     println!("stderr: {}", String::from_utf8_lossy(&res.stderr));
//     println!("######################################");
//     assert!(res.status.success());
//     res
// }

// /// run a test command as the idm_admin user
// fn test_cmd_idm_admin(token_cache_path: &str, rsclient: &NetidmClient, cmd: &str) -> Output {
//     println!("##############################\nrunning {}", cmd);
//     let res = cli_netidm!()
//         .env("NETIDM_PASSWORD", IDM_ADMIN_TEST_PASSWORD)
//         .args(cmd.split(" "))
//         .output()
//         .unwrap();
//     println!("##############################\n{} result: {:?}", cmd, res);
//     assert!(res.status.success());
//     res
// }

// Disabled due to inconsistent test failures and blocking
/*
#[netidmd_testkit::test]
/// Testing the CLI doing things.
async fn test_integration_with_assert_cmd(rsclient: NetidmClient) {
    // setup the admin things
    login_put_admin_idm_admins(rsclient).await;

    rsclient
        .idm_person_account_primary_credential_set_password(
            IDM_ADMIN_TEST_USER,
            IDM_ADMIN_TEST_PASSWORD,
        )
        .await
        .expect(&format!("Failed to set {} password", IDM_ADMIN_TEST_USER));

    let token_cache_dir = tempdir().unwrap();
    let token_cache_path = format!("{}/netidm_tokens", token_cache_dir.path().display());

    // we have to spawn in another thread for ... reasons
    assert!(tokio::task::spawn_blocking(move || {
        let anon_login = cli_netidm!()
            .args(&["login", "-D", "anonymous"])
            .output()
            .unwrap();
        println!("Login Output: {:?}", anon_login);

        let anon_whoami = cli_netidm!()
            .args(&["self", "whoami", "-D", "anonymous"])
            .output()
            .unwrap();
        assert!(anon_whoami.status.success());
        println!("Output: {:?}", anon_whoami);

        test_cmd_admin(&token_cache_path, rsclient, "login -D admin");

        // login as idm_admin
        test_cmd_idm_admin(&token_cache_path, rsclient, "login -D idm_admin");
        test_cmd_admin_split(
            &token_cache_path,
            rsclient,
            &[
                "service-account",
                "create",
                NOT_ADMIN_TEST_USERNAME,
                "Test account",
                "-D",
                "admin",
                "-o",
                "json",
            ],
        );

        test_cmd_admin(
            &token_cache_path,
            rsclient,
            &format!("service-account get -D admin {}", NOT_ADMIN_TEST_USERNAME),
        );
        // updating the display name
        test_cmd_admin(
            &token_cache_path,
            rsclient,
            &format!(
                "service-account update -D admin {} --displayname cheeseballs",
                NOT_ADMIN_TEST_USERNAME
            ),
        );
        // updating the email
        test_cmd_admin(
            &token_cache_path,
            rsclient,
            &format!(
                "service-account update -D admin {} --mail foo@bar.com",
                NOT_ADMIN_TEST_USERNAME
            ),
        );

        // checking the email was changed
        let sad = test_cmd_admin(
            &token_cache_path,
            rsclient,
            &format!(
                "service-account get -D admin -o json {}",
                NOT_ADMIN_TEST_USERNAME
            ),
        );
        let str_output: String = String::from_utf8_lossy(&sad.stdout).into();
        assert!(str_output.contains("foo@bar.com"));

        true
    })
    .await
    .unwrap());
    println!("Success!");
}
*/
