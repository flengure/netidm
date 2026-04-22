use crate::OpType;
use crate::{handle_client_error, Oauth2Opt, OutputMode};
use crate::{NetidmClientParser, Oauth2ClaimMapJoin};
use anyhow::{Context, Error};
use netidm_proto::internal::{ImageValue, Oauth2ClaimMapJoin as ProtoOauth2ClaimMapJoin};
use std::fs::read;
use std::process::exit;

impl Oauth2Opt {
    pub async fn exec(&self, opt: NetidmClientParser) {
        match self {
            #[cfg(feature = "dev-oauth2-device-flow")]
            Oauth2Opt::DeviceFlowDisable(nopt) => {
                // TODO: finish the CLI bits for DeviceFlowDisable
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_device_flow_update(&nopt.name, true)
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            #[cfg(feature = "dev-oauth2-device-flow")]
            Oauth2Opt::DeviceFlowEnable(nopt) => {
                // TODO: finish the CLI bits for DeviceFlowEnable
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_device_flow_update(&nopt.name, true)
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::List => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_oauth2_rs_list().await {
                    Ok(r) => match opt.output_mode {
                        OutputMode::Json => {
                            let r_attrs: Vec<_> = r.iter().map(|entry| &entry.attrs).collect();
                            println!(
                                "{}",
                                serde_json::to_string(&r_attrs).expect("Failed to serialise json")
                            );
                        }
                        OutputMode::Text => r.iter().for_each(|ent| println!("{ent}")),
                    },
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::Get(nopt) => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_oauth2_rs_get(nopt.name.as_str()).await {
                    Ok(Some(e)) => opt.output_mode.print_message(e),
                    Ok(None) => {
                        // Fall back to OAuth2 client provider lookup
                        match client.idm_oauth2_client_get(nopt.name.as_str()).await {
                            Ok(Some(e)) => opt.output_mode.print_message(e),
                            Ok(None) => opt.output_mode.print_message("No matching entries"),
                            Err(e) => handle_client_error(e, opt.output_mode),
                        }
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::CreateBasic {
                name,
                displayname,
                origin,
            } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_basic_create(
                        name.as_str(),
                        displayname.as_str(),
                        origin.as_str(),
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::CreatePublic {
                name,
                displayname,
                origin,
            } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_public_create(
                        name.as_str(),
                        displayname.as_str(),
                        origin.as_str(),
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::UpdateScopeMap(cbopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update_scope_map(
                        cbopt.nopt.name.as_str(),
                        cbopt.group.as_str(),
                        cbopt.scopes.iter().map(|s| s.as_str()).collect(),
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::DeleteScopeMap(cbopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_delete_scope_map(cbopt.nopt.name.as_str(), cbopt.group.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::UpdateSupScopeMap(cbopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update_sup_scope_map(
                        cbopt.nopt.name.as_str(),
                        cbopt.group.as_str(),
                        cbopt.scopes.iter().map(|s| s.as_str()).collect(),
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => {
                        error!("Error -> {:?}", e);
                        exit(1)
                    }
                }
            }
            Oauth2Opt::DeleteSupScopeMap(cbopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_delete_sup_scope_map(
                        cbopt.nopt.name.as_str(),
                        cbopt.group.as_str(),
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::ResetSecrets(cbopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update(cbopt.name.as_str(), None, None, None, true)
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::ShowBasicSecret(nopt) => {
                let client = opt.to_client(OpType::Read).await;
                match client
                    .idm_oauth2_rs_get_basic_secret(nopt.name.as_str())
                    .await
                {
                    Ok(Some(secret)) => match opt.output_mode {
                        OutputMode::Text => println!("{secret}"),
                        OutputMode::Json => println!("{{\"secret\": \"{secret}\"}}"),
                    },
                    Ok(None) => {
                        opt.output_mode.print_message("No secret configured");
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::Delete(nopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_oauth2_rs_delete(nopt.name.as_str()).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::SetDisplayname(cbopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update(
                        cbopt.nopt.name.as_str(),
                        None,
                        Some(cbopt.displayname.as_str()),
                        None,
                        false,
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::SetName { nopt, name } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update(
                        nopt.name.as_str(),
                        Some(name.as_str()),
                        None,
                        None,
                        false,
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::SetLandingUrl { nopt, url } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update(nopt.name.as_str(), None, None, Some(url.as_str()), false)
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::SetImage {
                nopt,
                path,
                image_type,
            } => {
                let img_res: Result<ImageValue, Error> = (move || {
                    let file_name = path
                        .file_name()
                        .context("Please pass a file")?
                        .to_str()
                        .context("Path contains non utf-8")?
                        .to_string();

                    let image_type = match image_type {
                        Some(val) => val.clone(),
                        None => {
                            path
                                .extension().context("Path has no extension so we can't infer the imageType, or you could pass the optional imageType argument yourself.")?
                                .to_str().context("Path contains invalid utf-8")?
                                .try_into()
                                .map_err(Error::msg)?
                        }
                    };

                    let read_res = read(path);
                    match read_res {
                        Ok(data) => Ok(ImageValue::new(file_name, image_type, data)),
                        Err(err) => {
                            if opt.debug {
                                eprintln!(
                                    "{}",
                                    netidm_lib_file_permissions::diagnose_path(path.as_ref())
                                );
                            }
                            Err(err).context(format!("Failed to read file at '{}'", path.display()))
                        }
                    }
                })();

                let img = match img_res {
                    Ok(img) => img,
                    Err(err) => {
                        eprintln!("{err:?}");
                        return;
                    }
                };

                let client = opt.to_client(OpType::Write).await;

                match client
                    .idm_oauth2_rs_update_image(nopt.name.as_str(), img)
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::RemoveImage(nopt) => {
                let client = opt.to_client(OpType::Write).await;

                match client.idm_oauth2_rs_delete_image(nopt.name.as_str()).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::EnablePkce(nopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_oauth2_rs_enable_pkce(nopt.name.as_str()).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::DisablePkce(nopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_oauth2_rs_disable_pkce(nopt.name.as_str()).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::EnableLegacyCrypto(nopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_enable_legacy_crypto(nopt.name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::DisableLegacyCrypto(nopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_disable_legacy_crypto(nopt.name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::PreferShortUsername(nopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_prefer_short_username(nopt.name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::PreferSPNUsername(nopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_prefer_spn_username(nopt.name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }

            Oauth2Opt::AddOrigin { name, origin } => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_oauth2_client_add_origin(name, origin).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::RemoveOrigin { name, origin } => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_oauth2_client_remove_origin(name, origin).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::UpdateClaimMap {
                name,
                group,
                claim_name,
                values,
            } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_update_claim_map(
                        name.as_str(),
                        claim_name.as_str(),
                        group.as_str(),
                        values,
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::UpdateClaimMapJoin {
                name,
                claim_name,
                join,
            } => {
                let client = opt.to_client(OpType::Write).await;

                let join = match join {
                    Oauth2ClaimMapJoin::Csv => ProtoOauth2ClaimMapJoin::Csv,
                    Oauth2ClaimMapJoin::Ssv => ProtoOauth2ClaimMapJoin::Ssv,
                    Oauth2ClaimMapJoin::Array => ProtoOauth2ClaimMapJoin::Array,
                };

                match client
                    .idm_oauth2_rs_update_claim_map_join(name.as_str(), claim_name.as_str(), join)
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::DeleteClaimMap {
                name,
                claim_name,
                group,
            } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_delete_claim_map(
                        name.as_str(),
                        claim_name.as_str(),
                        group.as_str(),
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }

            Oauth2Opt::EnablePublicLocalhost { name } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_enable_public_localhost_redirect(name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }

            Oauth2Opt::DisablePublicLocalhost { name } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_disable_public_localhost_redirect(name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::EnableStrictRedirectUri { name } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_enable_strict_redirect_uri(name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }

            Oauth2Opt::DisableStrictRedirectUri { name } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_disable_strict_redirect_uri(name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::RotateCryptographicKeys { name, rotate_at } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_rotate_keys(name.as_str(), *rotate_at)
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::RevokeCryptographicKey { name, key_id } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_revoke_key(name.as_str(), key_id.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::DisableConsentPrompt(nopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_disable_consent_prompt(nopt.name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::EnableConsentPrompt(nopt) => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_rs_enable_consent_prompt(nopt.name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::CreateGithub {
                name,
                client_id,
                client_secret,
            } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_create_github(
                        name.as_str(),
                        client_id.as_str(),
                        client_secret.as_str(),
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::CreateGoogle {
                name,
                client_id,
                client_secret,
            } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_create_google(
                        name.as_str(),
                        client_id.as_str(),
                        client_secret.as_str(),
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::CreateOidc {
                name,
                issuer,
                client_id,
                client_secret,
            } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_create_oidc(
                        name.as_str(),
                        issuer,
                        client_id.as_str(),
                        client_secret.as_str(),
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::EnableJitProvisioning { name } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_enable_jit_provisioning(name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::DisableJitProvisioning { name } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_disable_jit_provisioning(name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::EnableEmailLinkAccounts { name } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_enable_email_link_accounts(name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::DisableEmailLinkAccounts { name } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_disable_email_link_accounts(name.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::EnableDomainEmailLinkAccounts => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_oauth2_domain_enable_email_link_accounts().await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::DisableDomainEmailLinkAccounts => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_oauth2_domain_disable_email_link_accounts().await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::SetIdentityClaimMap {
                name,
                netidm_attr,
                provider_claim,
            } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_set_claim_map(
                        name.as_str(),
                        netidm_attr.as_str(),
                        provider_claim.as_str(),
                    )
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::SetLinkBy { name, link_by } => {
                // Client-side input validation — reject unknown values up front so the
                // operator sees a clear error without a round-trip. The server independently
                // validates on write.
                let normalised = link_by.trim().to_lowercase();
                if !matches!(normalised.as_str(), "email" | "username" | "id") {
                    opt.output_mode
                        .print_message("Error: link-by must be one of: email, username, id");
                    return;
                }
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_set_link_by(name.as_str(), normalised.as_str())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::AddGroupMapping {
                name,
                upstream,
                netidm_group,
            } => {
                let client = opt.to_client(OpType::Write).await;
                let uuid =
                    match crate::common::resolve_netidm_group_uuid(&client, netidm_group.as_str())
                        .await
                    {
                        Ok(u) => u,
                        Err(msg) => {
                            opt.output_mode.print_message(format!("Error: {msg}"));
                            return;
                        }
                    };
                match client
                    .idm_oauth2_client_add_group_mapping(name.as_str(), upstream.as_str(), uuid)
                    .await
                {
                    Ok(_) => opt
                        .output_mode
                        .print_message(format!("added mapping: {upstream} -> {uuid}")),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::RemoveGroupMapping { name, upstream } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_oauth2_client_remove_group_mapping(name.as_str(), upstream.as_str())
                    .await
                {
                    Ok(_) => opt
                        .output_mode
                        .print_message(format!("removed mapping: {upstream}")),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::ListGroupMappings { name } => {
                let client = opt.to_client(OpType::Read).await;
                match client
                    .idm_oauth2_client_list_group_mappings(name.as_str())
                    .await
                {
                    Ok(mappings) => {
                        if mappings.is_empty() {
                            opt.output_mode.print_message("(no mappings)");
                        } else {
                            for (upstream, uuid) in mappings {
                                opt.output_mode.print_message(format!("{upstream}\t{uuid}"));
                            }
                        }
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::AddPostLogoutRedirectUri { name, uri } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_add_post_logout_redirect_uri(name.as_str(), uri.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::RemovePostLogoutRedirectUri { name, uri } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_remove_post_logout_redirect_uri(name.as_str(), uri.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::ListPostLogoutRedirectUris { name } => {
                let client = opt.to_client(OpType::Read).await;
                match client
                    .idm_oauth2_client_list_post_logout_redirect_uris(name.as_str())
                    .await
                {
                    Ok(uris) => {
                        if uris.is_empty() {
                            opt.output_mode
                                .print_message("(no post-logout redirect URIs)");
                        } else {
                            for uri in uris {
                                opt.output_mode.print_message(uri);
                            }
                        }
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            Oauth2Opt::SetBackchannelLogoutUri { name, uri } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_set_backchannel_logout_uri(name.as_str(), uri.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::ClearBackchannelLogoutUri { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_clear_backchannel_logout_uri(name.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::SetProviderKind { name, kind } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_set_provider_kind(name.as_str(), kind.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubSetHost { name, url } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_set_host(name.as_str(), url.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubAddOrgFilter { name, org } => {
                if !org
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
                {
                    eprintln!("error: org name must contain only alphanumeric characters, hyphens, or underscores");
                    std::process::exit(1);
                }
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_add_org_filter(name.as_str(), org.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubRemoveOrgFilter { name, org } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_remove_org_filter(name.as_str(), org.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubAddAllowedTeam { name, team } => {
                if !team.contains(':') {
                    eprintln!("error: team must be in 'org:team' format (e.g. acme:engineers)");
                    std::process::exit(1);
                }
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_add_allowed_team(name.as_str(), team.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubRemoveAllowedTeam { name, team } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_remove_allowed_team(name.as_str(), team.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubSetTeamNameField { name, field } => {
                if !matches!(field.as_str(), "slug" | "name" | "both") {
                    eprintln!("error: field must be one of: slug, name, both");
                    std::process::exit(1);
                }
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_set_team_name_field(name.as_str(), field.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubEnableLoadAllGroups { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_set_load_all_groups(name.as_str(), true)
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubDisableLoadAllGroups { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_set_load_all_groups(name.as_str(), false)
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubSetPreferredEmailDomain { name, domain } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_set_preferred_email_domain(
                        name.as_str(),
                        domain.as_str(),
                    )
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubClearPreferredEmailDomain { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_clear_preferred_email_domain(name.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubEnableJitProvisioning { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_set_allow_jit_provisioning(name.as_str(), true)
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            Oauth2Opt::GithubDisableJitProvisioning { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_oauth2_client_github_set_allow_jit_provisioning(name.as_str(), false)
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
        }
    }
}
