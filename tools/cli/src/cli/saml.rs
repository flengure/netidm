use crate::NetidmClientParser;
use crate::OpType;
use crate::{handle_client_error, SamlClientOpt};
use netidm_client::saml::SamlClientConfig;
use std::fs;

impl SamlClientOpt {
    pub async fn exec(&self, opt: NetidmClientParser) {
        match self {
            SamlClientOpt::List => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_saml_client_list().await {
                    Ok(list) => {
                        for entry in list {
                            opt.output_mode.print_message(
                                entry
                                    .attrs
                                    .get("name")
                                    .and_then(|v| v.first())
                                    .map(|s| s.as_str())
                                    .unwrap_or("<unnamed>"),
                            );
                        }
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SamlClientOpt::Get { name } => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_saml_client_get(name.as_str()).await {
                    Ok(Some(entry)) => opt.output_mode.print_message(format!("{entry:?}").as_str()),
                    Ok(None) => opt.output_mode.print_message("Not found"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SamlClientOpt::Create {
                name,
                displayname,
                sso_url,
                idp_cert,
                entity_id,
                acs_url,
                nameid_format,
                email_attr,
                displayname_attr,
                groups_attr,
                jit_provisioning,
                sso_issuer,
                groups_delim,
                insecure_skip_sig_validation,
                filter_groups,
            } => {
                let pem = match fs::read_to_string(idp_cert) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Failed to read IdP certificate: {e}");
                        return;
                    }
                };
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_saml_client_create(SamlClientConfig {
                        name: name.as_str(),
                        display_name: displayname.as_str(),
                        idp_sso_url: sso_url.as_str(),
                        idp_certificate: pem.trim(),
                        entity_id: entity_id.as_str(),
                        acs_url: acs_url.as_str(),
                        name_id_format: nameid_format.as_deref(),
                        email_attr: email_attr.as_deref(),
                        displayname_attr: displayname_attr.as_deref(),
                        groups_attr: groups_attr.as_deref(),
                        jit_provisioning: *jit_provisioning,
                        sso_issuer: sso_issuer.as_deref(),
                        groups_delim: groups_delim.as_deref(),
                        insecure_skip_sig_validation: *insecure_skip_sig_validation,
                        filter_groups: *filter_groups,
                    })
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SamlClientOpt::Delete { name } => {
                let client = opt.to_client(OpType::Write).await;
                match client.idm_saml_client_delete(name.as_str()).await {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SamlClientOpt::UpdateCert { name, idp_cert } => {
                let pem = match fs::read_to_string(idp_cert) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("Failed to read IdP certificate: {e}");
                        return;
                    }
                };
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_saml_client_update_cert(name.as_str(), pem.trim())
                    .await
                {
                    Ok(_) => opt.output_mode.print_message("Success"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SamlClientOpt::AddGroupMapping {
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
                    .idm_saml_client_add_group_mapping(name.as_str(), upstream.as_str(), uuid)
                    .await
                {
                    Ok(_) => opt
                        .output_mode
                        .print_message(format!("added mapping: {upstream} -> {uuid}")),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SamlClientOpt::RemoveGroupMapping { name, upstream } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_saml_client_remove_group_mapping(name.as_str(), upstream.as_str())
                    .await
                {
                    Ok(_) => opt
                        .output_mode
                        .print_message(format!("removed mapping: {upstream}")),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SamlClientOpt::ListGroupMappings { name } => {
                let client = opt.to_client(OpType::Read).await;
                match client
                    .idm_saml_client_list_group_mappings(name.as_str())
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
            SamlClientOpt::SetSloUrl { name, url } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_saml_client_set_slo_url(name.as_str(), url.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            SamlClientOpt::ClearSloUrl { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client.idm_saml_client_clear_slo_url(name.as_str()).await {
                    handle_client_error(e, opt.output_mode);
                }
            }
            SamlClientOpt::SetSsoIssuer { name, issuer } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_saml_client_set_sso_issuer(name.as_str(), issuer.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            SamlClientOpt::ClearSsoIssuer { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client.idm_saml_client_clear_sso_issuer(name.as_str()).await {
                    handle_client_error(e, opt.output_mode);
                }
            }
            SamlClientOpt::SetGroupsDelim { name, delim } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_saml_client_set_groups_delim(name.as_str(), delim.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            SamlClientOpt::ClearGroupsDelim { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_saml_client_clear_groups_delim(name.as_str())
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            SamlClientOpt::AddAllowedGroup { name, group } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_saml_client_add_allowed_group(name.as_str(), group.as_str())
                    .await
                {
                    Ok(_) => opt
                        .output_mode
                        .print_message(format!("added allowed group: {group}")),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SamlClientOpt::RemoveAllowedGroup { name, group } => {
                let client = opt.to_client(OpType::Write).await;
                match client
                    .idm_saml_client_remove_allowed_group(name.as_str(), group.as_str())
                    .await
                {
                    Ok(_) => opt
                        .output_mode
                        .print_message(format!("removed allowed group: {group}")),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SamlClientOpt::ListAllowedGroups { name } => {
                let client = opt.to_client(OpType::Read).await;
                match client.idm_saml_client_get(name.as_str()).await {
                    Ok(Some(entry)) => {
                        let groups: Vec<_> = entry
                            .attrs
                            .get("saml_allowed_groups")
                            .cloned()
                            .unwrap_or_default();
                        if groups.is_empty() {
                            opt.output_mode.print_message("(no allowed groups)");
                        } else {
                            for g in groups {
                                opt.output_mode.print_message(g);
                            }
                        }
                    }
                    Ok(None) => opt.output_mode.print_message("Not found"),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            SamlClientOpt::SetInsecureSkipSigValidation { name, value } => {
                let parsed = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    other => {
                        eprintln!("invalid value {other:?}: expected 'true' or 'false'");
                        return;
                    }
                };
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_saml_client_set_insecure_skip_sig_validation(name.as_str(), parsed)
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
            SamlClientOpt::SetFilterGroups { name, value } => {
                let parsed = match value.as_str() {
                    "true" => true,
                    "false" => false,
                    other => {
                        eprintln!("invalid value {other:?}: expected 'true' or 'false'");
                        return;
                    }
                };
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client
                    .idm_saml_client_set_filter_groups(name.as_str(), parsed)
                    .await
                {
                    handle_client_error(e, opt.output_mode);
                }
            }
        }
    }
}
