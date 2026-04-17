use crate::OpType;
use crate::{handle_client_error, KanidmClientParser, WgOpt};
use kanidm_proto::wg::{WgConnectRequest, WgTokenCreate, WgTunnelCreate};

impl WgOpt {
    pub async fn exec(&self, opt: KanidmClientParser) {
        match self {
            WgOpt::TunnelList => {
                let client = opt.to_client(OpType::Read).await;
                match client.wg_tunnel_list().await {
                    Ok(tunnels) => {
                        for t in tunnels {
                            println!(
                                "{} (iface={} endpoint={} port={} backend={})",
                                t.name, t.interface, t.endpoint, t.listen_port, t.backend
                            );
                        }
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            WgOpt::TunnelGet { name } => {
                let client = opt.to_client(OpType::Read).await;
                match client.wg_tunnel_get(name).await {
                    Ok(Some(t)) => println!(
                        "{} (iface={} pubkey={} endpoint={} port={} addrs={} backend={})",
                        t.name,
                        t.interface,
                        t.public_key,
                        t.endpoint,
                        t.listen_port,
                        t.address.join(", "),
                        t.backend,
                    ),
                    Ok(None) => println!("Tunnel '{}' not found", name),
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            WgOpt::TunnelCreate {
                name,
                interface,
                private_key,
                endpoint,
                listen_port,
                address,
                dns,
                mtu,
            } => {
                let client = opt.to_client(OpType::Write).await;
                let req = WgTunnelCreate {
                    name: name.clone(),
                    interface: interface.clone(),
                    private_key: private_key.clone(),
                    endpoint: endpoint.clone(),
                    listen_port: *listen_port,
                    address: address.clone(),
                    dns: dns.clone(),
                    mtu: *mtu,
                };
                if let Err(e) = client.wg_tunnel_create(req).await {
                    handle_client_error(e, opt.output_mode);
                }
            }
            WgOpt::TunnelDelete { name } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client.wg_tunnel_delete(name).await {
                    handle_client_error(e, opt.output_mode);
                }
            }
            WgOpt::PeerList { tunnel } => {
                let client = opt.to_client(OpType::Read).await;
                match client.wg_peer_list(tunnel).await {
                    Ok(peers) => {
                        for p in peers {
                            println!(
                                "{} pubkey={} ips={} last_seen={}",
                                p.name,
                                p.pubkey,
                                p.allowed_ips.join(", "),
                                p.last_seen.as_deref().unwrap_or("never"),
                            );
                        }
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            WgOpt::PeerDelete { tunnel, peer_uuid } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client.wg_peer_delete(tunnel, peer_uuid).await {
                    handle_client_error(e, opt.output_mode);
                }
            }
            WgOpt::TokenList { tunnel } => {
                let client = opt.to_client(OpType::Read).await;
                match client.wg_token_list(tunnel).await {
                    Ok(tokens) => {
                        for t in tokens {
                            let uses = t.uses_left.map(|u| u.to_string()).unwrap_or_else(|| "unlimited".to_string());
                            let expiry = t.expiry.as_deref().unwrap_or("never");
                            println!("{} uses={} expires={}", t.name, uses, expiry);
                        }
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            WgOpt::TokenCreate { tunnel, uses, expiry } => {
                let client = opt.to_client(OpType::Write).await;
                let req = WgTokenCreate {
                    uses: *uses,
                    expiry: expiry.clone(),
                    principal: None,
                };
                match client.wg_token_create(tunnel, req).await {
                    Ok(resp) => {
                        println!("Token: {}", resp.token_name);
                        println!("Secret: {}", resp.secret);
                        if let Some(exp) = resp.expires {
                            println!("Expires: {}", exp);
                        }
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
            WgOpt::TokenDelete { tunnel, token } => {
                let client = opt.to_client(OpType::Write).await;
                if let Err(e) = client.wg_token_delete(tunnel, token).await {
                    handle_client_error(e, opt.output_mode);
                }
            }
            WgOpt::Connect { token, pubkey } => {
                let client = opt.to_client(OpType::Write).await;
                let req = WgConnectRequest {
                    token: token.clone(),
                    pubkey: pubkey.clone(),
                };
                match client.wg_connect(req).await {
                    Ok(resp) => {
                        println!("# WireGuard client config");
                        print!("{}", resp.config);
                    }
                    Err(e) => handle_client_error(e, opt.output_mode),
                }
            }
        }
    }
}
