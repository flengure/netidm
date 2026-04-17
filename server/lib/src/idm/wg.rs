//! IdmServer extension for WireGuard tunnel and peer management.

use std::sync::Arc;

use crate::idm::server::{IdmServerProxyReadTransaction, IdmServerProxyWriteTransaction};
use crate::prelude::*;
use crypto_glue::{
    s256::{Sha256, Sha256Output},
    traits::Digest,
};
use ipnet::IpNet;
use kanidm_proto::wg::{
    WgConnectRequest, WgConnectResponse, WgPeerResponse, WgTokenCreate, WgTokenCreatedResponse,
    WgTokenInfo, WgTunnelCreate, WgTunnelResponse,
};
use kanidmd_wg::alloc::allocate;
use kanidmd_wg::types::{WgPeerConfig, WgTunnelConfig};
use rand::RngExt;

// ---- Read operations ----

impl IdmServerProxyReadTransaction<'_> {
    /// Return all WgTunnel entries the server has access to.
    pub fn wg_list_tunnels(&mut self) -> Result<Vec<WgTunnelConfig>, OperationError> {
        let filter = filter!(f_eq(Attribute::Class, EntryClass::WgTunnel.into()));
        let entries = self.qs_read.internal_search(filter)?;
        entries
            .iter()
            .map(wg_tunnel_config_from_entry)
            .collect()
    }

    /// Return all tunnels as API response objects (peer counts come from the caller).
    pub fn wg_list_tunnel_responses(
        &mut self,
        backend: &str,
    ) -> Result<Vec<WgTunnelResponse>, OperationError> {
        let filter = filter!(f_eq(Attribute::Class, EntryClass::WgTunnel.into()));
        let entries = self.qs_read.internal_search(filter)?;
        entries
            .iter()
            .map(|e| {
                let cfg = wg_tunnel_config_from_entry(e)?;
                Ok(WgTunnelResponse {
                    name: cfg.name,
                    interface: cfg.interface.clone(),
                    public_key: cfg.public_key,
                    endpoint: cfg.endpoint,
                    listen_port: cfg.listen_port,
                    address: cfg.address.iter().map(|a| a.to_string()).collect(),
                    dns: cfg.dns,
                    mtu: cfg.mtu,
                    peer_count: 0,
                    backend: backend.to_string(),
                })
            })
            .collect()
    }

    /// Return all WgPeer entries belonging to a tunnel (identified by UUID).
    pub fn wg_list_peers_for_tunnel(
        &mut self,
        tunnel_uuid: Uuid,
    ) -> Result<Vec<WgPeerConfig>, OperationError> {
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::WgPeer.into()),
            f_eq(
                Attribute::WgTunnelRef,
                PartialValue::Refer(tunnel_uuid)
            )
        ]));
        let entries = self.qs_read.internal_search(filter)?;
        entries
            .iter()
            .map(wg_peer_config_from_entry)
            .collect()
    }

    /// Return (uuid, pubkey) pairs for all peers on a tunnel.
    pub fn wg_list_peer_pubkeys_for_tunnel(
        &mut self,
        tunnel_uuid: Uuid,
    ) -> Result<Vec<(Uuid, String)>, OperationError> {
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::WgPeer.into()),
            f_eq(
                Attribute::WgTunnelRef,
                PartialValue::Refer(tunnel_uuid)
            )
        ]));
        let entries = self.qs_read.internal_search(filter)?;
        Ok(entries
            .iter()
            .filter_map(|e| {
                let uuid = e.get_uuid();
                let pubkey = e.get_ava_single_utf8(Attribute::WgPubkey)?.to_string();
                Some((uuid, pubkey))
            })
            .collect())
    }
}

// ---- Write operations ----

impl IdmServerProxyWriteTransaction<'_> {
    /// Update the WgLastSeen attribute on a WgPeer entry.
    pub fn wg_update_last_seen(
        &mut self,
        peer_uuid: Uuid,
        ts: time::OffsetDateTime,
    ) -> Result<(), OperationError> {
        let modlist = ModifyList::new_purge_and_set(Attribute::WgLastSeen, Value::new_datetime(ts));
        self.qs_write.internal_modify_uuid(peer_uuid, &modlist)
    }

    /// Delete a WgPeer entry by UUID.
    pub fn wg_peer_delete(&mut self, peer_uuid: Uuid) -> Result<(), OperationError> {
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(peer_uuid)));
        self.qs_write.internal_delete(&filter)
    }

    /// Create a new WgTunnel entry from an admin request.
    pub fn wg_tunnel_create(&mut self, req: &WgTunnelCreate) -> Result<(), OperationError> {
        let mut entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::WgTunnel.to_value()),
            (Attribute::Name, Value::new_iname(&req.name)),
            (Attribute::WgInterface, Value::new_iname(&req.interface)),
            (Attribute::WgPrivateKey, Value::new_utf8s(&req.private_key)),
            (Attribute::WgEndpoint, Value::new_utf8s(&req.endpoint)),
            (Attribute::WgListenPort, Value::Uint32(u32::from(req.listen_port)))
        );

        for addr in &req.address {
            entry.add_ava(Attribute::WgAddress, Value::new_utf8s(addr));
        }
        for dns in &req.dns {
            entry.add_ava(Attribute::WgDns, Value::new_utf8s(dns));
        }
        if let Some(mtu) = req.mtu {
            entry.add_ava(Attribute::WgMtu, Value::Uint32(mtu));
        }

        self.qs_write.internal_create(vec![entry])
    }

    /// Delete a WgTunnel entry by name.
    pub fn wg_tunnel_delete(&mut self, name: &str) -> Result<(), OperationError> {
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::WgTunnel.into()),
            f_eq(Attribute::Name, PartialValue::new_iname(name))
        ]));
        self.qs_write.internal_delete(&filter)
    }

    /// Create a WgToken entry for a tunnel. Returns the plaintext secret to send to the user.
    pub fn wg_token_create(
        &mut self,
        tunnel_uuid: Uuid,
        tunnel_name: &str,
        req: &WgTokenCreate,
    ) -> Result<WgTokenCreatedResponse, OperationError> {
        let mut rng = rand::rng();
        let secret_bytes: [u8; 32] = rng.random();
        let secret = base64url_encode(&secret_bytes);
        let hash = sha256_of(secret.as_bytes());

        let token_name = format!(
            "wgtoken-{}-{}",
            tunnel_name,
            Uuid::new_v4().as_simple()
        );

        let mut entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::WgToken.to_value()),
            (Attribute::Name, Value::new_iname(&token_name)),
            (Attribute::WgTunnelRef, Value::Refer(tunnel_uuid)),
            (Attribute::WgTokenSecret, Value::Sha256(hash))
        );

        if let Some(uses) = req.uses {
            entry.add_ava(Attribute::WgTokenUsesLeft, Value::Uint32(uses));
        }
        if let Some(expiry_str) = &req.expiry {
            let expiry = time::OffsetDateTime::parse(expiry_str, &time::format_description::well_known::Rfc3339)
                .map_err(|_| OperationError::InvalidAttribute("Invalid expiry datetime".into()))?;
            entry.add_ava(Attribute::WgTokenExpiry, Value::new_datetime(expiry));
        }

        self.qs_write.internal_create(vec![entry])?;

        let expires = req.expiry.clone();
        Ok(WgTokenCreatedResponse {
            token_name,
            secret,
            expires,
        })
    }

    /// Validate a presented token secret and return the entry UUID and tunnel UUID.
    /// Checks expiry and uses_left. Does NOT consume the token.
    pub fn wg_token_validate(
        &mut self,
        secret: &str,
        ct: Duration,
    ) -> Result<(Uuid, Uuid), OperationError> {
        let hash = sha256_of(secret.as_bytes());
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::WgToken.into()),
            f_eq(Attribute::WgTokenSecret, PartialValue::Sha256(hash))
        ]));
        let entries = self.qs_write.internal_search(filter.clone())?;
        let e = entries
            .into_iter()
            .next()
            .ok_or(OperationError::NoMatchingEntries)?;

        // Check expiry.
        if let Some(expiry) = e.get_ava_single_datetime(Attribute::WgTokenExpiry) {
            let now = time::OffsetDateTime::UNIX_EPOCH + ct;
            if expiry < now {
                return Err(OperationError::InvalidEntryState);
            }
        }

        // Check uses_left.
        if let Some(uses_left) = e.get_ava_single_uint32(Attribute::WgTokenUsesLeft) {
            if uses_left == 0 {
                return Err(OperationError::InvalidEntryState);
            }
        }

        let token_uuid = e.get_uuid();
        let tunnel_uuid = e
            .get_ava_single_refer(Attribute::WgTunnelRef)
            .ok_or(OperationError::InvalidEntryState)?;

        Ok((token_uuid, tunnel_uuid))
    }

    /// Consume a token: decrement uses_left, or delete if it hits 0 / was single-use.
    pub fn wg_token_consume(&mut self, token_uuid: Uuid) -> Result<(), OperationError> {
        let filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(token_uuid)));
        let entries = self.qs_write.internal_search(filter)?;
        let Some(e) = entries.into_iter().next() else {
            return Ok(());
        };
        match e.get_ava_single_uint32(Attribute::WgTokenUsesLeft) {
            Some(uses) if uses <= 1 => {
                let del_filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(token_uuid)));
                self.qs_write.internal_delete(&del_filter)
            }
            Some(uses) => {
                let ml = ModifyList::new_purge_and_set(
                    Attribute::WgTokenUsesLeft,
                    Value::Uint32(uses - 1),
                );
                self.qs_write.internal_modify_uuid(token_uuid, &ml)
            }
            None => {
                // Unlimited-use token — delete it (single-shot semantics).
                let del_filter = filter!(f_eq(Attribute::Uuid, PartialValue::Uuid(token_uuid)));
                self.qs_write.internal_delete(&del_filter)
            }
        }
    }

    /// Full peer registration flow: validate token, allocate IPs, create WgPeer entry.
    pub fn wg_connect(
        &mut self,
        caller_name: &str,
        req: &WgConnectRequest,
        ct: Duration,
    ) -> Result<WgConnectResponse, OperationError> {
        let (token_uuid, tunnel_uuid) = self.wg_token_validate(&req.token, ct)?;

        // Load tunnel config.
        let tunnel_filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::WgTunnel.into()),
            f_eq(Attribute::Uuid, PartialValue::Uuid(tunnel_uuid))
        ]));
        let tunnels = self.qs_write.internal_search(tunnel_filter)?;
        let tunnel_entry = tunnels
            .into_iter()
            .next()
            .ok_or(OperationError::InvalidEntryState)?;
        let tunnel = wg_tunnel_config_from_entry(&tunnel_entry)?;

        // Check pubkey uniqueness.
        let peer_filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::WgPeer.into()),
            f_eq(Attribute::WgTunnelRef, PartialValue::Refer(tunnel_uuid)),
            f_eq(
                Attribute::WgPubkey,
                PartialValue::new_utf8s(req.pubkey.as_str())
            )
        ]));
        if !self.qs_write.internal_search(peer_filter)?.is_empty() {
            return Err(OperationError::UniqueConstraintViolation);
        }

        // Gather existing peer CIDRs for allocation.
        let peer_entries = self.qs_write.internal_search(filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::WgPeer.into()),
            f_eq(Attribute::WgTunnelRef, PartialValue::Refer(tunnel_uuid))
        ])))?;
        let existing: Vec<IpNet> = peer_entries
            .iter()
            .flat_map(|e| {
                e.get_ava_set(Attribute::WgAllowedIps)
                    .and_then(|vs| vs.as_utf8_iter())
                    .map(|iter| {
                        iter.filter_map(|s| s.parse::<IpNet>().ok())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            })
            .collect();

        let allocated = allocate(&tunnel.address, &existing)
            .map_err(|_| OperationError::ResourceLimit)?;

        // Create WgPeer entry.
        let peer_name = format!("peer-{}-{}", caller_name, &tunnel.name);
        let peer_uuid = Uuid::new_v4();
        let mut peer_entry = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::WgPeer.to_value()),
            (Attribute::Name, Value::new_iname(&peer_name)),
            (Attribute::Uuid, Value::Uuid(peer_uuid)),
            (Attribute::WgPubkey, Value::new_utf8s(&req.pubkey)),
            (Attribute::WgTunnelRef, Value::Refer(tunnel_uuid))
        );
        for cidr in &allocated {
            peer_entry.add_ava(Attribute::WgAllowedIps, Value::new_utf8s(&cidr.to_string()));
        }
        self.qs_write.internal_create(vec![peer_entry])?;

        // Consume the token.
        self.wg_token_consume(token_uuid)?;

        // Build wg-quick config string.
        let address_list: Vec<String> = allocated.iter().map(|a| a.to_string()).collect();
        let mut config = format!(
            "[Interface]\nPrivateKey = <client-private-key>\nAddress = {}\n",
            address_list.join(", ")
        );
        if !tunnel.dns.is_empty() {
            config.push_str(&format!("DNS = {}\n", tunnel.dns.join(", ")));
        }
        config.push_str(&format!(
            "\n[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0, ::/0\n",
            tunnel.public_key, tunnel.endpoint
        ));
        if let Some(mtu) = tunnel.mtu {
            config.push_str(&format!("# MTU = {mtu}\n"));
        }

        Ok(WgConnectResponse {
            config,
            address: address_list,
            server_pubkey: tunnel.public_key,
            endpoint: tunnel.endpoint,
        })
    }

    /// Delete a WgToken by name.
    pub fn wg_token_delete(&mut self, tunnel_uuid: Uuid, token_name: &str) -> Result<(), OperationError> {
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::WgToken.into()),
            f_eq(Attribute::WgTunnelRef, PartialValue::Refer(tunnel_uuid)),
            f_eq(Attribute::Name, PartialValue::new_iname(token_name))
        ]));
        self.qs_write.internal_delete(&filter)
    }
}

// ---- Read helpers ----

impl IdmServerProxyReadTransaction<'_> {
    /// List tokens for a tunnel by name.
    pub fn wg_token_list(&mut self, tunnel_name: &str) -> Result<Vec<WgTokenInfo>, OperationError> {
        let tunnel_uuid = self
            .qs_read
            .name_to_uuid(tunnel_name)
            .map_err(|_| OperationError::NoMatchingEntries)?;
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::WgToken.into()),
            f_eq(Attribute::WgTunnelRef, PartialValue::Refer(tunnel_uuid))
        ]));
        let entries = self.qs_read.internal_search(filter)?;
        Ok(entries
            .iter()
            .map(|e| WgTokenInfo {
                name: e
                    .get_ava_single_iname(Attribute::Name)
                    .unwrap_or("")
                    .to_string(),
                uses_left: e.get_ava_single_uint32(Attribute::WgTokenUsesLeft),
                expiry: e
                    .get_ava_single_datetime(Attribute::WgTokenExpiry)
                    .map(|dt| dt.format(&time::format_description::well_known::Rfc3339).unwrap_or_default()),
                principal: e
                    .get_ava_single_refer(Attribute::WgTokenPrincipalRef)
                    .map(|u| u.to_string()),
            })
            .collect())
    }

    /// List peers for a tunnel by name.
    pub fn wg_peer_list(&mut self, tunnel_name: &str) -> Result<Vec<WgPeerResponse>, OperationError> {
        let tunnel_uuid = self
            .qs_read
            .name_to_uuid(tunnel_name)
            .map_err(|_| OperationError::NoMatchingEntries)?;
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::WgPeer.into()),
            f_eq(Attribute::WgTunnelRef, PartialValue::Refer(tunnel_uuid))
        ]));
        let entries = self.qs_read.internal_search(filter)?;
        Ok(entries
            .iter()
            .map(|e| {
                let name = e.get_ava_single_iname(Attribute::Name).unwrap_or("").to_string();
                let pubkey = e.get_ava_single_utf8(Attribute::WgPubkey).unwrap_or("").to_string();
                let allowed_ips = e
                    .get_ava_set(Attribute::WgAllowedIps)
                    .and_then(|vs| vs.as_utf8_iter())
                    .map(|iter| iter.map(|s| s.to_string()).collect::<Vec<_>>())
                    .unwrap_or_default();
                let last_seen = e
                    .get_ava_single_datetime(Attribute::WgLastSeen)
                    .map(|dt| dt.format(&time::format_description::well_known::Rfc3339).unwrap_or_default());
                let keepalive = e.get_ava_single_uint32(Attribute::WgPersistentKeepalive);
                WgPeerResponse {
                    name,
                    pubkey,
                    allowed_ips,
                    user: String::new(),
                    last_seen,
                    keepalive,
                }
            })
            .collect())
    }

    /// Return a single tunnel as an API response (for admin GET).
    pub fn wg_tunnel_get_response(
        &mut self,
        name: &str,
        peer_count: u32,
        backend: &str,
    ) -> Result<Option<WgTunnelResponse>, OperationError> {
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::WgTunnel.into()),
            f_eq(Attribute::Name, PartialValue::new_iname(name))
        ]));
        let entries = self.qs_read.internal_search(filter)?;
        let Some(e) = entries.first() else {
            return Ok(None);
        };
        let cfg = wg_tunnel_config_from_entry(e)?;
        Ok(Some(WgTunnelResponse {
            name: cfg.name,
            interface: cfg.interface,
            public_key: cfg.public_key,
            endpoint: cfg.endpoint,
            listen_port: cfg.listen_port,
            address: cfg.address.iter().map(|a| a.to_string()).collect(),
            dns: cfg.dns,
            mtu: cfg.mtu,
            peer_count,
            backend: backend.to_string(),
        }))
    }
}

// ---- Entry conversion helpers ----

fn wg_tunnel_config_from_entry(
    e: &Arc<EntrySealedCommitted>,
) -> Result<WgTunnelConfig, OperationError> {
    let name = e
        .get_ava_single_iname(Attribute::Name)
        .ok_or(OperationError::InvalidEntryState)?
        .to_string();
    let interface = e
        .get_ava_single_iname(Attribute::WgInterface)
        .ok_or(OperationError::InvalidEntryState)?
        .to_string();
    let private_key = e
        .get_ava_single_utf8(Attribute::WgPrivateKey)
        .ok_or(OperationError::InvalidEntryState)?
        .to_string();
    let public_key = e
        .get_ava_single_utf8(Attribute::WgPublicKey)
        .unwrap_or("")
        .to_string();
    let endpoint = e
        .get_ava_single_utf8(Attribute::WgEndpoint)
        .ok_or(OperationError::InvalidEntryState)?
        .to_string();
    let listen_port = e
        .get_ava_single_uint32(Attribute::WgListenPort)
        .ok_or(OperationError::InvalidEntryState)? as u16;

    let address = e
        .get_ava_set(Attribute::WgAddress)
        .and_then(|vs| vs.as_utf8_iter())
        .map(|iter| iter.filter_map(|s| s.parse().ok()).collect::<Vec<_>>())
        .unwrap_or_default();

    let dns = e
        .get_ava_set(Attribute::WgDns)
        .and_then(|vs| vs.as_utf8_iter())
        .map(|iter| iter.map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    let mtu = e.get_ava_single_uint32(Attribute::WgMtu);

    let pre_up = e
        .get_ava_set(Attribute::WgPreUp)
        .and_then(|vs| vs.as_utf8_iter())
        .map(|iter| iter.map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    let post_up = e
        .get_ava_set(Attribute::WgPostUp)
        .and_then(|vs| vs.as_utf8_iter())
        .map(|iter| iter.map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    let pre_down = e
        .get_ava_set(Attribute::WgPreDown)
        .and_then(|vs| vs.as_utf8_iter())
        .map(|iter| iter.map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    let post_down = e
        .get_ava_set(Attribute::WgPostDown)
        .and_then(|vs| vs.as_utf8_iter())
        .map(|iter| iter.map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();

    Ok(WgTunnelConfig {
        uuid: e.get_uuid(),
        name,
        interface,
        private_key,
        public_key,
        endpoint,
        listen_port,
        address,
        dns,
        mtu,
        pre_up,
        post_up,
        pre_down,
        post_down,
    })
}

fn sha256_of(data: &[u8]) -> Sha256Output {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

fn base64url_encode(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn wg_peer_config_from_entry(
    e: &Arc<EntrySealedCommitted>,
) -> Result<WgPeerConfig, OperationError> {
    let name = e
        .get_ava_single_iname(Attribute::Name)
        .ok_or(OperationError::InvalidEntryState)?
        .to_string();
    let pubkey = e
        .get_ava_single_utf8(Attribute::WgPubkey)
        .ok_or(OperationError::InvalidEntryState)?
        .to_string();

    let allowed_ips = e
        .get_ava_set(Attribute::WgAllowedIps)
        .and_then(|vs| vs.as_utf8_iter())
        .map(|iter| iter.filter_map(|s| s.parse().ok()).collect::<Vec<_>>())
        .unwrap_or_default();

    let preshared_key = e
        .get_ava_single_utf8(Attribute::WgPresharedKey)
        .map(|s| s.to_string());

    let persistent_keepalive = e.get_ava_single_uint32(Attribute::WgPersistentKeepalive);

    Ok(WgPeerConfig {
        name,
        pubkey,
        allowed_ips,
        preshared_key,
        persistent_keepalive,
        endpoint: None,
    })
}

#[cfg(test)]
mod tests {
    use super::{base64url_encode, sha256_of};

    #[test]
    fn base64url_encode_produces_no_padding() {
        let encoded = base64url_encode(b"hello world");
        assert!(!encoded.contains('='), "URL-safe base64 should have no padding");
        assert!(!encoded.contains('+'), "URL-safe base64 should not contain '+'");
        assert!(!encoded.contains('/'), "URL-safe base64 should not contain '/'");
        assert_eq!(encoded, "aGVsbG8gd29ybGQ");
    }

    #[test]
    fn sha256_produces_32_bytes() {
        let hash = sha256_of(b"test");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn sha256_is_deterministic() {
        let h1 = sha256_of(b"some data");
        let h2 = sha256_of(b"some data");
        assert_eq!(h1, h2);
    }

    #[test]
    fn sha256_differs_for_different_inputs() {
        let h1 = sha256_of(b"data1");
        let h2 = sha256_of(b"data2");
        assert_ne!(h1, h2);
    }
}
