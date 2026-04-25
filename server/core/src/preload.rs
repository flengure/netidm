//! TOML preload system — applies operator-authored resource definitions on
//! startup and SIGHUP reload.
//!
//! Files in `preload.d/` must match `^\d\d-.*\.toml$` and are applied in
//! lexicographic order. Each file produces one idempotent assertion batch:
//! if the file content (SHA-256 nonce) has not changed since the last run,
//! the batch is skipped entirely.
//!
//! Removing a file stops future assertion but does NOT delete the resource.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::LazyLock;

use crypto_glue::s256::{Sha256, Sha256Output};
use crypto_glue::traits::Digest;
use regex::Regex;
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};
use uuid::Uuid;

use netidm_proto::attribute::Attribute;
use netidm_proto::scim_v1::client::{ScimAssertGeneric, ScimEntryAssertion};

use crate::actors::QueryServerWriteV1;

static PRELOAD_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new(r"^\d\d-.*\.toml$").expect("Invalid preload path regex")
});

fn preload_uuid(kind: &str, name: &str) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!("netidm:preload:{}:{}", kind, name).as_bytes(),
    )
}

fn file_migration_id(path: &Path) -> Uuid {
    Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!("netidm:preload:file:{}", path.display()).as_bytes(),
    )
}

// ── TOML schema ──────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Default)]
struct PreloadFile {
    #[serde(default)]
    tunnel: Vec<PreloadTunnel>,
    #[serde(default)]
    user: Vec<PreloadUser>,
    #[serde(default)]
    group: Vec<PreloadGroup>,
    #[serde(default)]
    oauth2_client: Vec<PreloadOAuth2Client>,
    #[serde(default)]
    connector: Vec<PreloadConnector>,
}

#[derive(Debug, Deserialize)]
struct PreloadTunnel {
    name: String,
    interface: String,
    private_key: String,
    endpoint: String,
    listen_port: u16,
    address: Vec<String>,
    #[serde(default)]
    dns: Vec<String>,
    mtu: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct PreloadSshKey {
    label: String,
    value: String,
}

#[derive(Debug, Deserialize)]
struct PreloadWgPeer {
    tunnel: String,
    name: String,
    pubkey: String,
    address: Vec<String>,
    psk: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PreloadUser {
    name: String,
    displayname: String,
    legalname: Option<String>,
    email: String,
    /// If present, adds the `posixaccount` class and sets `loginShell`.
    shell: Option<String>,
    #[serde(default)]
    ssh_keys: Vec<PreloadSshKey>,
    #[serde(default)]
    wg_peers: Vec<PreloadWgPeer>,
}

#[derive(Debug, Deserialize)]
struct PreloadGroup {
    name: String,
    /// `true` adds the `posixgroup` class.
    #[serde(default)]
    posix: bool,
    #[serde(default)]
    members: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PreloadScopeMap {
    group: String,
    scopes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct PreloadOAuth2Client {
    name: String,
    displayname: Option<String>,
    origin: String,
    origin_landing: Option<String>,
    #[serde(default)]
    disable_pkce: bool,
    /// Defaults to a single map: `idm_all_accounts` → standard OIDC scopes.
    #[serde(default)]
    scope_maps: Vec<PreloadScopeMap>,
}

#[derive(Debug, Deserialize)]
struct PreloadGroupMapping {
    upstream: String,
    /// Short name of a group also defined in this preload system.
    group: String,
}

#[derive(Debug, Deserialize)]
struct PreloadConnector {
    name: String,
    displayname: Option<String>,
    provider: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    jit_provisioning: bool,
    #[serde(default)]
    email_link_accounts: bool,
    /// Provider-specific: GitHub org restriction.
    #[serde(default)]
    org_filter: Vec<String>,
    /// Provider-specific: GitHub team allowlist (`"Org:team"` format).
    #[serde(default)]
    allowed_teams: Vec<String>,
    /// Maps upstream team/group names to netidm group names.
    #[serde(default)]
    group_mappings: Vec<PreloadGroupMapping>,
    /// Additional OAuth2 scopes beyond the provider default.
    #[serde(default)]
    extra_scopes: Vec<String>,
}

// ── Assertion builders ────────────────────────────────────────────────────────

impl PreloadTunnel {
    fn to_assertion(&self) -> ScimEntryAssertion {
        let mut attrs: BTreeMap<Attribute, Option<JsonValue>> = BTreeMap::new();
        attrs.insert(Attribute::Class, Some(json!(["wg_tunnel"])));
        attrs.insert(Attribute::Name, Some(json!(self.name)));
        attrs.insert(Attribute::WgInterface, Some(json!(self.interface)));
        attrs.insert(Attribute::WgPrivateKey, Some(json!(self.private_key)));
        attrs.insert(Attribute::WgEndpoint, Some(json!(self.endpoint)));
        attrs.insert(Attribute::WgListenPort, Some(json!(self.listen_port)));
        attrs.insert(Attribute::WgAddress, Some(json!(self.address)));
        if !self.dns.is_empty() {
            attrs.insert(Attribute::WgDns, Some(json!(self.dns)));
        }
        if let Some(mtu) = self.mtu {
            attrs.insert(Attribute::WgMtu, Some(json!(mtu)));
        }
        ScimEntryAssertion::Present {
            id: preload_uuid("tunnel", &self.name),
            attrs,
        }
    }
}

impl PreloadUser {
    fn to_assertion(&self) -> ScimEntryAssertion {
        let mut attrs: BTreeMap<Attribute, Option<JsonValue>> = BTreeMap::new();

        let classes = if self.shell.is_some() {
            json!(["person", "account", "posixaccount"])
        } else {
            json!(["person", "account"])
        };
        attrs.insert(Attribute::Class, Some(classes));
        attrs.insert(Attribute::Name, Some(json!(self.name)));
        attrs.insert(Attribute::DisplayName, Some(json!(self.displayname)));
        attrs.insert(
            Attribute::LegalName,
            Some(json!(self
                .legalname
                .as_deref()
                .unwrap_or(self.displayname.as_str()))),
        );
        attrs.insert(Attribute::Mail, Some(json!([{"value": self.email}])));

        if let Some(shell) = &self.shell {
            attrs.insert(Attribute::LoginShell, Some(json!(shell)));
        }

        if !self.ssh_keys.is_empty() {
            let keys: Vec<JsonValue> = self
                .ssh_keys
                .iter()
                .map(|k| json!({"label": k.label, "value": k.value}))
                .collect();
            attrs.insert(Attribute::SshPublicKey, Some(json!(keys)));
        }

        if !self.wg_peers.is_empty() {
            // WgInlinePeer is the virtual attribute that scim_assert expands
            // into separate WgPeer entries.
            let peers: Vec<JsonValue> = self
                .wg_peers
                .iter()
                .map(|p| {
                    let mut map = serde_json::Map::new();
                    map.insert("tunnel".into(), json!(p.tunnel));
                    map.insert("name".into(), json!(p.name));
                    map.insert("key".into(), json!(p.pubkey));
                    map.insert("address".into(), json!(p.address.join(",")));
                    if let Some(psk) = &p.psk {
                        map.insert("psk".into(), json!(psk));
                    }
                    JsonValue::Object(map)
                })
                .collect();
            attrs.insert(Attribute::WgInlinePeer, Some(json!(peers)));
        }

        ScimEntryAssertion::Present {
            id: preload_uuid("user", &self.name),
            attrs,
        }
    }
}

impl PreloadGroup {
    fn to_assertion(&self) -> ScimEntryAssertion {
        let mut attrs: BTreeMap<Attribute, Option<JsonValue>> = BTreeMap::new();

        let classes = if self.posix {
            json!(["group", "posixgroup"])
        } else {
            json!(["group"])
        };
        attrs.insert(Attribute::Class, Some(classes));
        attrs.insert(Attribute::Name, Some(json!(self.name)));

        if !self.members.is_empty() {
            let members: Vec<JsonValue> =
                self.members.iter().map(|m| json!({"value": m})).collect();
            attrs.insert(Attribute::Member, Some(json!(members)));
        }

        ScimEntryAssertion::Present {
            id: preload_uuid("group", &self.name),
            attrs,
        }
    }
}

impl PreloadOAuth2Client {
    fn to_assertion(&self) -> ScimEntryAssertion {
        let mut attrs: BTreeMap<Attribute, Option<JsonValue>> = BTreeMap::new();

        attrs.insert(
            Attribute::Class,
            Some(json!([
                "oauth2_resource_server",
                "oauth2_resource_server_basic"
            ])),
        );
        attrs.insert(Attribute::Name, Some(json!(self.name)));
        attrs.insert(
            Attribute::DisplayName,
            Some(json!(self.displayname.as_deref().unwrap_or(&self.name))),
        );
        attrs.insert(Attribute::OAuth2RsOrigin, Some(json!(self.origin)));
        attrs.insert(
            Attribute::OAuth2RsOriginLanding,
            Some(json!(self
                .origin_landing
                .as_deref()
                .unwrap_or(&self.origin))),
        );

        if self.disable_pkce {
            attrs.insert(
                Attribute::OAuth2AllowInsecureClientDisablePkce,
                Some(json!(true)),
            );
        }

        let scope_maps: Vec<JsonValue> = if self.scope_maps.is_empty() {
            vec![json!({
                "group": "idm_all_accounts",
                "scopes": ["openid", "profile", "email", "groups", "offline_access"],
            })]
        } else {
            self.scope_maps
                .iter()
                .map(|sm| json!({"group": sm.group, "scopes": sm.scopes}))
                .collect()
        };
        attrs.insert(Attribute::OAuth2RsScopeMap, Some(json!(scope_maps)));

        ScimEntryAssertion::Present {
            id: preload_uuid("oauth2_client", &self.name),
            attrs,
        }
    }
}

impl PreloadConnector {
    fn to_assertion(&self) -> ScimEntryAssertion {
        let mut attrs: BTreeMap<Attribute, Option<JsonValue>> = BTreeMap::new();

        attrs.insert(Attribute::Class, Some(json!(["connector"])));
        attrs.insert(Attribute::Name, Some(json!(self.name)));
        attrs.insert(
            Attribute::DisplayName,
            Some(json!(self.displayname.as_deref().unwrap_or(&self.name))),
        );
        attrs.insert(Attribute::ConnectorProviderKind, Some(json!(self.provider)));
        attrs.insert(Attribute::ConnectorId, Some(json!(self.client_id)));
        attrs.insert(Attribute::ConnectorSecret, Some(json!(self.client_secret)));

        if self.email_link_accounts {
            attrs.insert(Attribute::OAuth2EmailLinkAccounts, Some(json!(true)));
        }

        if self.provider == "github" {
            attrs.insert(
                Attribute::OAuth2AuthorisationEndpoint,
                Some(json!("https://github.com/login/oauth/authorize")),
            );
            attrs.insert(
                Attribute::OAuth2TokenEndpoint,
                Some(json!("https://github.com/login/oauth/access_token")),
            );
            attrs.insert(
                Attribute::OAuth2UserinfoEndpoint,
                Some(json!("https://api.github.com/user")),
            );

            let mut scopes = vec!["read:user", "user:email", "read:org"];
            for extra in &self.extra_scopes {
                if !scopes.contains(&extra.as_str()) {
                    scopes.push(extra.as_str());
                }
            }
            attrs.insert(Attribute::OAuth2RequestScopes, Some(json!(scopes)));

            if self.jit_provisioning {
                attrs.insert(
                    Attribute::ConnectorGithubAllowJitProvisioning,
                    Some(json!(true)),
                );
                attrs.insert(Attribute::ConnectorGithubLoadAllGroups, Some(json!(true)));
            }

            if !self.org_filter.is_empty() {
                attrs.insert(
                    Attribute::ConnectorGithubOrgFilter,
                    Some(json!(self.org_filter)),
                );
            }

            if !self.allowed_teams.is_empty() {
                attrs.insert(
                    Attribute::ConnectorGithubAllowedTeams,
                    Some(json!(self.allowed_teams)),
                );
            }
        }

        if !self.group_mappings.is_empty() {
            // Format: "upstream:group_uuid" — the target group must also be
            // seeded via this preload system so its UUID is deterministic.
            let mappings: Vec<JsonValue> = self
                .group_mappings
                .iter()
                .map(|m| {
                    let group_uuid = preload_uuid("group", &m.group);
                    json!(format!("{}:{}", m.upstream, group_uuid))
                })
                .collect();
            attrs.insert(Attribute::OAuth2GroupMapping, Some(json!(mappings)));
        }

        ScimEntryAssertion::Present {
            id: preload_uuid("connector", &self.name),
            attrs,
        }
    }
}

// ── preload_apply ─────────────────────────────────────────────────────────────

#[tracing::instrument(
    level = "info",
    fields(uuid = ?eventid),
    skip_all,
)]
pub async fn preload_apply(
    eventid: Uuid,
    server_write_ref: &'static QueryServerWriteV1,
    preload_path: &Path,
) {
    if !preload_path.exists() {
        info!(
            path = %preload_path.display(),
            "Preload path does not exist — skipping."
        );
        return;
    }

    let mut dir_ents = match tokio::fs::read_dir(preload_path).await {
        Ok(d) => d,
        Err(err) => {
            error!(?err, "Unable to read preload directory.");
            return;
        }
    };

    let mut paths = Vec::new();
    loop {
        match dir_ents.next_entry().await {
            Ok(Some(ent)) => paths.push(ent.path()),
            Ok(None) => break,
            Err(err) => {
                error!(?err, "Unable to read preload directory entries.");
                return;
            }
        }
    }

    let mut paths: Vec<_> = paths
        .into_iter()
        .filter(|p| {
            if !p.is_file() {
                return false;
            }
            let Some(name) = p.file_name().and_then(|n| n.to_str()) else {
                return false;
            };
            if !PRELOAD_RE.is_match(name) {
                info!(
                    path = %p.display(),
                    "ignoring file that does not match naming pattern (expected NN-name.toml)"
                );
                return false;
            }
            true
        })
        .collect();

    paths.sort_unstable();

    for path in paths {
        info!(path = %path.display(), "examining preload file");

        let content = match tokio::fs::read(&path).await {
            Ok(b) => b,
            Err(err) => {
                error!(?err, path = %path.display(), "Unable to read preload file — skipping.");
                continue;
            }
        };

        let content_str = match std::str::from_utf8(&content) {
            Ok(s) => s,
            Err(err) => {
                error!(?err, path = %path.display(), "Preload file is not valid UTF-8 — skipping.");
                continue;
            }
        };

        let preload_file: PreloadFile = match toml::from_str(content_str) {
            Ok(f) => f,
            Err(err) => {
                error!(?err, path = %path.display(), "Invalid TOML preload file — skipping.");
                continue;
            }
        };

        let mut assertions: Vec<ScimEntryAssertion> = Vec::new();

        for t in &preload_file.tunnel {
            assertions.push(t.to_assertion());
        }
        for u in &preload_file.user {
            assertions.push(u.to_assertion());
        }
        for g in &preload_file.group {
            assertions.push(g.to_assertion());
        }
        for c in &preload_file.oauth2_client {
            assertions.push(c.to_assertion());
        }
        for conn in &preload_file.connector {
            assertions.push(conn.to_assertion());
        }

        if assertions.is_empty() {
            info!(path = %path.display(), "Preload file has no entries — skipping.");
            continue;
        }

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let nonce: Sha256Output = hasher.finalize();

        let scim = ScimAssertGeneric {
            id: file_migration_id(&path),
            assertions,
        };

        if let Err(err) = server_write_ref
            .handle_scim_migration_apply(eventid, scim, nonce)
            .await
        {
            error!(?err, path = %path.display(), "Failed to apply preload file.");
        }
    }
}
