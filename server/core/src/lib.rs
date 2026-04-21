//! These contain the server "cores". These are able to startup the server
//! (bootstrap) to a running state and then execute tasks. This is where modules
//! are logically ordered based on their depenedncies for execution. Some of these
//! are task-only i.e. reindexing, and some of these launch the server into a
//! fully operational state (https, ldap, etc).
//!
//! Generally, this is the "entry point" where the server begins to run, and
//! the entry point for all client traffic which is then directed to the
//! various `actors`.

#![deny(warnings)]
#![warn(unused_extern_crates)]
#![warn(unused_imports)]
#![deny(clippy::todo)]
#![deny(clippy::unimplemented)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
#![deny(clippy::panic)]
#![deny(clippy::unreachable)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::needless_pass_by_value)]
#![deny(clippy::trivially_copy_pass_by_ref)]
#![deny(clippy::indexing_slicing)]

#[macro_use]
extern crate tracing;
#[macro_use]
extern crate netidmd_lib;

mod actors;
pub mod admin;
pub mod config;
mod crypto;
mod https;
mod interval;
mod ldaps;
mod logout_worker;
mod repl;
mod tcp;
mod utils;

use crate::actors::{QueryServerReadV1, QueryServerWriteV1};
use crate::admin::AdminActor;
use crate::config::Configuration;
use crate::interval::IntervalActor;
use crate::utils::touch_file_or_quit;
use compact_jwt::{JwsHs256Signer, JwsSigner};
use crypto_glue::{
    s256::{Sha256, Sha256Output},
    traits::Digest,
};
use netidm_proto::backup::BackupCompression;
use netidm_proto::config::ServerRole;
use netidm_proto::internal::OperationError;
use netidm_proto::scim_v1::client::ScimAssertGeneric;
use netidmd_lib::be::{Backend, BackendConfig, BackendTransaction};
use netidmd_lib::idm::ldap::LdapServer;
use netidmd_lib::idm::oauth2_connector::ConnectorRegistry;
use netidmd_lib::idm::server::IdmServer;
use netidmd_lib::prelude::*;
use netidmd_lib::schema::Schema;
use netidmd_lib::status::StatusActor;
use netidmd_lib::value::CredentialType;
use netidmd_wg::{
    backend::boringtun::BoringtunBackend, backend::kernel::KernelBackend, BackendKind, WgManager,
};
use regex::Regex;
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::LazyLock;
use tokio::sync::broadcast;
use tokio::task;

#[cfg(not(target_family = "windows"))]
use libc::umask;

// === internal setup helpers

fn setup_backend(config: &Configuration, schema: &Schema) -> Result<Backend, OperationError> {
    setup_backend_vacuum(config, schema, false)
}

fn setup_backend_vacuum(
    config: &Configuration,
    schema: &Schema,
    vacuum: bool,
) -> Result<Backend, OperationError> {
    // Limit the scope of the schema txn.
    // let schema_txn = task::block_on(schema.write());
    let schema_txn = schema.write();
    let idxmeta = schema_txn.reload_idxmeta();

    let pool_size: u32 = config.threads as u32;

    let cfg = BackendConfig::new(
        config.db_path.as_deref(),
        pool_size,
        config.db_fs_type.unwrap_or_default(),
        config.db_arc_size,
    );

    Backend::new(cfg, idxmeta, vacuum)
}

// TODO #54: We could move most of the be/schema/qs setup and startup
// outside of this call, then pass in "what we need" in a cloneable
// form, this way we could have separate Idm vs Qs threads, and dedicated
// threads for write vs read
async fn setup_qs_idms(
    be: Backend,
    schema: Schema,
    config: &Configuration,
) -> Result<(QueryServer, IdmServer, IdmServerDelayed, IdmServerAudit), OperationError> {
    let curtime = duration_from_epoch_now();
    // Create a query_server implementation
    let query_server = QueryServer::new(be, schema, config.domain.clone(), curtime)?;

    // TODO #62: Should the IDM parts be broken out to the IdmServer?
    // What's important about this initial setup here is that it also triggers
    // the schema and acp reload, so they are now configured correctly!
    // Initialise the schema core.
    //
    // Now search for the schema itself, and validate that the system
    // in memory matches the BE on disk, and that it's syntactically correct.
    // Write it out if changes are needed.
    query_server
        .initialise_helper(curtime, DOMAIN_TGT_LEVEL)
        .await?;

    // We generate a SINGLE idms only!
    let is_integration_test = config.integration_test_config.is_some();
    let (idms, idms_delayed, idms_audit) = IdmServer::new(
        query_server.clone(),
        &config.origin,
        is_integration_test,
        curtime,
    )
    .await?;

    Ok((query_server, idms, idms_delayed, idms_audit))
}

async fn setup_qs(
    be: Backend,
    schema: Schema,
    config: &Configuration,
) -> Result<QueryServer, OperationError> {
    let curtime = duration_from_epoch_now();
    // Create a query_server implementation
    let query_server = QueryServer::new(be, schema, config.domain.clone(), curtime)?;

    // TODO #62: Should the IDM parts be broken out to the IdmServer?
    // What's important about this initial setup here is that it also triggers
    // the schema and acp reload, so they are now configured correctly!
    // Initialise the schema core.
    //
    // Now search for the schema itself, and validate that the system
    // in memory matches the BE on disk, and that it's syntactically correct.
    // Write it out if changes are needed.
    query_server
        .initialise_helper(curtime, DOMAIN_TGT_LEVEL)
        .await?;

    Ok(query_server)
}

macro_rules! dbscan_setup_be {
    (
        $config:expr
    ) => {{
        let schema = match Schema::new() {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to setup in memory schema: {:?}", e);
                std::process::exit(1);
            }
        };

        match setup_backend($config, &schema) {
            Ok(be) => be,
            Err(e) => {
                error!("Failed to setup BE: {:?}", e);
                return;
            }
        }
    }};
}

pub fn dbscan_list_indexes_core(config: &Configuration) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_indexes() {
        Ok(mut idx_list) => {
            idx_list.sort_unstable();
            idx_list.iter().for_each(|idx_name| {
                println!("{idx_name}");
            })
        }
        Err(e) => {
            error!("Failed to retrieve index list: {:?}", e);
        }
    };
}

pub fn dbscan_list_id2entry_core(config: &Configuration) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_id2entry() {
        Ok(mut id_list) => {
            id_list.sort_unstable_by_key(|k| k.0);
            id_list.iter().for_each(|(id, value)| {
                println!("{id:>8}: {value}");
            })
        }
        Err(e) => {
            error!("Failed to retrieve id2entry list: {:?}", e);
        }
    };
}

pub fn dbscan_list_index_analysis_core(config: &Configuration) {
    let _be = dbscan_setup_be!(config);
    // TBD in after slopes merge.
}

pub fn dbscan_list_index_core(config: &Configuration, index_name: &str) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_index_content(index_name) {
        Ok(mut idx_list) => {
            idx_list.sort_unstable_by(|a, b| a.0.cmp(&b.0));
            idx_list.iter().for_each(|(key, value)| {
                println!("{key:>50}: {value:?}");
            })
        }
        Err(e) => {
            error!("Failed to retrieve index list: {:?}", e);
        }
    };
}

pub fn dbscan_get_id2entry_core(config: &Configuration, id: u64) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.get_id2entry(id) {
        Ok((id, value)) => println!("{id:>8}: {value}"),
        Err(e) => {
            error!("Failed to retrieve id2entry value: {:?}", e);
        }
    };
}

pub fn dbscan_quarantine_id2entry_core(config: &Configuration, id: u64) {
    let be = dbscan_setup_be!(config);
    let mut be_wrtxn = match be.write() {
        Ok(txn) => txn,
        Err(err) => {
            error!(
                ?err,
                "Unable to proceed, backend write transaction failure."
            );
            return;
        }
    };

    match be_wrtxn
        .quarantine_entry(id)
        .and_then(|_| be_wrtxn.commit())
    {
        Ok(()) => {
            println!("quarantined - {id:>8}")
        }
        Err(e) => {
            error!("Failed to quarantine id2entry value: {:?}", e);
        }
    };
}

pub fn dbscan_list_quarantined_core(config: &Configuration) {
    let be = dbscan_setup_be!(config);
    let mut be_rotxn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    match be_rotxn.list_quarantined() {
        Ok(mut id_list) => {
            id_list.sort_unstable_by_key(|k| k.0);
            id_list.iter().for_each(|(id, value)| {
                println!("{id:>8}: {value}");
            })
        }
        Err(e) => {
            error!("Failed to retrieve id2entry list: {:?}", e);
        }
    };
}

pub fn dbscan_restore_quarantined_core(config: &Configuration, id: u64) {
    let be = dbscan_setup_be!(config);
    let mut be_wrtxn = match be.write() {
        Ok(txn) => txn,
        Err(err) => {
            error!(
                ?err,
                "Unable to proceed, backend write transaction failure."
            );
            return;
        }
    };

    match be_wrtxn
        .restore_quarantined(id)
        .and_then(|_| be_wrtxn.commit())
    {
        Ok(()) => {
            println!("restored - {id:>8}")
        }
        Err(e) => {
            error!("Failed to restore quarantined id2entry value: {:?}", e);
        }
    };
}

pub fn backup_server_core(config: &Configuration, dst_path: Option<&Path>) {
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    let be = match setup_backend(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    let mut be_ro_txn = match be.read() {
        Ok(txn) => txn,
        Err(err) => {
            error!(?err, "Unable to proceed, backend read transaction failure.");
            return;
        }
    };

    let compression = match config.online_backup.as_ref() {
        Some(backup_config) => backup_config.compression,
        None => BackupCompression::default(),
    };

    if let Some(dst_path) = dst_path {
        if dst_path.exists() {
            error!(
                "backup file {} already exists, will not overwrite it.",
                dst_path.display()
            );
            return;
        }

        let output = match std::fs::File::create(dst_path) {
            Ok(output) => output,
            Err(err) => {
                error!(?err, "File::create error creating {}", dst_path.display());
                return;
            }
        };

        match be_ro_txn.backup(output, compression) {
            Ok(_) => info!("Backup success!"),
            Err(e) => {
                error!("Backup failed: {:?}", e);
                std::process::exit(1);
            }
        };
    } else {
        // No path set, default to stdout
        let stdout = std::io::stdout().lock();

        match be_ro_txn.backup(stdout, compression) {
            Ok(_) => info!("Backup success!"),
            Err(e) => {
                error!("Backup failed: {:?}", e);
                std::process::exit(1);
            }
        };
    };
    // Let the txn abort, even on success.
}

pub async fn restore_server_core(config: &Configuration, dst_path: &Path) {
    // If it's an in memory database, we don't need to touch anything
    if let Some(db_path) = config.db_path.as_ref() {
        touch_file_or_quit(db_path);
    }

    // First, we provide the in-memory schema so that core attrs are indexed correctly.
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    let be = match setup_backend(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup backend: {:?}", e);
            return;
        }
    };

    let mut be_wr_txn = match be.write() {
        Ok(txn) => txn,
        Err(err) => {
            error!(
                ?err,
                "Unable to proceed, backend write transaction failure."
            );
            return;
        }
    };

    let compression = BackupCompression::identify_file(dst_path);

    let input = match std::fs::File::open(dst_path) {
        Ok(output) => output,
        Err(err) => {
            error!(?err, "File::open error reading {}", dst_path.display());
            return;
        }
    };

    let r = be_wr_txn
        .restore(input, compression)
        .and_then(|_| be_wr_txn.commit());

    if r.is_err() {
        error!("Failed to restore database: {:?}", r);
        std::process::exit(1);
    }
    info!("Database loaded successfully");

    reindex_inner(be, schema, config).await;

    info!("✅ Restore Success!");
}

pub async fn reindex_server_core(config: &Configuration) {
    info!("Start Index Phase 1 ...");
    // First, we provide the in-memory schema so that core attrs are indexed correctly.
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            std::process::exit(1);
        }
    };

    let be = match setup_backend(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    reindex_inner(be, schema, config).await;

    info!("✅ Reindex Success!");
}

async fn reindex_inner(be: Backend, schema: Schema, config: &Configuration) {
    // Reindex only the core schema attributes to bootstrap the process.
    let mut be_wr_txn = match be.write() {
        Ok(txn) => txn,
        Err(err) => {
            error!(
                ?err,
                "Unable to proceed, backend write transaction failure."
            );
            return;
        }
    };

    let r = be_wr_txn.reindex(true).and_then(|_| be_wr_txn.commit());

    // Now that's done, setup a minimal qs and reindex from that.
    if r.is_err() {
        error!("Failed to reindex database: {:?}", r);
        std::process::exit(1);
    }
    info!("Index Phase 1 Success!");

    info!("Attempting to init query server ...");

    let (qs, _idms, _idms_delayed, _idms_audit) = match setup_qs_idms(be, schema, config).await {
        Ok(t) => t,
        Err(e) => {
            error!("Unable to setup query server or idm server -> {:?}", e);
            return;
        }
    };
    info!("Init Query Server Success!");

    info!("Start Index Phase 2 ...");

    let Ok(mut qs_write) = qs.write(duration_from_epoch_now()).await else {
        error!("Unable to acquire write transaction");
        return;
    };
    let r = qs_write.reindex(true).and_then(|_| qs_write.commit());

    match r {
        Ok(_) => info!("Index Phase 2 Success!"),
        Err(e) => {
            error!("Reindex failed: {:?}", e);
            std::process::exit(1);
        }
    };
}

pub fn vacuum_server_core(config: &Configuration) {
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to setup in memory schema: {e:?}");
            std::process::exit(1);
        }
    };

    // The schema doesn't matter here. Vacuum is run as part of db open to avoid
    // locking.
    let r = setup_backend_vacuum(config, &schema, true);

    match r {
        Ok(_) => eprintln!("Vacuum Success!"),
        Err(e) => {
            eprintln!("Vacuum failed: {e:?}");
            std::process::exit(1);
        }
    };
}

pub async fn domain_rename_core(config: &Configuration) {
    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to setup in memory schema: {e:?}");
            std::process::exit(1);
        }
    };

    // Start the backend.
    let be = match setup_backend(config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    // Setup the qs, and perform any migrations and changes we may have.
    let qs = match setup_qs(be, schema, config).await {
        Ok(t) => t,
        Err(e) => {
            error!("Unable to setup query server -> {:?}", e);
            return;
        }
    };

    let new_domain_name = config.domain.as_str();

    // make sure we're actually changing the domain name...
    match qs.read().await.map(|qs| qs.get_domain_name().to_string()) {
        Ok(old_domain_name) => {
            admin_info!(?old_domain_name, ?new_domain_name);
            if old_domain_name == new_domain_name {
                admin_info!("Domain name not changing, stopping.");
                return;
            }
            admin_debug!(
                "Domain name is changing from {:?} to {:?}",
                old_domain_name,
                new_domain_name
            );
        }
        Err(e) => {
            admin_error!("Failed to query domain name, quitting! -> {:?}", e);
            return;
        }
    }

    let Ok(mut qs_write) = qs.write(duration_from_epoch_now()).await else {
        error!("Unable to acquire write transaction");
        return;
    };
    let r = qs_write
        .danger_domain_rename(new_domain_name)
        .and_then(|_| qs_write.commit());

    match r {
        Ok(_) => info!("Domain Rename Success!"),
        Err(e) => {
            error!("Domain Rename Failed - Rollback has occurred: {:?}", e);
            std::process::exit(1);
        }
    };
}

pub async fn verify_server_core(config: &Configuration) {
    let curtime = duration_from_epoch_now();
    // setup the qs - without initialise!
    let schema_mem = match Schema::new() {
        Ok(sc) => sc,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            return;
        }
    };
    // Setup the be
    let be = match setup_backend(config, &schema_mem) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE: {:?}", e);
            return;
        }
    };

    let server = match QueryServer::new(be, schema_mem, config.domain.clone(), curtime) {
        Ok(qs) => qs,
        Err(err) => {
            error!(?err, "Failed to setup query server");
            return;
        }
    };

    // Run verifications.
    let r = server.verify().await;

    if r.is_empty() {
        eprintln!("Verification passed!");
        std::process::exit(0);
    } else {
        for er in r {
            error!("{:?}", er);
        }
        std::process::exit(1);
    }

    // Now add IDM server verifications?
}

pub fn cert_generate_core(config: &Configuration) {
    // Get the cert root

    let (tls_key_path, tls_chain_path) = match &config.tls_config {
        Some(tls_config) => (tls_config.key.as_path(), tls_config.chain.as_path()),
        None => {
            error!("Unable to find TLS configuration");
            std::process::exit(1);
        }
    };

    if tls_key_path.exists() && tls_chain_path.exists() {
        info!(
            "TLS key and chain already exist - remove them first if you intend to regenerate these"
        );
        return;
    }

    let origin_domain = match config.origin.domain() {
        Some(val) => val,
        None => {
            error!("origin does not contain a valid domain");
            std::process::exit(1);
        }
    };

    let cert_root = match tls_key_path.parent() {
        Some(parent) => parent,
        None => {
            error!("Unable to find parent directory of {:?}", tls_key_path);
            std::process::exit(1);
        }
    };

    let ca_cert = cert_root.join("ca.pem");
    let ca_key = cert_root.join("cakey.pem");
    let tls_cert_path = cert_root.join("cert.pem");

    let ca_handle = if !ca_cert.exists() || !ca_key.exists() {
        // Generate the CA again.
        let ca_handle = match crypto::build_ca() {
            Ok(ca_handle) => ca_handle,
            Err(e) => {
                error!(err = ?e, "Failed to build CA");
                std::process::exit(1);
            }
        };

        if crypto::write_ca(ca_key, ca_cert, &ca_handle).is_err() {
            error!("Failed to write CA");
            std::process::exit(1);
        }

        ca_handle
    } else {
        match crypto::load_ca(ca_key, ca_cert) {
            Ok(ca_handle) => ca_handle,
            Err(_) => {
                error!("Failed to load CA");
                std::process::exit(1);
            }
        }
    };

    if !tls_key_path.exists() || !tls_chain_path.exists() || !tls_cert_path.exists() {
        // Generate the cert from the ca.
        let cert_handle = match crypto::build_cert(origin_domain, &ca_handle) {
            Ok(cert_handle) => cert_handle,
            Err(e) => {
                error!(err = ?e, "Failed to build certificate");
                std::process::exit(1);
            }
        };

        if crypto::write_cert(tls_key_path, tls_chain_path, tls_cert_path, &cert_handle).is_err() {
            error!("Failed to write certificates");
            std::process::exit(1);
        }
    }
    info!("certificate generation complete");
}

static MIGRATION_PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    #[allow(clippy::expect_used)]
    Regex::new("^\\d\\d-.*\\.h?json$").expect("Invalid SPN regex found")
});

struct ScimMigration {
    path: PathBuf,
    hash: Sha256Output,
    assertions: ScimAssertGeneric,
}

#[instrument(
    level = "info",
    fields(uuid = ?eventid),
    skip_all,
)]
async fn migration_apply(
    eventid: Uuid,
    server_write_ref: &'static QueryServerWriteV1,
    migration_path: &Path,
) {
    if !migration_path.exists() {
        info!(migration_path = %migration_path.display(), "Migration path does not exist - migrations will be skipped.");
        return;
    }

    let mut dir_ents = match tokio::fs::read_dir(migration_path).await {
        Ok(dir_ents) => dir_ents,
        Err(err) => {
            error!(?err, "Unable to read migration directory.");
            let diag = netidm_lib_file_permissions::diagnose_path(migration_path);
            info!(%diag);
            return;
        }
    };

    let mut migration_paths = Vec::with_capacity(8);

    loop {
        match dir_ents.next_entry().await {
            Ok(Some(dir_ent)) => migration_paths.push(dir_ent.path()),
            Ok(None) => {
                // Complete,
                break;
            }
            Err(err) => {
                error!(?err, "Unable to read directory entries.");
                return;
            }
        }
    }

    // Filter these.

    let mut migration_paths: Vec<_> = migration_paths.into_iter()
        .filter(|path| {
            if !path.is_file() {
                info!(path = %path.display(), "ignoring path that is not a file.");
                return false;
            }

            let Some(file_name) = path.file_name().and_then(std::ffi::OsStr::to_str) else {
                info!(path = %path.display(), "ignoring path that has no file name, or is not a valid utf-8 file name.");
                return false;
            };

            if !MIGRATION_PATH_RE.is_match(file_name) {
                info!(path = %path.display(), "ignoring file that does not match naming pattern.");
                info!("expected pattern 'XX-NAME.json' where XX are two numbers, followed by a hypen, with the file extension .json");
                return false;
            }

            true
        })
        .collect();

    migration_paths.sort_unstable();
    let mut migrations = Vec::with_capacity(migration_paths.len());

    for migration_path in migration_paths {
        info!(path = %migration_path.display(), "examining migration");

        let migration_content = match tokio::fs::read(&migration_path).await {
            Ok(bytes) => bytes,
            Err(err) => {
                error!(?err, "Unable to read migration - it will be ignored.");
                let diag = netidm_lib_file_permissions::diagnose_path(&migration_path);
                info!(%diag);
                continue;
            }
        };

        // Is it valid json?
        let assertions: ScimAssertGeneric = match serde_hjson::from_slice(&migration_content) {
            Ok(assertions) => assertions,
            Err(err) => {
                error!(?err, path = %migration_path.display(), "Invalid JSON SCIM Assertion");
                continue;
            }
        };

        // Hash the content.
        let mut hasher = Sha256::new();
        hasher.update(&migration_content);
        let migration_hash: Sha256Output = hasher.finalize();

        migrations.push(ScimMigration {
            path: migration_path,
            hash: migration_hash,
            assertions,
        });
    }

    let mut migration_ids = BTreeSet::new();
    for migration in &migrations {
        // BTreeSet returns false on duplicate value insertion.
        if !migration_ids.insert(migration.assertions.id) {
            error!(path = %migration.path.display(), uuid = ?migration.assertions.id, "Duplicate migration UUID found, refusing to proceed!!! All migrations must have a unique ID!!!");
            return;
        }
    }

    // Okay, we're setup to go - apply them all. Note that we do these
    // separately, each migration occurs in its own transaction.
    for ScimMigration {
        path,
        hash,
        assertions,
    } in migrations
    {
        if let Err(err) = server_write_ref
            .handle_scim_migration_apply(eventid, assertions, hash)
            .await
        {
            error!(?err, path = %path.display(), "Failed to apply migration");
        };
    }
}

#[derive(Clone, Debug)]
pub enum CoreAction {
    Shutdown,
    Reload,
}

pub(crate) enum TaskName {
    AdminSocket,
    AuditdActor,
    BackupActor,
    DelayedActionActor,
    HttpsServer,
    IntervalActor,
    LdapActor,
    Replication,
    TlsAcceptorReload,
    MigrationReload,
    WgHandshakePoller,
    WgPeerRevocation,
    LogoutDeliveryWorker,
}

impl Display for TaskName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                TaskName::AdminSocket => "Admin Socket",
                TaskName::AuditdActor => "Auditd Actor",
                TaskName::BackupActor => "Backup Actor",
                TaskName::DelayedActionActor => "Delayed Action Actor",
                TaskName::HttpsServer => "HTTPS Server",
                TaskName::IntervalActor => "Interval Actor",
                TaskName::LdapActor => "LDAP Acceptor Actor",
                TaskName::Replication => "Replication",
                TaskName::TlsAcceptorReload => "TlsAcceptor Reload Monitor",
                TaskName::MigrationReload => "Migration Reload Monitor",
                TaskName::WgHandshakePoller => "WireGuard Handshake Poller",
                TaskName::WgPeerRevocation => "WireGuard Peer Revocation",
                TaskName::LogoutDeliveryWorker => "Back-Channel Logout Delivery Worker",
            }
        )
    }
}

pub struct CoreHandle {
    clean_shutdown: bool,
    tx: broadcast::Sender<CoreAction>,
    /// This stores a name for the handle, and the handle itself so we can tell which failed/succeeded at the end.
    handles: Vec<(TaskName, task::JoinHandle<()>)>,
    connector_registry: Arc<ConnectorRegistry>,
    idm_server: Arc<IdmServer>,
}

impl CoreHandle {
    pub fn connector_registry(&self) -> Arc<ConnectorRegistry> {
        Arc::clone(&self.connector_registry)
    }

    pub fn idm_server(&self) -> Arc<IdmServer> {
        Arc::clone(&self.idm_server)
    }

    pub fn subscribe(&mut self) -> broadcast::Receiver<CoreAction> {
        self.tx.subscribe()
    }

    pub async fn shutdown(&mut self) {
        if self.tx.send(CoreAction::Shutdown).is_err() {
            eprintln!("No receivers acked shutdown request. Treating as unclean.");
            return;
        }

        // Wait on the handles.
        while let Some((handle_name, handle)) = self.handles.pop() {
            debug!("Waiting for {handle_name} ...");
            if let Err(error) = handle.await {
                eprintln!("Task {handle_name} failed to finish: {error:?}");
            }
        }

        self.clean_shutdown = true;
    }

    pub async fn reload(&mut self) {
        if self.tx.send(CoreAction::Reload).is_err() {
            eprintln!("No receivers acked reload request.");
        }
    }
}

impl Drop for CoreHandle {
    fn drop(&mut self) {
        if !self.clean_shutdown {
            eprintln!("⚠️  UNCLEAN SHUTDOWN OCCURRED ⚠️ ");
        }
        // Can't enable yet until we clean up unix_int cache layer test
        // debug_assert!(self.clean_shutdown);
    }
}

pub async fn create_server_core(
    config: Configuration,
    config_test: bool,
) -> Result<CoreHandle, ()> {
    // Until this point, we probably want to write to the log macro fns.
    let (broadcast_tx, mut broadcast_rx) = broadcast::channel(4);

    if config.integration_test_config.is_some() {
        warn!("RUNNING IN INTEGRATION TEST MODE.");
        warn!("IF YOU SEE THIS IN PRODUCTION YOU MUST CONTACT SUPPORT IMMEDIATELY.");
    } else if config.tls_config.is_none() {
        // TLS is great! We won't run without it.
        error!("Running without TLS is not supported! Quitting!");
        return Err(());
    }

    info!(
        "Starting netidm with {}configuration: {}",
        if config_test { "TEST " } else { "" },
        config
    );
    // Setup umask, so that every we touch or create is secure.
    #[cfg(not(target_family = "windows"))]
    unsafe {
        umask(0o0027)
    };

    // Similar, create a stats task which aggregates statistics from the
    // server as they come in.
    let status_ref = StatusActor::start();

    // Setup TLS (if any)
    let maybe_tls_acceptor = match crypto::setup_tls(&config.tls_config) {
        Ok(tls_acc) => tls_acc,
        Err(err) => {
            error!(?err, "Failed to configure TLS acceptor");
            return Err(());
        }
    };

    let schema = match Schema::new() {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to setup in memory schema: {:?}", e);
            return Err(());
        }
    };

    // Setup the be for the qs.
    let be = match setup_backend(&config, &schema) {
        Ok(be) => be,
        Err(e) => {
            error!("Failed to setup BE -> {:?}", e);
            return Err(());
        }
    };
    // Start the IDM server.
    let (_qs, idms, mut idms_delayed, mut idms_audit) =
        match setup_qs_idms(be, schema, &config).await {
            Ok(t) => t,
            Err(e) => {
                error!("Unable to setup query server or idm server -> {:?}", e);
                return Err(());
            }
        };

    // Extract any configuration from the IDMS that we may need.
    // For now we just do this per run, but we need to extract this from the db later.
    let jws_signer = match JwsHs256Signer::generate_hs256() {
        Ok(k) => k.set_sign_option_embed_kid(false),
        Err(e) => {
            error!("Unable to setup jws signer -> {:?}", e);
            return Err(());
        }
    };

    // Any pre-start tasks here.
    if let Some(itc) = &config.integration_test_config {
        let Ok(mut idms_prox_write) = idms.proxy_write(duration_from_epoch_now()).await else {
            error!("Unable to acquire write transaction");
            return Err(());
        };
        // We need to set the admin pw.
        match idms_prox_write.recover_account(&itc.admin_user, Some(&itc.admin_password)) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST {} account -> {:?}",
                    &itc.admin_user, e
                );
                return Err(());
            }
        };
        // set the idm_admin account password
        match idms_prox_write.recover_account(&itc.idm_admin_user, Some(&itc.idm_admin_password)) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST {} account -> {:?}",
                    &itc.idm_admin_user, e
                );
                return Err(());
            }
        };

        // Add admin to idm_admins to allow tests more flexibility wrt to permissions.
        // This way our default access controls can be stricter to prevent lateral
        // movement.
        match idms_prox_write.qs_write.internal_modify_uuid(
            UUID_IDM_ADMINS,
            &ModifyList::new_append(Attribute::Member, Value::Refer(UUID_ADMIN)),
        ) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST admin as member of idm_admins -> {:?}",
                    e
                );
                return Err(());
            }
        };

        match idms_prox_write.qs_write.internal_modify_uuid(
            UUID_IDM_ALL_PERSONS,
            &ModifyList::new_purge_and_set(
                Attribute::CredentialTypeMinimum,
                CredentialType::Any.into(),
            ),
        ) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    "Unable to configure INTEGRATION TEST default credential policy -> {:?}",
                    e
                );
                return Err(());
            }
        };

        match idms_prox_write.commit() {
            Ok(_) => {}
            Err(e) => {
                error!("Unable to commit INTEGRATION TEST setup -> {:?}", e);
                return Err(());
            }
        }
    }

    let ldap = match LdapServer::new(&idms).await {
        Ok(l) => l,
        Err(e) => {
            error!("Unable to start LdapServer -> {:?}", e);
            return Err(());
        }
    };

    // Arc the idms and ldap
    let connector_registry = idms.connector_registry();
    let idms_arc = Arc::new(idms);
    let ldap_arc = Arc::new(ldap);

    // Start the WireGuard manager and bring up configured tunnels.
    let wg_manager = {
        let backend_kind = netidmd_wg::backend::detect_backend();
        let backend: Arc<dyn netidmd_wg::backend::WgBackend> = match backend_kind {
            BackendKind::Kernel => Arc::new(KernelBackend),
            BackendKind::Boringtun => Arc::new(BoringtunBackend),
        };
        let manager = Arc::new(WgManager::new(backend, backend_kind));
        let mut idms_prox_read = match idms_arc.proxy_read().await {
            Ok(r) => r,
            Err(e) => {
                error!(
                    "Unable to acquire read transaction for WG startup -> {:?}",
                    e
                );
                return Err(());
            }
        };
        match idms_prox_read.wg_list_tunnels() {
            Ok(tunnels) => {
                let ct_now = duration_from_epoch_now();
                drop(idms_prox_read);
                for tunnel in tunnels {
                    let tunnel_name = tunnel.name.clone();
                    let tunnel_uuid = tunnel.uuid;

                    // Derive public key and persist if absent.
                    if tunnel.public_key.is_empty() {
                        match WgManager::derive_public_key(&tunnel.private_key) {
                            Ok(pubkey) => {
                                if let Ok(mut w) = idms_arc.proxy_write(ct_now).await {
                                    let ml = netidmd_lib::prelude::ModifyList::new_purge_and_set(
                                        netidmd_lib::prelude::Attribute::WgPublicKey,
                                        netidmd_lib::prelude::Value::new_utf8s(&pubkey),
                                    );
                                    if let Err(e) =
                                        w.qs_write.internal_modify_uuid(tunnel_uuid, &ml)
                                    {
                                        error!(
                                            "Failed to write public key for tunnel {} -> {:?}",
                                            tunnel_name, e
                                        );
                                    } else {
                                        let _ = w.commit();
                                    }
                                }
                            }
                            Err(e) => error!(
                                "Failed to derive public key for tunnel {} -> {:?}",
                                tunnel_name, e
                            ),
                        }
                    }

                    // Read peers fresh for this tunnel.
                    let peers = match idms_arc.proxy_read().await {
                        Ok(mut r) => match r.wg_list_peers_for_tunnel(tunnel_uuid) {
                            Ok(p) => p,
                            Err(e) => {
                                error!(
                                    "Failed to list peers for tunnel {} -> {:?}",
                                    tunnel_name, e
                                );
                                continue;
                            }
                        },
                        Err(e) => {
                            error!(
                                "Failed to acquire read txn for peers of tunnel {} -> {:?}",
                                tunnel_name, e
                            );
                            continue;
                        }
                    };

                    if let Err(e) = manager.bring_up(&tunnel, &peers).await {
                        error!(
                            "Failed to bring up WireGuard tunnel {} -> {:?}",
                            tunnel_name, e
                        );
                    }
                }
            }
            Err(e) => {
                error!("Failed to list WireGuard tunnels at startup -> {:?}", e);
                drop(idms_prox_read);
            }
        }
        manager
    };

    // Pass it to the actor for threading.
    // Start the read query server with the given be path: future config
    let server_read_ref = QueryServerReadV1::start_static(idms_arc.clone(), ldap_arc.clone());

    // Create the server async write entry point.
    let server_write_ref = QueryServerWriteV1::start_static(idms_arc.clone());

    // Background task: drive OIDC Back-Channel Logout deliveries. Polls
    // the persistent `LogoutDelivery` queue and POSTs each due record's
    // signed logout token to the relying-party endpoint with a bounded
    // timeout and bounded retry budget. Woken immediately via
    // `idms_arc.logout_delivery_notify()` when `terminate_session`
    // enqueues a new record (US3 of PR-RP-LOGOUT).
    let logout_worker_handle =
        logout_worker::spawn_worker(idms_arc.clone(), broadcast_tx.subscribe());

    // Background task: poll WireGuard handshake timestamps every 60 seconds and
    // write last_seen back to WgPeer entries.
    let wg_handshake_handle = {
        let mut broadcast_rx = broadcast_tx.subscribe();
        let wg_poll_manager = wg_manager.clone();
        let wg_poll_idms = idms_arc.clone();
        task::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let tunnels = {
                            let Ok(mut read_txn) = wg_poll_idms.proxy_read().await else { continue };
                            match read_txn.wg_list_tunnels() {
                                Ok(t) => t,
                                Err(e) => {
                                    error!("WG poller: failed to list tunnels: {:?}", e);
                                    continue;
                                }
                            }
                        };
                        for tunnel in &tunnels {
                            let handshakes = match wg_poll_manager.peer_handshakes(tunnel).await {
                                Ok(h) => h,
                                Err(e) => {
                                    error!("WG poller: handshake query for {} failed: {:?}", tunnel.name, e);
                                    continue;
                                }
                            };
                            let peer_map = {
                                let Ok(mut read_txn) = wg_poll_idms.proxy_read().await else { continue };
                                match read_txn.wg_list_peer_pubkeys_for_tunnel(tunnel.uuid) {
                                    Ok(pairs) => pairs,
                                    Err(e) => {
                                        error!("WG poller: peer list for {} failed: {:?}", tunnel.name, e);
                                        continue;
                                    }
                                }
                            };
                            for (pubkey, secs) in handshakes {
                                if secs == 0 {
                                    continue;
                                }
                                if let Some((peer_uuid, _)) = peer_map.iter().find(|(_, pk)| *pk == pubkey) {
                                    let ts = time::OffsetDateTime::from_unix_timestamp(secs as i64)
                                        .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
                                    let eventid = Uuid::new_v4();
                                    if let Err(e) = server_write_ref.handle_wg_update_last_seen(*peer_uuid, ts, eventid).await {
                                        error!("WG poller: failed to write last_seen for {}: {:?}", pubkey, e);
                                    }
                                }
                            }
                        }
                    }
                    Ok(action) = broadcast_rx.recv() => {
                        match action {
                            CoreAction::Shutdown => break,
                            CoreAction::Reload => {},
                        }
                    }
                }
            }
            info!("Stopped {}", TaskName::WgHandshakePoller);
        })
    };

    // Background task: compare live WireGuard peers against Netidm DB every 30 seconds
    // and remove any peers that have been deleted from Netidm.
    let wg_revoke_handle = {
        let mut broadcast_rx = broadcast_tx.subscribe();
        let wg_revoke_manager = wg_manager.clone();
        let wg_revoke_idms = idms_arc.clone();
        task::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(30));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        let tunnels = {
                            let Ok(mut read_txn) = wg_revoke_idms.proxy_read().await else { continue };
                            match read_txn.wg_list_tunnels() {
                                Ok(t) => t,
                                Err(e) => {
                                    error!("WG revoke: failed to list tunnels: {:?}", e);
                                    continue;
                                }
                            }
                        };
                        for tunnel in &tunnels {
                            let db_pubkeys: std::collections::BTreeSet<String> = {
                                let Ok(mut read_txn) = wg_revoke_idms.proxy_read().await else { continue };
                                match read_txn.wg_list_peer_pubkeys_for_tunnel(tunnel.uuid) {
                                    Ok(pairs) => pairs.into_iter().map(|(_, pk)| pk).collect(),
                                    Err(e) => {
                                        error!("WG revoke: peer list for {} failed: {:?}", tunnel.name, e);
                                        continue;
                                    }
                                }
                            };
                            let live_handshakes = match wg_revoke_manager.peer_handshakes(tunnel).await {
                                Ok(h) => h,
                                Err(e) => {
                                    error!("WG revoke: handshake query for {} failed: {:?}", tunnel.name, e);
                                    continue;
                                }
                            };
                            for (pubkey, _) in live_handshakes {
                                if !db_pubkeys.contains(&pubkey) {
                                    if let Err(e) = wg_revoke_manager.remove_peer(tunnel, &pubkey).await {
                                        error!("WG revoke: failed to remove {} from {}: {:?}", pubkey, tunnel.name, e);
                                    }
                                }
                            }
                        }
                    }
                    Ok(action) = broadcast_rx.recv() => {
                        match action {
                            CoreAction::Shutdown => break,
                            CoreAction::Reload => {},
                        }
                    }
                }
            }
            info!("Stopped {}", TaskName::WgPeerRevocation);
        })
    };

    let delayed_handle = task::spawn(async move {
        let mut buffer = Vec::with_capacity(DELAYED_ACTION_BATCH_SIZE);
        loop {
            tokio::select! {
                added = idms_delayed.recv_many(&mut buffer) => {
                    if added == 0 {
                        // Channel has closed, stop the task.
                        break
                    }
                    server_write_ref.handle_delayedaction(&mut buffer).await;
                }
                Ok(action) = broadcast_rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break,
                        CoreAction::Reload => {},
                    }
                }
            }
        }
        info!("Stopped {}", TaskName::DelayedActionActor);
    });

    let mut broadcast_rx = broadcast_tx.subscribe();

    let auditd_handle = task::spawn(async move {
        loop {
            tokio::select! {
                Ok(action) = broadcast_rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break,
                        CoreAction::Reload => {},
                    }
                }
                audit_event = idms_audit.audit_rx().recv() => {
                    match serde_json::to_string(&audit_event) {
                        Ok(audit_event) => {
                            warn!(%audit_event);
                        }
                        Err(e) => {
                            error!(err=?e, "Unable to process audit event to json.");
                            warn!(?audit_event, json=false);
                        }
                    }

                }
            }
        }
        info!("Stopped {}", TaskName::AuditdActor);
    });

    // Run the migrations *once*, only in production though.
    let migration_path = config
        .migration_path
        .clone()
        .unwrap_or(PathBuf::from(env!("NETIDM_SERVER_MIGRATION_PATH")));

    if config.integration_test_config.is_none() {
        let eventid = Uuid::new_v4();
        migration_apply(eventid, server_write_ref, migration_path.as_path()).await;
    }

    // Setup the Migration Reload Trigger.
    let mut broadcast_rx = broadcast_tx.subscribe();
    let migration_reload_handle = task::spawn(async move {
        loop {
            tokio::select! {
                Ok(action) = broadcast_rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break,
                        CoreAction::Reload => {
                            // Read the migrations.
                            // Apply them.
                            let eventid = Uuid::new_v4();
                            migration_apply(
                                eventid,
                                server_write_ref,
                                migration_path.as_path(),
                            ).await;

                            info!("Migration reload complete");
                        },
                    }
                }
            }
        }
        info!("Stopped {}", TaskName::MigrationReload);
    });

    // Setup a TLS Acceptor Reload trigger.

    let mut broadcast_rx = broadcast_tx.subscribe();
    let tls_config = config.tls_config.clone();

    let (tls_acceptor_reload_tx, _tls_acceptor_reload_rx) = broadcast::channel(1);
    let tls_acceptor_reload_tx_c = tls_acceptor_reload_tx.clone();

    let tls_acceptor_reload_handle = task::spawn(async move {
        loop {
            tokio::select! {
                Ok(action) = broadcast_rx.recv() => {
                    match action {
                        CoreAction::Shutdown => break,
                        CoreAction::Reload => {
                            let tls_acceptor = match crypto::setup_tls(&tls_config) {
                                Ok(Some(tls_acc)) => tls_acc,
                                Ok(None) => {
                                    warn!("TLS not configured, ignoring reload request.");
                                    continue;
                                }
                                Err(err) => {
                                    error!(?err, "Failed to configure and reload TLS acceptor");
                                    continue;
                                }
                            };

                            // We don't log here as the receivers will notify when they have completed
                            // the reload.
                            if tls_acceptor_reload_tx_c.send(tls_acceptor).is_err() {
                                error!("TLS acceptor did not accept the reload, the server may have failed!");
                            };
                            info!("TLS acceptor reload notification sent");
                        },
                    }
                }
            }
        }
        info!("Stopped {}", TaskName::TlsAcceptorReload);
    });

    // Setup timed events associated to the write thread
    let interval_handle = IntervalActor::start(server_write_ref, broadcast_tx.subscribe());
    // Setup timed events associated to the read thread
    let maybe_backup_handle = match &config.online_backup {
        Some(online_backup_config) => {
            if online_backup_config.enabled {
                let handle = IntervalActor::start_online_backup(
                    server_read_ref,
                    online_backup_config,
                    broadcast_tx.subscribe(),
                )?;
                Some(handle)
            } else {
                debug!("Backups disabled");
                None
            }
        }
        None => {
            debug!("Online backup not requested, skipping");
            None
        }
    };

    // If we have been requested to init LDAP, configure it now.
    let maybe_ldap_acceptor_handles = match &config.ldapbindaddress {
        Some(la) => {
            let opt_ldap_ssl_acceptor = maybe_tls_acceptor.clone();

            let h = ldaps::create_ldap_server(
                la,
                opt_ldap_ssl_acceptor,
                server_read_ref,
                &broadcast_tx,
                &tls_acceptor_reload_tx,
                config.ldap_client_address_info.trusted_tcp_info(),
            )
            .await?;
            Some(h)
        }
        None => {
            debug!("LDAP not requested, skipping");
            None
        }
    };

    // If we have replication configured, setup the listener with its initial replication
    // map (if any).
    let (maybe_repl_handle, maybe_repl_ctrl_tx) = match &config.repl_config {
        Some(rc) => {
            if !config_test {
                // ⚠️  only start the sockets and listeners in non-config-test modes.
                let (h, repl_ctrl_tx) =
                    repl::create_repl_server(idms_arc.clone(), rc, broadcast_tx.subscribe())
                        .await?;
                (Some(h), Some(repl_ctrl_tx))
            } else {
                (None, None)
            }
        }
        None => {
            debug!("Replication not requested, skipping");
            (None, None)
        }
    };

    let maybe_http_acceptor_handles = if config_test {
        admin_info!("This config rocks! 🪨 ");
        None
    } else {
        let handles: Vec<task::JoinHandle<()>> = https::create_https_server(
            config.clone(),
            jws_signer,
            status_ref,
            server_write_ref,
            server_read_ref,
            broadcast_tx.clone(),
            https::ServerServices {
                maybe_tls_acceptor,
                tls_acceptor_reload_tx: tls_acceptor_reload_tx.clone(),
                wg_manager: wg_manager.clone(),
            },
        )
        .await
        .inspect_err(|err| {
            error!(?err, "Failed to start HTTPS server");
        })?;

        if config.role != ServerRole::WriteReplicaNoUI {
            admin_info!("ready to rock! 🪨  UI available at: {}", config.origin);
        } else {
            admin_info!("ready to rock! 🪨 ");
        }
        Some(handles)
    };

    // If we are NOT in integration test mode, start the admin socket now
    let maybe_admin_sock_handle = if config.integration_test_config.is_none() {
        let broadcast_tx_ = broadcast_tx.clone();

        let admin_handle = AdminActor::create_admin_sock(
            config.adminbindpath.as_str(),
            server_write_ref,
            server_read_ref,
            broadcast_tx_,
            maybe_repl_ctrl_tx,
        )
        .await?;

        Some(admin_handle)
    } else {
        None
    };

    let mut handles: Vec<(TaskName, task::JoinHandle<()>)> = vec![
        (TaskName::IntervalActor, interval_handle),
        (TaskName::DelayedActionActor, delayed_handle),
        (TaskName::AuditdActor, auditd_handle),
        (TaskName::TlsAcceptorReload, tls_acceptor_reload_handle),
        (TaskName::MigrationReload, migration_reload_handle),
        (TaskName::WgHandshakePoller, wg_handshake_handle),
        (TaskName::WgPeerRevocation, wg_revoke_handle),
        (TaskName::LogoutDeliveryWorker, logout_worker_handle),
    ];

    if let Some(backup_handle) = maybe_backup_handle {
        handles.push((TaskName::BackupActor, backup_handle))
    }

    if let Some(admin_sock_handle) = maybe_admin_sock_handle {
        handles.push((TaskName::AdminSocket, admin_sock_handle))
    }

    if let Some(ldap_handles) = maybe_ldap_acceptor_handles {
        for ldap_handle in ldap_handles {
            handles.push((TaskName::LdapActor, ldap_handle))
        }
    }

    if let Some(http_handles) = maybe_http_acceptor_handles {
        for http_handle in http_handles {
            handles.push((TaskName::HttpsServer, http_handle))
        }
    }

    if let Some(repl_handle) = maybe_repl_handle {
        handles.push((TaskName::Replication, repl_handle))
    }

    Ok(CoreHandle {
        clean_shutdown: false,
        tx: broadcast_tx,
        handles,
        connector_registry,
        idm_server: Arc::clone(&idms_arc),
    })
}
