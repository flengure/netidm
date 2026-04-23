use crate::prelude::*;

use crate::migration_data;
use netidm_proto::internal::DomainUpgradeCheckReport as ProtoDomainUpgradeCheckReport;

use super::ServerPhase;

impl QueryServer {
    #[instrument(level = "info", name = "system_initialisation", skip_all)]
    pub async fn initialise_helper(
        &self,
        ts: Duration,
        domain_target_level: DomainVersion,
    ) -> Result<(), OperationError> {
        // We need to perform this in a single transaction pass to prevent tainting
        // databases during upgrades.
        let mut write_txn = self.write(ts).await?;

        // Check our database version - attempt to do an initial indexing
        // based on the in memory configuration. This ONLY triggers ONCE on
        // the very first run of the instance when the DB in newely created.
        write_txn.upgrade_reindex(SYSTEM_INDEX_VERSION)?;

        // Because we init the schema here, and commit, this reloads meaning
        // that the on-disk index meta has been loaded, so our subsequent
        // migrations will be correctly indexed.
        //
        // Remember, that this would normally mean that it's possible for schema
        // to be mis-indexed (IE we index the new schemas here before we read
        // the schema to tell us what's indexed), but because we have the in
        // mem schema that defines how schema is structured, and this is all
        // marked "system", then we won't have an issue here.
        write_txn
            .initialise_schema_core()
            .and_then(|_| write_txn.reload())?;

        // This is what tells us if the domain entry existed before or not. This
        // is now the primary method of migrations and version detection.
        let db_domain_version = match write_txn.internal_search_uuid(UUID_DOMAIN_INFO) {
            Ok(e) => Ok(e.get_ava_single_uint32(Attribute::Version).unwrap_or(0)),
            Err(OperationError::NoMatchingEntries) => Ok(0),
            Err(r) => Err(r),
        }?;

        debug!(?db_domain_version, "Before setting internal domain info");

        if db_domain_version == 0 {
            // This is here to catch when we increase domain levels but didn't create the migration
            // hooks. If this fails it probably means you need to add another migration hook
            // in the above.
            debug_assert!(domain_target_level <= DOMAIN_MAX_LEVEL);

            const { assert!(DOMAIN_MIN_CREATION_LEVEL == DOMAIN_LEVEL_30) };
            write_txn.bootstrap_dl30()?;

            write_txn
                .internal_apply_domain_migration(domain_target_level)
                .map(|()| {
                    warn!(
                        "Domain level has been bootstrapped to {}",
                        domain_target_level
                    );
                })?;
        }

        // These steps apply both to bootstrapping and normal startup, since we now have
        // a DB with data populated in either path.

        // Domain info is now present, so we need to reflect that in our server
        // domain structures. If we don't do this, the in memory domain level
        // is stuck at 0 which can confuse init domain info below.
        //
        // This also is where the former domain taint flag will be loaded to
        // d_info so that if the *previous* execution of the database was
        // a devel version, we'll still trigger the forced remigration in
        // in the case that we are moving from dev -> stable.
        write_txn.force_domain_reload();

        write_txn.reload()?;

        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        write_txn.set_phase(ServerPhase::SchemaReady);

        // #2756 - if we *aren't* creating the base IDM entries, then we
        // need to force dyn groups to reload since we're now at schema
        // ready. This is done indirectly by ... reloading the schema again.
        //
        // This is because dyngroups don't load until server phase >= schemaready
        // and the reload path for these is either a change in the dyngroup entry
        // itself or a change to schema reloading. Since we aren't changing the
        // dyngroup here, we have to go via the schema reload path.
        write_txn.force_schema_reload();

        // Reload as init idm affects access controls.
        write_txn.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        write_txn.set_phase(ServerPhase::DomainInfoReady);

        // This is the start of domain info related migrations which we will need in future
        // to handle replication. Due to the access control rework, and the addition of "managed by"
        // syntax, we need to ensure both nodes "fence" replication from each other. We do this
        // by changing domain infos to be incompatible during this phase.

        // The reloads will have populated this structure now.
        let domain_info_version = write_txn.get_domain_version();
        let domain_patch_level = write_txn.get_domain_patch_level();
        let domain_development_taint = write_txn.get_domain_development_taint();
        debug!(
            ?db_domain_version,
            ?domain_patch_level,
            ?domain_development_taint,
            "After setting internal domain info"
        );

        let mut reload_required = false;

        // If the database domain info is a lower version than our target level, we reload.
        if domain_info_version < domain_target_level {
            // if (domain_target_level - domain_info_version) > DOMAIN_MIGRATION_SKIPS {
            if domain_info_version < DOMAIN_MIGRATION_FROM_MIN {
                error!(
                    "UNABLE TO PROCEED. You are attempting a skip update which is NOT SUPPORTED."
                );
                error!(
                    "For more see: https://netidm.github.io/netidm/stable/support.html#upgrade-policy and https://netidm.github.io/netidm/stable/server_updates.html"
                );
                error!(domain_previous_version = ?domain_info_version, domain_target_version = ?domain_target_level, domain_migration_minimum_limit = ?DOMAIN_MIGRATION_FROM_MIN);
                return Err(OperationError::MG0008SkipUpgradeAttempted);
            }

            // Apply each step in order.
            for domain_target_level_step in domain_info_version..domain_target_level {
                // Rust has no way to do a range with the minimum excluded and the maximum
                // included, so we have to do min -> max which includes min and excludes max,
                // and by adding 1 we gett the same result.
                let domain_target_level_step = domain_target_level_step + 1;
                write_txn
                    .internal_apply_domain_migration(domain_target_level_step)
                    .map(|()| {
                        warn!(
                            "Domain level has been raised to {}",
                            domain_target_level_step
                        );
                    })?;
            }

            // Reload if anything in migrations requires it - this triggers the domain migrations
            // which in turn can trigger schema reloads etc. If the server was just brought up
            // then we don't need the extra reload since we are already at the correct
            // version of the server, and this call to set the target level is just for persistence
            // of the value.
            if domain_info_version != 0 {
                reload_required = true;
            }
        } else if domain_info_version > domain_target_level {
            // This is a DOWNGRADE which may not proceed.
            error!("UNABLE TO PROCEED. You are attempting a downgrade which is NOT SUPPORTED.");
            error!(
                "For more see: https://netidm.github.io/netidm/stable/support.html#upgrade-policy and https://netidm.github.io/netidm/stable/server_updates.html"
            );
            error!(domain_previous_version = ?domain_info_version, domain_target_version = ?domain_target_level);
            return Err(OperationError::MG0010DowngradeNotAllowed);
        } else if domain_development_taint {
            // This forces pre-release versions to re-migrate each start up. This solves
            // the domain-version-sprawl issue so that during a development cycle we can
            // do a single domain version bump, and continue to extend the migrations
            // within that release cycle to contain what we require.
            //
            // If this is a pre-release build
            // AND
            // we are NOT in a test environment
            // AND
            // We did not already need a version migration as above
            write_txn.domain_remigrate(DOMAIN_PREVIOUS_TGT_LEVEL)?;

            reload_required = true;
        }

        // If we are new enough to support patches, and we are lower than the target patch level
        // then a reload will be applied after we raise the patch level.
        if domain_patch_level < DOMAIN_TGT_PATCH_LEVEL {
            write_txn
                .internal_modify_uuid(
                    UUID_DOMAIN_INFO,
                    &ModifyList::new_purge_and_set(
                        Attribute::PatchLevel,
                        Value::new_uint32(DOMAIN_TGT_PATCH_LEVEL),
                    ),
                )
                .map(|()| {
                    warn!(
                        "Domain patch level has been raised to {}",
                        domain_patch_level
                    );
                })?;

            reload_required = true;
        };

        // Execute whatever operations we have batched up and ready to go. This is needed
        // to preserve ordering of the operations - if we reloaded after a remigrate then
        // we would have skipped the patch level fix which needs to have occurred *first*.
        if reload_required {
            write_txn.reload()?;
        }

        // Now set the db/domain devel taint flag to match our current release status
        // if it changes. This is what breaks the cycle of db taint from dev -> stable
        let current_devel_flag = option_env!("NETIDM_PRE_RELEASE").is_some();
        if current_devel_flag {
            warn!("Domain Development Taint mode is enabled");
        }
        if domain_development_taint != current_devel_flag {
            write_txn.internal_modify_uuid(
                UUID_DOMAIN_INFO,
                &ModifyList::new_purge_and_set(
                    Attribute::DomainDevelopmentTaint,
                    Value::Bool(current_devel_flag),
                ),
            )?;
        }

        // We are ready to run
        write_txn.set_phase(ServerPhase::Running);

        // Commit all changes, this also triggers the final reload, this should be a no-op
        // since we already did all the needed loads above.
        write_txn.commit()?;

        debug!("Database version check and migrations success! ☀️  ");
        Ok(())
    }
}

impl QueryServerWriteTransaction<'_> {
    /// Apply a domain migration `to_level`. Errors if `to_level` is not greater than or equal to
    /// the active level.
    #[instrument(level = "debug", skip(self))]
    pub(crate) fn internal_apply_domain_migration(
        &mut self,
        to_level: u32,
    ) -> Result<(), OperationError> {
        self.internal_modify_uuid(
            UUID_DOMAIN_INFO,
            &ModifyList::new_purge_and_set(Attribute::Version, Value::new_uint32(to_level)),
        )
        .and_then(|()| self.reload())
    }

    fn internal_migrate_or_create_batch(
        &mut self,
        msg: &str,
        entries: Vec<EntryInitNew>,
    ) -> Result<(), OperationError> {
        #[cfg(test)]
        eprintln!("MIGRATION BATCH: {}", msg);
        let r: Result<(), _> = entries
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry));

        if let Err(err) = r {
            error!(?err, msg);
            debug_assert!(false);
        }

        Ok(())
    }

    #[instrument(level = "debug", skip_all)]
    /// - If the thing exists:
    ///   - Ensure the set of attributes match and are present
    ///     (but don't delete multivalue, or extended attributes in the situation.
    /// - If not:
    ///   - Create the entry
    ///
    /// This will extra classes an attributes alone!
    ///
    /// NOTE: `gen_modlist*` IS schema aware and will handle multivalue correctly!
    fn internal_migrate_or_create(
        &mut self,
        e: Entry<EntryInit, EntryNew>,
    ) -> Result<(), OperationError> {
        // NOTE: Ignoring an attribute only affects the migration phase, not create.
        self.internal_migrate_or_create_ignore_attrs(
            e,
            &[
                // If the credential type is present, we don't want to touch it.
                Attribute::CredentialTypeMinimum,
            ],
        )
    }

    #[instrument(level = "debug", skip_all)]
    fn internal_delete_batch(
        &mut self,
        msg: &str,
        entries: Vec<Uuid>,
    ) -> Result<(), OperationError> {
        let filter = entries
            .into_iter()
            .map(|uuid| f_eq(Attribute::Uuid, PartialValue::Uuid(uuid)))
            .collect();

        let filter = filter_all!(f_or(filter));

        let result = self.internal_delete(&filter);

        match result {
            Ok(_) | Err(OperationError::NoMatchingEntries) => Ok(()),
            Err(err) => {
                error!(?err, msg);
                Err(err)
            }
        }
    }

    /// This is the same as [QueryServerWriteTransaction::internal_migrate_or_create]
    /// but it will ignore the specified list of attributes, so that if an admin has
    /// modified those values then we don't stomp them.
    #[instrument(level = "trace", skip_all)]
    fn internal_migrate_or_create_ignore_attrs(
        &mut self,
        mut e: Entry<EntryInit, EntryNew>,
        attrs: &[Attribute],
    ) -> Result<(), OperationError> {
        trace!("operating on {:?}", e.get_uuid());

        let Some(filt) = e.filter_from_attrs(&[Attribute::Uuid]) else {
            return Err(OperationError::FilterGeneration);
        };

        trace!("search {:?}", filt);

        let results = self.internal_search(filt.clone())?;

        if results.is_empty() {
            // The entry does not exist. Create it.

            // If there are create-once members, set them up now.
            if let Some(members_create_once) = e.pop_ava(Attribute::MemberCreateOnce) {
                if let Some(members) = e.get_ava_mut(Attribute::Member) {
                    // Merge
                    members.merge(&members_create_once).inspect_err(|err| {
                        error!(?err, "Unable to merge member sets, mismatched types?");
                    })?;
                } else {
                    // Just push
                    e.set_ava_set(&Attribute::Member, members_create_once);
                }
            };

            self.internal_create(vec![e])
        } else if results.len() == 1 {
            // This is always ignored during migration.
            e.remove_ava(&Attribute::MemberCreateOnce);

            // For each ignored attr, we remove it from entry.
            for attr in attrs.iter() {
                e.remove_ava(attr);
            }

            // If the thing is subset, pass
            match e.gen_modlist_assert(&self.schema) {
                Ok(modlist) => {
                    // Apply to &results[0]
                    trace!(?modlist);
                    self.internal_modify(&filt, &modlist)
                }
                Err(e) => Err(OperationError::SchemaViolation(e)),
            }
        } else {
            admin_error!(
                "Invalid Result Set - Expected One Entry for {:?} - {:?}",
                filt,
                results
            );
            Err(OperationError::InvalidDbState)
        }
    }

    // Commented as an example of patch application
    /*
    /// Patch Application - This triggers a one-shot fixup task for issue #3178
    /// to force access controls to re-migrate in existing databases so that they're
    /// content matches expected values.
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_patch_level_2(&mut self) -> Result<(), OperationError> {
        admin_warn!("applying domain patch 2.");

        debug_assert!(*self.phase >= ServerPhase::SchemaReady);

        let idm_data = migration_data::dl9::phase_7_builtin_access_control_profiles();

        idm_data
            .into_iter()
            .try_for_each(|entry| self.internal_migrate_or_create(entry))
            .map_err(|err| {
                error!(?err, "migrate_domain_patch_level_2 -> Error");
                err
            })?;

        self.reload()?;

        Ok(())
    }
    */

    /// DL28 — PR-CONNECTOR-GITHUB.
    ///
    /// Adds one discriminator attribute (`OAuth2ClientProviderKind`) + seven
    /// GitHub-specific config attributes on `EntryClass::OAuth2Client`, plus
    /// a DL28 refresh of `idm_acp_oauth2_client_admin` covering the new
    /// attrs. No new entry class.
    ///
    /// Runs the full DL28 phase batches (schema attrs, ACP refresh) with
    /// `internal_migrate_or_create_batch` semantics — idempotent on
    /// incremental DL27→DL28 upgrades, and produces a complete base IDM on
    /// bootstrap (DL0→DL28) by delegating phases 2–8 through the DL28→DL26
    /// chain.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError::MG0004DomainLevelInDevelopment`] if this
    /// level is not yet enabled in the current build, or any error from
    /// the underlying phase batches.
    pub(crate) fn bootstrap_dl28(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_28 {
            error!("Unable to raise domain level from 27 to 28.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // Run the full DL28 phase chain. `dl28::phase_N` inherits
        // `dl26::phase_N` for the phases DL28 doesn't extend, so
        // bootstrap (DL0 → DL28) produces a complete base IDM;
        // incremental upgrade from DL27 is idempotent.

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl28::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl28::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl28::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl28 system entries",
            migration_data::dl28::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl28::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl28::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl28::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl28::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        // Delegate to DL26's backfill (SAML session indices). DL28
        // adds no further backfill of its own.
        self.backfill_saml_session_indices()?;

        Ok(())
    }

    /// DL29 bootstrap — schema-only migration for the generic-OIDC connector
    /// (PR-CONNECTOR-GENERIC-OIDC). Adds ten OIDC-specific config attributes on
    /// `EntryClass::OAuth2Client` and extends the ACP to cover them. All new
    /// attributes are optional so pre-DL29 entries decode unchanged.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError::MG0004DomainLevelInDevelopment`] if this level
    /// is not yet enabled, or any error from the underlying phase batches.
    pub(crate) fn bootstrap_dl29(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_29 {
            error!("Unable to raise domain level from 28 to 29.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl29::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl29::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl29::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl29 system entries",
            migration_data::dl29::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl29::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl29::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl29::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl29::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        self.backfill_saml_session_indices()?;

        Ok(())
    }

    /// DL30 — PR-CONNECTOR-GOOGLE.
    ///
    /// Adds four Google-specific config attributes on `EntryClass::OAuth2Client`
    /// (hosted_domain, service_account_json, admin_email, fetch_groups) plus a DL30
    /// refresh of `idm_acp_oauth2_client_admin`. No new entry class.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError::MG0004DomainLevelInDevelopment`] if this level
    /// is not yet enabled, or any error from the underlying phase batches.
    pub(crate) fn bootstrap_dl30(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_30 {
            error!("Unable to raise domain level from 29 to 30.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl30::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl30::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl30::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl30 system entries",
            migration_data::dl30::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl30::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl30::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl30::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl30::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    /// DL26 backfill step for the SAML `<SessionIndex>` migration.
    ///
    /// Pre-DL26 SAML assertions did not carry `<SessionIndex>`, so any
    /// currently-active SAML session cannot be uniquely addressed by an
    /// inbound `<LogoutRequest>` carrying a SessionIndex. The spec's Q5/C
    /// decision calls for backfilling a synthetic SessionIndex onto every
    /// such active session at migration time.
    ///
    /// In DL26 Foundational this helper is a safe no-op: it logs a note that
    /// pre-existing SAML sessions will fall through to the "no SessionIndex"
    /// branch of SLO correlation (ending every session of that user at that
    /// SP) until those sessions naturally expire and are re-issued with
    /// SessionIndex by the US4 auth-response path. The real Stage-1 /
    /// Stage-2 backfill described in `specs/009-rp-logout/research.md` R6
    /// lands with US4 (SAML SLO) once SessionIndex emission is wired into
    /// the SAML IdP response builder.
    ///
    /// # Errors
    ///
    /// Returns any [`OperationError`] if the underlying log-and-return path
    /// grows DB touches in a later revision.
    pub(crate) fn backfill_saml_session_indices(&mut self) -> Result<(), OperationError> {
        info!(
            "DL26 SAML SessionIndex backfill: no-op in Foundational phase. \
             Pre-existing SAML sessions will be SLO-addressable via the \
             no-SessionIndex branch until they naturally expire and are \
             re-issued with a SessionIndex by the DL26 SAML IdP auth path \
             (landing with US4 of PR-RP-LOGOUT)."
        );
        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    pub(crate) fn initialise_schema_core(&mut self) -> Result<(), OperationError> {
        admin_debug!("initialise_schema_core -> start ...");
        // Load in all the "core" schema, that we already have in "memory".
        let entries = self.schema.to_entries();

        // admin_debug!("Dumping schemas: {:?}", entries);

        // internal_migrate_or_create.
        let r: Result<_, _> = entries.into_iter().try_for_each(|e| {
            trace!(?e, "init schema entry");
            self.internal_migrate_or_create(e)
        });
        if r.is_ok() {
            admin_debug!("initialise_schema_core -> Ok!");
        } else {
            admin_error!(?r, "initialise_schema_core -> Error");
        }
        // why do we have error handling if it's always supposed to be `Ok`?
        debug_assert!(r.is_ok());
        r
    }
}

impl QueryServerReadTransaction<'_> {
    /// Retrieve the domain info of this server
    pub fn domain_upgrade_check(
        &mut self,
    ) -> Result<ProtoDomainUpgradeCheckReport, OperationError> {
        let d_info = &self.d_info;

        let name = d_info.d_name.clone();
        let uuid = d_info.d_uuid;
        let current_level = d_info.d_vers;
        let upgrade_level = DOMAIN_TGT_NEXT_LEVEL;

        // DL7→DL8 upgrade checks are obsolete (DL28 is minimum baseline)
        let report_items = Vec::new();

        Ok(ProtoDomainUpgradeCheckReport {
            name,
            uuid,
            current_level,
            upgrade_level,
            report_items,
        })
    }
}

#[cfg(test)]
mod tests {
    // use super::{ProtoDomainUpgradeCheckItem, ProtoDomainUpgradeCheckStatus};
    use crate::prelude::*;
    use crate::value::CredentialType;
    use crate::valueset::ValueSetCredentialType;

    #[qs_test]
    async fn test_init_idempotent_schema_core(server: &QueryServer) {
        {
            // Setup and abort.
            let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
            assert!(server_txn.initialise_schema_core().is_ok());
        }
        {
            let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.commit().is_ok());
        }
        {
            // Now do it again in a new txn, but abort
            let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
            assert!(server_txn.initialise_schema_core().is_ok());
        }
        {
            // Now do it again in a new txn.
            let mut server_txn = server.write(duration_from_epoch_now()).await.unwrap();
            assert!(server_txn.initialise_schema_core().is_ok());
            assert!(server_txn.commit().is_ok());
        }
    }

    /// This test is for ongoing/longterm checks over the previous to current version.
    /// This is in contrast to the specific version checks below that are often to
    /// test a version to version migration.
    #[qs_test(domain_level=DOMAIN_PREVIOUS_TGT_LEVEL)]
    async fn test_migrations_dl_previous_to_dl_target(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_PREVIOUS_TGT_LEVEL);

        // == SETUP ==

        // Add a member to a group - it should not be removed.
        // Remove a default member from a group - it should be returned.
        let modlist = ModifyList::new_set(
            Attribute::Member,
            // This achieves both because this removes IDM_ADMIN from the group
            // while setting only anon as a member.
            ValueSetRefer::new(UUID_ANONYMOUS),
        );
        write_txn
            .internal_modify_uuid(UUID_IDM_ADMINS, &modlist)
            .expect("Unable to modify CredentialTypeMinimum");

        // Remove a group from an object that is "create once".  It should not
        // be re-added.
        let modlist = ModifyList::new_purge(Attribute::Member);
        write_txn
            .internal_modify_uuid(UUID_IDM_PEOPLE_SELF_NAME_WRITE, &modlist)
            .expect("Unable to remove idm_all_persons from self-write");

        // Change default account policy - it should not be reverted.
        let modlist = ModifyList::new_set(
            Attribute::CredentialTypeMinimum,
            ValueSetCredentialType::new(CredentialType::Any),
        );
        write_txn
            .internal_modify_uuid(UUID_IDM_ALL_PERSONS, &modlist)
            .expect("Unable to modify CredentialTypeMinimum");

        write_txn.commit().expect("Unable to commit");

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_TGT_LEVEL)
            .expect("Unable to set domain level");

        // post migration verification.
        // Check that our group is as we left it
        let idm_admins_entry = write_txn
            .internal_search_uuid(UUID_IDM_ADMINS)
            .expect("Unable to retrieve all persons");

        let members = idm_admins_entry
            .get_ava_refer(Attribute::Member)
            .expect("No members present");

        // Still present
        assert!(members.contains(&UUID_ANONYMOUS));
        // Was reverted
        assert!(members.contains(&UUID_IDM_ADMIN));

        // Check that self-write still doesn't have all persons.
        let idm_people_self_name_write_entry = write_txn
            .internal_search_uuid(UUID_IDM_PEOPLE_SELF_NAME_WRITE)
            .expect("Unable to retrieve all persons");

        let members = idm_people_self_name_write_entry.get_ava_refer(Attribute::Member);

        // There are no members!
        assert!(members.is_none());

        // Check that the account policy did not revert.
        let all_persons_entry = write_txn
            .internal_search_uuid(UUID_IDM_ALL_PERSONS)
            .expect("Unable to retrieve all persons");

        assert_eq!(
            all_persons_entry.get_ava_single_credential_type(Attribute::CredentialTypeMinimum),
            Some(CredentialType::Any)
        );

        write_txn.commit().expect("Unable to commit");
    }

    #[qs_test(domain_level=DOMAIN_TGT_LEVEL)]
    async fn test_migrations_prevent_downgrades(server: &QueryServer) {
        let curtime = duration_from_epoch_now();

        let mut write_txn = server.write(curtime).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_TGT_LEVEL);

        drop(write_txn);

        // MUST NOT SUCCEED.
        let err = server
            .initialise_helper(curtime, DOMAIN_PREVIOUS_TGT_LEVEL)
            .await
            .expect_err("Domain level was lowered!!!!");

        assert_eq!(err, OperationError::MG0010DowngradeNotAllowed);
    }

    /// DL28 idempotent re-migration: asserts that the eight new schema attributes introduced
    /// for the GitHub upstream connector (one discriminator + seven
    /// GitHub-specific config attrs) are reachable through the schema after
    /// migration, and that an `OAuth2Client` entry can round-trip each new
    /// attribute through a write → commit → read cycle (which exercises both
    /// the schema-class extension and the DL28 ACP refresh).
    #[qs_test(domain_level=DOMAIN_PREVIOUS_TGT_LEVEL)]
    async fn test_migrations_dl28_idempotent(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_PREVIOUS_TGT_LEVEL);

        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_28)
            .expect("Unable to set domain level to version 28");

        // The eight new DL28 schema attributes must resolve by UUID after
        // migration — that is, the schema phase has loaded them.
        for (uuid, label) in [
            (
                UUID_SCHEMA_ATTR_OAUTH2_CLIENT_PROVIDER_KIND,
                "OAUTH2_CLIENT_PROVIDER_KIND",
            ),
            (
                UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_HOST,
                "OAUTH2_CLIENT_GITHUB_HOST",
            ),
            (
                UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_ORG_FILTER,
                "OAUTH2_CLIENT_GITHUB_ORG_FILTER",
            ),
            (
                UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_ALLOWED_TEAMS,
                "OAUTH2_CLIENT_GITHUB_ALLOWED_TEAMS",
            ),
            (
                UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_TEAM_NAME_FIELD,
                "OAUTH2_CLIENT_GITHUB_TEAM_NAME_FIELD",
            ),
            (
                UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_LOAD_ALL_GROUPS,
                "OAUTH2_CLIENT_GITHUB_LOAD_ALL_GROUPS",
            ),
            (
                UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_PREFERRED_EMAIL_DOMAIN,
                "OAUTH2_CLIENT_GITHUB_PREFERRED_EMAIL_DOMAIN",
            ),
            (
                UUID_SCHEMA_ATTR_OAUTH2_CLIENT_GITHUB_ALLOW_JIT_PROVISIONING,
                "OAUTH2_CLIENT_GITHUB_ALLOW_JIT_PROVISIONING",
            ),
        ] {
            write_txn.internal_search_uuid(uuid).unwrap_or_else(|_| {
                panic!("UUID_SCHEMA_ATTR_{label} missing after DL28 migration")
            });
        }

        // Round-trip: create an OAuth2Client entry carrying all eight
        // DL28 attrs. Bound by schema, so success proves both that the
        // `OAuth2Client` class was extended to include them in `systemmay`
        // and that their declared syntaxes match the values we pass.
        let client_uuid = Uuid::new_v4();
        write_txn
            .internal_create(vec![entry_init!(
                (Attribute::Class, EntryClass::Object.to_value()),
                (Attribute::Class, EntryClass::OAuth2Client.to_value()),
                (Attribute::Name, Value::new_iname("test_github_connector")),
                (Attribute::Uuid, Value::Uuid(client_uuid)),
                (Attribute::DisplayName, Value::new_utf8s("Test GitHub")),
                (
                    Attribute::OAuth2ClientId,
                    Value::new_utf8s("github-client-id")
                ),
                (
                    Attribute::OAuth2ClientSecret,
                    Value::new_utf8s("github-client-secret")
                ),
                (
                    Attribute::OAuth2AuthorisationEndpoint,
                    Value::new_url_s("https://github.com/login/oauth/authorize")
                        .expect("valid url")
                ),
                (
                    Attribute::OAuth2TokenEndpoint,
                    Value::new_url_s("https://github.com/login/oauth/access_token")
                        .expect("valid url")
                ),
                (
                    Attribute::OAuth2RequestScopes,
                    Value::new_oauthscope("read_user").expect("valid oauth scope")
                ),
                (
                    Attribute::OAuth2ClientProviderKind,
                    Value::new_iutf8("github")
                ),
                (
                    Attribute::OAuth2ClientGithubHost,
                    Value::new_url_s("https://github.acme.internal").expect("valid url")
                ),
                (
                    Attribute::OAuth2ClientGithubOrgFilter,
                    Value::new_utf8s("acme")
                ),
                (
                    Attribute::OAuth2ClientGithubOrgFilter,
                    Value::new_utf8s("widgetco")
                ),
                (
                    Attribute::OAuth2ClientGithubAllowedTeams,
                    Value::new_utf8s("acme:employees")
                ),
                (
                    Attribute::OAuth2ClientGithubTeamNameField,
                    Value::new_iutf8("slug")
                ),
                (
                    Attribute::OAuth2ClientGithubLoadAllGroups,
                    Value::Bool(true)
                ),
                (
                    Attribute::OAuth2ClientGithubPreferredEmailDomain,
                    Value::new_iutf8("acme.com")
                ),
                (
                    Attribute::OAuth2ClientGithubAllowJitProvisioning,
                    Value::Bool(false)
                )
            )])
            .expect("Unable to create DL28 OAuth2Client test entry");

        // Read-back each attribute to confirm round-trip.
        let read_back = write_txn
            .internal_search_uuid(client_uuid)
            .expect("Unable to retrieve DL28 OAuth2Client test entry");

        assert_eq!(
            read_back.get_ava_single_iutf8(Attribute::OAuth2ClientProviderKind),
            Some("github")
        );
        assert_eq!(
            read_back
                .get_ava_single_url(Attribute::OAuth2ClientGithubHost)
                .map(|u| u.as_str()),
            Some("https://github.acme.internal/")
        );
        let org_filter: std::collections::BTreeSet<&str> = read_back
            .get_ava_set(Attribute::OAuth2ClientGithubOrgFilter)
            .and_then(|vs| vs.as_utf8_iter())
            .expect("org filter present")
            .collect();
        assert!(org_filter.contains("acme"));
        assert!(org_filter.contains("widgetco"));
        let allowed_teams: std::collections::BTreeSet<&str> = read_back
            .get_ava_set(Attribute::OAuth2ClientGithubAllowedTeams)
            .and_then(|vs| vs.as_utf8_iter())
            .expect("allowed teams present")
            .collect();
        assert!(allowed_teams.contains("acme:employees"));
        assert_eq!(
            read_back.get_ava_single_iutf8(Attribute::OAuth2ClientGithubTeamNameField),
            Some("slug")
        );
        assert_eq!(
            read_back.get_ava_single_bool(Attribute::OAuth2ClientGithubLoadAllGroups),
            Some(true)
        );
        assert_eq!(
            read_back.get_ava_single_iutf8(Attribute::OAuth2ClientGithubPreferredEmailDomain),
            Some("acme.com")
        );
        assert_eq!(
            read_back.get_ava_single_bool(Attribute::OAuth2ClientGithubAllowJitProvisioning),
            Some(false)
        );

        write_txn.commit().expect("Unable to commit");
    }
}
