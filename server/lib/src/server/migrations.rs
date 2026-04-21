use crate::prelude::*;

use crate::migration_data;
use netidm_proto::internal::{
    DomainUpgradeCheckItem as ProtoDomainUpgradeCheckItem,
    DomainUpgradeCheckReport as ProtoDomainUpgradeCheckReport,
    DomainUpgradeCheckStatus as ProtoDomainUpgradeCheckStatus,
};

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

            // Assert that we have a minimum creation level that is valid.
            const { assert!(DOMAIN_MIN_CREATION_LEVEL == DOMAIN_LEVEL_10) };

            // No domain info was present, so neither was the rest of the IDM. Bring up the
            // full IDM here.

            match domain_target_level {
                DOMAIN_LEVEL_10 => write_txn.migrate_domain_9_to_10()?,
                DOMAIN_LEVEL_11 => write_txn.migrate_domain_10_to_11()?,
                DOMAIN_LEVEL_12 => write_txn.migrate_domain_11_to_12()?,
                DOMAIN_LEVEL_13 => write_txn.migrate_domain_12_to_13()?,
                DOMAIN_LEVEL_14 => write_txn.migrate_domain_13_to_14()?,
                DOMAIN_LEVEL_15 => write_txn.migrate_domain_14_to_15()?,
                DOMAIN_LEVEL_16 => write_txn.migrate_domain_15_to_16()?,
                DOMAIN_LEVEL_17 => write_txn.migrate_domain_16_to_17()?,
                DOMAIN_LEVEL_18 => write_txn.migrate_domain_17_to_18()?,
                DOMAIN_LEVEL_19 => write_txn.migrate_domain_18_to_19()?,
                DOMAIN_LEVEL_20 => write_txn.migrate_domain_19_to_20()?,
                DOMAIN_LEVEL_21 => write_txn.migrate_domain_20_to_21()?,
                DOMAIN_LEVEL_22 => write_txn.migrate_domain_21_to_22()?,
                DOMAIN_LEVEL_23 => write_txn.migrate_domain_22_to_23()?,
                DOMAIN_LEVEL_24 => write_txn.migrate_domain_23_to_24()?,
                DOMAIN_LEVEL_25 => write_txn.migrate_domain_24_to_25()?,
                DOMAIN_LEVEL_26 => write_txn.migrate_domain_25_to_26()?,
                _ => {
                    error!("Invalid requested domain target level for server bootstrap");
                    debug_assert!(false);
                    return Err(OperationError::MG0009InvalidTargetLevelForBootstrap);
                }
            }

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

    /// Migration domain level 9 to 10 (1.6.0)
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_9_to_10(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_9 {
            error!("Unable to raise domain level from 9 to 10.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // =========== Apply changes ==============
        self.internal_migrate_or_create_batch(
            "phase 1 - schema attrs",
            migration_data::dl10::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl10::phase_2_schema_classes(),
        )?;

        // Reload for the new schema.
        self.reload()?;

        // Since we just loaded in a ton of schema, lets reindex it in case we added
        // new indexes, or this is a bootstrap and we have no indexes yet.
        self.reindex(false)?;

        // Set Phase
        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl10::phase_3_key_provider(),
        )?;

        // Reload for the new key providers
        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - system entries",
            migration_data::dl10::phase_4_system_entries(),
        )?;

        // Reload for the new system entries
        self.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        self.set_phase(ServerPhase::DomainInfoReady);

        // Bring up the IDM entries.
        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl10::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl10::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl10::phase_7_builtin_access_control_profiles(),
        )?;

        self.reload()?;

        // =========== OAuth2 Cryptography Migration ==============

        debug!("START OAUTH2 MIGRATION");

        // Load all the OAuth2 providers.
        let all_oauth2_rs_entries = self.internal_search(filter!(f_eq(
            Attribute::Class,
            EntryClass::OAuth2ResourceServer.into()
        )))?;

        if !all_oauth2_rs_entries.is_empty() {
            let entry_iter = all_oauth2_rs_entries.iter().map(|tgt_entry| {
                let entry_uuid = tgt_entry.get_uuid();
                let mut modlist = ModifyList::new_list(vec![
                    Modify::Present(Attribute::Class, EntryClass::KeyObject.to_value()),
                    Modify::Present(Attribute::Class, EntryClass::KeyObjectJwtEs256.to_value()),
                    Modify::Present(Attribute::Class, EntryClass::KeyObjectJweA128GCM.to_value()),
                    // Delete the fernet key, rs256 if any, and the es256 key
                    Modify::Purged(Attribute::OAuth2RsTokenKey),
                    Modify::Purged(Attribute::Es256PrivateKeyDer),
                    Modify::Purged(Attribute::Rs256PrivateKeyDer),
                ]);

                trace!(?tgt_entry);

                // Import the ES256 Key
                if let Some(es256_private_der) =
                    tgt_entry.get_ava_single_private_binary(Attribute::Es256PrivateKeyDer)
                {
                    modlist.push_mod(Modify::Present(
                        Attribute::KeyActionImportJwsEs256,
                        Value::PrivateBinary(es256_private_der.to_vec()),
                    ))
                } else {
                    warn!("Unable to migrate es256 key");
                }

                let has_rs256 = tgt_entry
                    .get_ava_single_bool(Attribute::OAuth2JwtLegacyCryptoEnable)
                    .unwrap_or(false);

                // If there is an rs256 key, import it.
                // Import the RS256 Key
                if has_rs256 {
                    modlist.push_mod(Modify::Present(
                        Attribute::Class,
                        EntryClass::KeyObjectJwtEs256.to_value(),
                    ));

                    if let Some(rs256_private_der) =
                        tgt_entry.get_ava_single_private_binary(Attribute::Rs256PrivateKeyDer)
                    {
                        modlist.push_mod(Modify::Present(
                            Attribute::KeyActionImportJwsRs256,
                            Value::PrivateBinary(rs256_private_der.to_vec()),
                        ))
                    } else {
                        warn!("Unable to migrate rs256 key");
                    }
                }

                (entry_uuid, modlist)
            });

            self.internal_batch_modify(entry_iter)?;
        }

        // Reload for new keys, and updated oauth2
        self.reload()?;

        // Done!

        Ok(())
    }

    /// Migration domain level 10 to 11 (1.7.0)
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_10_to_11(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_10 {
            error!("Unable to raise domain level from 10 to 11.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // =========== Apply changes ==============
        self.internal_migrate_or_create_batch(
            "phase 1 - schema attrs",
            migration_data::dl11::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl11::phase_2_schema_classes(),
        )?;

        // Reload for the new schema.
        self.reload()?;

        // Since we just loaded in a ton of schema, lets reindex it in case we added
        // new indexes, or this is a bootstrap and we have no indexes yet.
        self.reindex(false)?;

        // Set Phase
        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl11::phase_3_key_provider(),
        )?;

        // Reload for the new key providers
        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - system entries",
            migration_data::dl11::phase_4_system_entries(),
        )?;

        // Reload for the new system entries
        self.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        self.set_phase(ServerPhase::DomainInfoReady);

        // Bring up the IDM entries.
        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl11::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl11::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl11::phase_7_builtin_access_control_profiles(),
        )?;

        self.reload()?;

        Ok(())
    }

    /// Migration domain level 11 to 12 (1.8.0)
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_11_to_12(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_11 {
            error!("Unable to raise domain level from 11 to 12.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // =========== Apply changes ==============
        self.internal_migrate_or_create_batch(
            "phase 1 - schema attrs",
            migration_data::dl12::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl12::phase_2_schema_classes(),
        )?;

        // Reload for the new schema.
        self.reload()?;

        // Since we just loaded in a ton of schema, lets reindex it in case we added
        // new indexes, or this is a bootstrap and we have no indexes yet.
        self.reindex(false)?;

        // Set Phase
        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl12::phase_3_key_provider(),
        )?;

        // Reload for the new key providers
        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - system entries",
            migration_data::dl12::phase_4_system_entries(),
        )?;

        // Reload for the new system entries
        self.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        self.set_phase(ServerPhase::DomainInfoReady);

        // Bring up the IDM entries.
        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl12::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl12::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl12::phase_7_builtin_access_control_profiles(),
        )?;

        self.reload()?;

        // Cleanup any leftover id keys
        let modlist = ModifyList::new_purge(Attribute::IdVerificationEcKey);
        let filter = filter_all!(f_pres(Attribute::IdVerificationEcKey));

        self.internal_modify(&filter, &modlist)?;

        Ok(())
    }

    /// Migration domain level 12 to 13 (1.9.0)
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_12_to_13(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_12 {
            error!("Unable to raise domain level from 12 to 13.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // =========== Apply changes ==============
        self.internal_migrate_or_create_batch(
            "phase 1 - schema attrs",
            migration_data::dl13::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl13::phase_2_schema_classes(),
        )?;

        // Reload for the new schema.
        self.reload()?;

        // Since we just loaded in a ton of schema, lets reindex it in case we added
        // new indexes, or this is a bootstrap and we have no indexes yet.
        self.reindex(false)?;

        // Set Phase
        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl13::phase_3_key_provider(),
        )?;

        // Reload for the new key providers
        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - system entries",
            migration_data::dl13::phase_4_system_entries(),
        )?;

        // Reload for the new system entries
        self.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        self.set_phase(ServerPhase::DomainInfoReady);

        // Bring up the IDM entries.
        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl13::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl13::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl13::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDS",
            migration_data::dl13::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    /// Migration domain level 13 to 14 (1.10.0)
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_13_to_14(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_13 {
            error!("Unable to raise domain level from 13 to 14.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        // =========== Apply changes ==============
        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl14::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl14::phase_2_schema_classes(),
        )?;

        // Reload for the new schema.
        self.reload()?;

        // Since we just loaded in a ton of schema, lets reindex it in case we added
        // new indexes, or this is a bootstrap and we have no indexes yet.
        self.reindex(false)?;

        // Set Phase
        // Indicate the schema is now ready, which allows dyngroups to work when they
        // are created in the next phase of migrations.
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl14::phase_3_key_provider(),
        )?;

        // Reload for the new key providers
        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl14 system entries",
            migration_data::dl14::phase_4_system_entries(),
        )?;

        // Reload for the new system entries
        self.reload()?;

        // Domain info is now ready and reloaded, we can proceed.
        self.set_phase(ServerPhase::DomainInfoReady);

        // Bring up the IDM entries.
        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl14::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl14::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl14::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDS",
            migration_data::dl14::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        // Default PasswordChangedTime to UNIX_EPOCH
        let filter = filter_all!(f_and!([
            f_eq(Attribute::Class, EntryClass::Person.into()),
            f_andnot(f_pres(Attribute::PasswordChangedTime)),
        ]));
        let modlist = ModifyList::new_purge_and_set(
            Attribute::PasswordChangedTime,
            Value::DateTime(time::OffsetDateTime::UNIX_EPOCH),
        );
        self.internal_modify(&filter, &modlist)?;

        Ok(())
    }

    /// Migration domain level 14 to 15 — adds OAuth2 JIT provisioning schema.
    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_14_to_15(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_15 {
            error!("Unable to raise domain level from 14 to 15.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl15::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl15::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl15::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl15 system entries",
            migration_data::dl15::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl15::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl15::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl15::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl15::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_15_to_16(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_16 {
            error!("Unable to raise domain level from 15 to 16.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl16::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl16::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl16::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl16 system entries",
            migration_data::dl16::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl16::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl16::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl16::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl16::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_16_to_17(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_17 {
            error!("Unable to raise domain level from 16 to 17.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl17::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl17::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl17::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl17 system entries",
            migration_data::dl17::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl17::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl17::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl17::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl17::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_17_to_18(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_18 {
            error!("Unable to raise domain level from 17 to 18.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl18::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl18::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl18::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl18 system entries",
            migration_data::dl18::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl18::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl18::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl18::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl18::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_18_to_19(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_19 {
            error!("Unable to raise domain level from 18 to 19.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl19::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl19::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl19::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl19 system entries",
            migration_data::dl19::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl19::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl19::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl19::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl19::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    #[instrument(level = "info", skip_all)]
    pub(crate) fn migrate_domain_19_to_20(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_20 {
            error!("Unable to raise domain level from 19 to 20.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl20::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl20::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl20::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl20 system entries",
            migration_data::dl20::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl20::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl20::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl20::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl20::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    /// Migrate the domain from level 20 to level 21.
    ///
    /// DL21 adds `OAuth2Issuer` and `OAuth2JwksUri` schema attributes for the generic OIDC
    /// upstream connector.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] if any migration phase fails or if this level is not yet
    /// enabled in the current build.
    pub(crate) fn migrate_domain_20_to_21(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_21 {
            error!("Unable to raise domain level from 20 to 21.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl21::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl21::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl21::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl21 system entries",
            migration_data::dl21::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl21::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl21::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl21::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl21::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    pub(crate) fn migrate_domain_21_to_22(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_22 {
            error!("Unable to raise domain level from 21 to 22.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl22::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl22::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl22::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl22 system entries",
            migration_data::dl22::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl22::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl22::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl22::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl22::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    /// Migrate the domain from level 22 to level 23.
    ///
    /// DL23 adds `DisplayName` to `systemmay` on `OAuth2ResourceServer` so that
    /// existing databases accept the `displayname` attribute in migration assertions
    /// without requiring a database wipe.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] if any migration phase fails or if this level is not yet
    /// enabled in the current build.
    pub(crate) fn migrate_domain_22_to_23(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_23 {
            error!("Unable to raise domain level from 22 to 23.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl23::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl23::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl23::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl23 system entries",
            migration_data::dl23::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl23::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl23::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl23::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl23::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    /// Raise the domain level from 23 to 24.
    ///
    /// DL24 adds `OAuth2LinkBy` to `systemmay` on `OAuth2Client`, enabling per-connector
    /// selection of the account-linking key (`"email"` | `"username"` | `"id"`). When the
    /// attribute is absent on an existing connector, the runtime treats it as
    /// `LinkBy::Email`, preserving pre-DL24 behaviour.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] if any migration phase fails or if this level is not yet
    /// enabled in the current build.
    pub(crate) fn migrate_domain_23_to_24(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_24 {
            error!("Unable to raise domain level from 23 to 24.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl24::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl24::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl24::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl24 system entries",
            migration_data::dl24::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl24::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl24::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl24::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl24::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    /// Raise the domain level from 24 to 25.
    ///
    /// DL25 adds three multi-value `Utf8String` attributes:
    ///   * `OAuth2GroupMapping` on `OAuth2Client`
    ///   * `SamlGroupMapping` on `SamlClient`
    ///   * `OAuth2UpstreamSyncedGroup` on `Person`
    ///
    /// Together they enable per-connector group mapping (upstream group name →
    /// netidm group UUID) and per-person tracking of which memberships were
    /// applied by which connector. No runtime behaviour changes in this DL —
    /// connectors do not yet populate upstream groups; each subsequent
    /// per-connector PR in the dex-parity roadmap populates `claims.groups`.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] if any migration phase fails or if this level
    /// is not yet enabled in the current build.
    pub(crate) fn migrate_domain_24_to_25(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_25 {
            error!("Unable to raise domain level from 24 to 25.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl25::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl25::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl25::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl25 system entries",
            migration_data::dl25::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl25::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl25::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl25::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl25::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        Ok(())
    }

    /// DL25 → DL26 migration: RP-Initiated Logout.
    ///
    /// Adds three URL attributes on existing client classes (OIDC post-logout
    /// redirect allowlist, OIDC back-channel logout endpoint, SAML SLO URL),
    /// two new entry classes (`LogoutDelivery`, `SamlSession`), updates the
    /// OAuth2 / SAML client admin ACPs to include the new URL attributes, and
    /// adds `idm_acp_logout_delivery_read`.
    ///
    /// # Errors
    ///
    /// Returns [`OperationError`] if any migration phase fails or if this
    /// level is not yet enabled in the current build.
    pub(crate) fn migrate_domain_25_to_26(&mut self) -> Result<(), OperationError> {
        if !cfg!(test) && DOMAIN_TGT_LEVEL < DOMAIN_LEVEL_26 {
            error!("Unable to raise domain level from 25 to 26.");
            return Err(OperationError::MG0004DomainLevelInDevelopment);
        }

        self.internal_migrate_or_create_batch(
            &format!("phase 1 - schema attrs target {}", DOMAIN_TGT_LEVEL),
            migration_data::dl26::phase_1_schema_attrs(),
        )?;

        self.internal_migrate_or_create_batch(
            "phase 2 - schema classes",
            migration_data::dl26::phase_2_schema_classes(),
        )?;

        self.reload()?;
        self.reindex(false)?;
        self.set_phase(ServerPhase::SchemaReady);

        self.internal_migrate_or_create_batch(
            "phase 3 - key provider",
            migration_data::dl26::phase_3_key_provider(),
        )?;

        self.reload()?;

        self.internal_migrate_or_create_batch(
            "phase 4 - dl26 system entries",
            migration_data::dl26::phase_4_system_entries(),
        )?;

        self.reload()?;
        self.set_phase(ServerPhase::DomainInfoReady);

        self.internal_migrate_or_create_batch(
            "phase 5 - builtin admin entries",
            migration_data::dl26::phase_5_builtin_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 6 - builtin not admin entries",
            migration_data::dl26::phase_6_builtin_non_admin_entries()?,
        )?;

        self.internal_migrate_or_create_batch(
            "phase 7 - builtin access control profiles",
            migration_data::dl26::phase_7_builtin_access_control_profiles(),
        )?;

        self.internal_delete_batch(
            "phase 8 - delete UUIDs",
            migration_data::dl26::phase_8_delete_uuids(),
        )?;

        self.reload()?;

        self.backfill_saml_session_indices()?;

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

        let mut report_items = Vec::with_capacity(1);

        if current_level <= DOMAIN_LEVEL_7 && upgrade_level >= DOMAIN_LEVEL_8 {
            let item = self
                .domain_upgrade_check_7_to_8_security_keys()
                .map_err(|err| {
                    error!(
                        ?err,
                        "Failed to perform domain upgrade check 7 to 8 - security-keys"
                    );
                    err
                })?;
            report_items.push(item);

            let item = self
                .domain_upgrade_check_7_to_8_oauth2_strict_redirect_uri()
                .map_err(|err| {
                    error!(
                        ?err,
                        "Failed to perform domain upgrade check 7 to 8 - oauth2-strict-redirect_uri"
                    );
                    err
                })?;
            report_items.push(item);
        }

        Ok(ProtoDomainUpgradeCheckReport {
            name,
            uuid,
            current_level,
            upgrade_level,
            report_items,
        })
    }

    pub(crate) fn domain_upgrade_check_7_to_8_security_keys(
        &mut self,
    ) -> Result<ProtoDomainUpgradeCheckItem, OperationError> {
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::Account.into()),
            f_pres(Attribute::PrimaryCredential),
        ]));

        let results = self.internal_search(filter)?;

        let affected_entries = results
            .into_iter()
            .filter_map(|entry| {
                if entry
                    .get_ava_single_credential(Attribute::PrimaryCredential)
                    .map(|cred| cred.has_securitykey())
                    .unwrap_or_default()
                {
                    Some(entry.get_display_id())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let status = if affected_entries.is_empty() {
            ProtoDomainUpgradeCheckStatus::Pass7To8SecurityKeys
        } else {
            ProtoDomainUpgradeCheckStatus::Fail7To8SecurityKeys
        };

        Ok(ProtoDomainUpgradeCheckItem {
            status,
            from_level: DOMAIN_LEVEL_7,
            to_level: DOMAIN_LEVEL_8,
            affected_entries,
        })
    }

    pub(crate) fn domain_upgrade_check_7_to_8_oauth2_strict_redirect_uri(
        &mut self,
    ) -> Result<ProtoDomainUpgradeCheckItem, OperationError> {
        let filter = filter!(f_and!([
            f_eq(Attribute::Class, EntryClass::OAuth2ResourceServer.into()),
            f_andnot(f_pres(Attribute::OAuth2StrictRedirectUri)),
        ]));

        let results = self.internal_search(filter)?;

        let affected_entries = results
            .into_iter()
            .map(|entry| entry.get_display_id())
            .collect::<Vec<_>>();

        let status = if affected_entries.is_empty() {
            ProtoDomainUpgradeCheckStatus::Pass7To8Oauth2StrictRedirectUri
        } else {
            ProtoDomainUpgradeCheckStatus::Fail7To8Oauth2StrictRedirectUri
        };

        Ok(ProtoDomainUpgradeCheckItem {
            status,
            from_level: DOMAIN_LEVEL_7,
            to_level: DOMAIN_LEVEL_8,
            affected_entries,
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

    #[qs_test(domain_level=DOMAIN_MIGRATION_FROM_INVALID)]
    async fn test_migrations_prevent_skips(server: &QueryServer) {
        let curtime = duration_from_epoch_now();

        let mut write_txn = server.write(curtime).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_MIGRATION_FROM_INVALID);

        drop(write_txn);

        // MUST NOT SUCCEED.
        let err = server
            .initialise_helper(curtime, DOMAIN_TGT_LEVEL)
            .await
            .expect_err("Migration went ahead!!!!");

        assert_eq!(err, OperationError::MG0008SkipUpgradeAttempted);
    }

    #[qs_test(domain_level=DOMAIN_MIGRATION_FROM_MIN)]
    async fn test_migrations_skip_valid(server: &QueryServer) {
        let curtime = duration_from_epoch_now();
        // This is a smoke test that X -> Z migrations work for some range. This doesn't
        // absolve us of the need to write more detailed migration tests.
        let mut write_txn = server.write(curtime).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_MIGRATION_FROM_MIN);

        drop(write_txn);

        // MUST SUCCEED.
        server
            .initialise_helper(curtime, DOMAIN_TGT_LEVEL)
            .await
            .expect("Migration failed!!!!")
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_10)]
    async fn test_migrations_dl10_dl11(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_10);

        write_txn.commit().expect("Unable to commit");

        // == pre migration verification. ==
        // check we currently would fail a migration.

        // let mut read_txn = server.read().await.unwrap();
        // drop(read_txn);

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // Fix any issues

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_11)
            .expect("Unable to set domain level to version 11");

        // post migration verification.

        write_txn.commit().expect("Unable to commit");
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_11)]
    async fn test_migrations_dl11_dl12(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_11);

        // Make a new person.
        let tuuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        write_txn
            .internal_create(vec![e1])
            .expect("Unable to create user");

        let user = write_txn
            .internal_search_uuid(tuuid)
            .expect("Unable to load user");

        // They still have an id verification key
        assert!(user.get_ava_set(Attribute::IdVerificationEcKey).is_some());

        write_txn.commit().expect("Unable to commit");

        // == pre migration verification. ==
        // check we currently would fail a migration.

        // let mut read_txn = server.read().await.unwrap();
        // drop(read_txn);

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // Fix any issues

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_12)
            .expect("Unable to set domain level to version 12");

        // post migration verification.
        let user = write_txn
            .internal_search_uuid(tuuid)
            .expect("Unable to load user");

        // The key has been removed.
        assert!(user.get_ava_set(Attribute::IdVerificationEcKey).is_none());

        // New users don't get a key
        let t2uuid = Uuid::new_v4();
        let e2 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson2")),
            (Attribute::Uuid, Value::Uuid(t2uuid)),
            (Attribute::Description, Value::new_utf8s("testperson2")),
            (Attribute::DisplayName, Value::new_utf8s("testperson2"))
        );

        write_txn
            .internal_create(vec![e2])
            .expect("Unable to create user");

        let user = write_txn
            .internal_search_uuid(t2uuid)
            .expect("Unable to load user");

        // No key!
        assert!(user.get_ava_set(Attribute::IdVerificationEcKey).is_none());

        write_txn.commit().expect("Unable to commit");
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_12)]
    async fn test_migrations_dl12_dl13(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_12);

        write_txn.commit().expect("Unable to commit");

        // == pre migration verification. ==
        // check we currently would fail a migration.

        // let mut read_txn = server.read().await.unwrap();
        // drop(read_txn);

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // Fix any issues

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_13)
            .expect("Unable to set domain level to version 13");

        // post migration verification.

        write_txn.commit().expect("Unable to commit");
    }

    #[qs_test(domain_level=DOMAIN_LEVEL_13)]
    async fn test_migrations_dl13_dl14(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_13);

        // Create a person without pwd_changed_time
        let tuuid = Uuid::new_v4();
        let e1 = entry_init!(
            (Attribute::Class, EntryClass::Object.to_value()),
            (Attribute::Class, EntryClass::Person.to_value()),
            (Attribute::Class, EntryClass::Account.to_value()),
            (Attribute::Name, Value::new_iname("testperson1")),
            (Attribute::Uuid, Value::Uuid(tuuid)),
            (Attribute::Description, Value::new_utf8s("testperson1")),
            (Attribute::DisplayName, Value::new_utf8s("testperson1"))
        );

        write_txn
            .internal_create(vec![e1])
            .expect("Unable to create test person");

        let user = write_txn
            .internal_search_uuid(tuuid)
            .expect("Unable to load test person");

        // sanity check
        assert!(user
            .get_ava_single_datetime(Attribute::PasswordChangedTime)
            .is_none());

        write_txn.commit().expect("Unable to commit");

        // == pre migration verification. ==
        // check we currently would fail a migration.

        // let mut read_txn = server.read().await.unwrap();
        // drop(read_txn);

        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        // Fix any issues

        // == Increase the version ==
        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_14)
            .expect("Unable to set domain level to version 14");

        // post migration verification.
        // pwd_changed_time should be defaulted to UNIX_EPOCH
        let user = write_txn
            .internal_search_uuid(tuuid)
            .expect("Unable to load test person after migration");

        let pwd_changed = user
            .get_ava_single_datetime(Attribute::PasswordChangedTime)
            .expect("PasswordChangedTime should be set after DL13->DL14 migration");

        assert_eq!(pwd_changed, time::OffsetDateTime::UNIX_EPOCH);

        write_txn.commit().expect("Unable to commit");
    }

    /// DL24 → DL25: asserts that the three new schema attributes introduced
    /// for upstream group plumbing (`OAuth2GroupMapping`, `SamlGroupMapping`,
    /// `OAuth2UpstreamSyncedGroup`) exist in the schema after migration.
    #[qs_test(domain_level=DOMAIN_LEVEL_24)]
    async fn test_migrations_dl24_dl25(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_24);

        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_25)
            .expect("Unable to set domain level to version 25");

        // Schema attributes are stored as entries keyed by their schema UUID.
        // Each of the three new attributes must resolve after the migration.
        write_txn
            .internal_search_uuid(UUID_SCHEMA_ATTR_OAUTH2_GROUP_MAPPING)
            .expect("UUID_SCHEMA_ATTR_OAUTH2_GROUP_MAPPING missing after DL25 migration");

        write_txn
            .internal_search_uuid(UUID_SCHEMA_ATTR_SAML_GROUP_MAPPING)
            .expect("UUID_SCHEMA_ATTR_SAML_GROUP_MAPPING missing after DL25 migration");

        write_txn
            .internal_search_uuid(UUID_SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP)
            .expect("UUID_SCHEMA_ATTR_OAUTH2_UPSTREAM_SYNCED_GROUP missing after DL25 migration");

        write_txn.commit().expect("Unable to commit");
    }

    /// DL25 → DL26: asserts that the RP-Initiated Logout schema elements
    /// (three URL attributes on existing client classes, two new entry
    /// classes with their attribute sets, and the new admin read-only ACP
    /// for the delivery queue) are present after migration.
    #[qs_test(domain_level=DOMAIN_LEVEL_25)]
    async fn test_migrations_dl25_dl26(server: &QueryServer) {
        let mut write_txn = server.write(duration_from_epoch_now()).await.unwrap();

        let db_domain_version = write_txn
            .internal_search_uuid(UUID_DOMAIN_INFO)
            .expect("unable to access domain entry")
            .get_ava_single_uint32(Attribute::Version)
            .expect("Attribute Version not present");

        assert_eq!(db_domain_version, DOMAIN_LEVEL_25);

        write_txn
            .internal_apply_domain_migration(DOMAIN_LEVEL_26)
            .expect("Unable to set domain level to version 26");

        // The three new URL attrs on existing client classes.
        write_txn
            .internal_search_uuid(UUID_SCHEMA_ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI)
            .expect("UUID_SCHEMA_ATTR_OAUTH2_RS_POST_LOGOUT_REDIRECT_URI missing after DL26 migration");
        write_txn
            .internal_search_uuid(UUID_SCHEMA_ATTR_OAUTH2_RS_BACKCHANNEL_LOGOUT_URI)
            .expect("UUID_SCHEMA_ATTR_OAUTH2_RS_BACKCHANNEL_LOGOUT_URI missing after DL26 migration");
        write_txn
            .internal_search_uuid(UUID_SCHEMA_ATTR_SAML_SINGLE_LOGOUT_SERVICE_URL)
            .expect("UUID_SCHEMA_ATTR_SAML_SINGLE_LOGOUT_SERVICE_URL missing after DL26 migration");

        // LogoutDelivery class + its seven attributes.
        write_txn
            .internal_search_uuid(UUID_SCHEMA_CLASS_LOGOUT_DELIVERY)
            .expect("UUID_SCHEMA_CLASS_LOGOUT_DELIVERY missing after DL26 migration");
        for (uuid, label) in [
            (
                UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_ENDPOINT,
                "LOGOUT_DELIVERY_ENDPOINT",
            ),
            (
                UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_TOKEN,
                "LOGOUT_DELIVERY_TOKEN",
            ),
            (
                UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_STATUS,
                "LOGOUT_DELIVERY_STATUS",
            ),
            (
                UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_ATTEMPTS,
                "LOGOUT_DELIVERY_ATTEMPTS",
            ),
            (
                UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_NEXT_ATTEMPT,
                "LOGOUT_DELIVERY_NEXT_ATTEMPT",
            ),
            (
                UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_CREATED,
                "LOGOUT_DELIVERY_CREATED",
            ),
            (UUID_SCHEMA_ATTR_LOGOUT_DELIVERY_RP, "LOGOUT_DELIVERY_RP"),
        ] {
            write_txn.internal_search_uuid(uuid).unwrap_or_else(|_| {
                panic!("UUID_SCHEMA_ATTR_{label} missing after DL26 migration")
            });
        }

        // SamlSession class + its five attributes.
        write_txn
            .internal_search_uuid(UUID_SCHEMA_CLASS_SAML_SESSION)
            .expect("UUID_SCHEMA_CLASS_SAML_SESSION missing after DL26 migration");
        for (uuid, label) in [
            (UUID_SCHEMA_ATTR_SAML_SESSION_USER, "SAML_SESSION_USER"),
            (UUID_SCHEMA_ATTR_SAML_SESSION_SP, "SAML_SESSION_SP"),
            (UUID_SCHEMA_ATTR_SAML_SESSION_INDEX, "SAML_SESSION_INDEX"),
            (
                UUID_SCHEMA_ATTR_SAML_SESSION_UAT_UUID,
                "SAML_SESSION_UAT_UUID",
            ),
            (UUID_SCHEMA_ATTR_SAML_SESSION_CREATED, "SAML_SESSION_CREATED"),
        ] {
            write_txn.internal_search_uuid(uuid).unwrap_or_else(|_| {
                panic!("UUID_SCHEMA_ATTR_{label} missing after DL26 migration")
            });
        }

        // The new admin read-only ACP for the delivery queue.
        write_txn
            .internal_search_uuid(UUID_IDM_ACP_LOGOUT_DELIVERY_READ)
            .expect("UUID_IDM_ACP_LOGOUT_DELIVERY_READ missing after DL26 migration");

        write_txn.commit().expect("Unable to commit");
    }
}
