use std::iter;

use compact_jwt::JweCompact;
use netidm_proto::internal::{
    CUIntentToken, CUSessionToken, CUStatus, CreateRequest, DeleteRequest, ImageValue,
    Modify as ProtoModify, ModifyList as ProtoModifyList, ModifyRequest,
    Oauth2ClaimMapJoin as ProtoOauth2ClaimMapJoin, OperationError,
};
use netidm_proto::v1::{AccountUnixExtend, Entry as ProtoEntry, GroupUnixExtend};
use std::str::FromStr;
use time::OffsetDateTime;
use tracing::{info, instrument, trace};
use uuid::Uuid;

use netidmd_lib::{
    event::{CreateEvent, DeleteEvent, ModifyEvent, ReviveRecycledEvent},
    filter::{Filter, FilterInvalid},
    idm::account::DestroySessionTokenEvent,
    idm::credupdatesession::{
        CredentialUpdateIntentTokenExchange, CredentialUpdateSessionToken,
        InitCredentialUpdateEvent, InitCredentialUpdateIntentEvent,
        InitCredentialUpdateIntentSendEvent,
    },
    idm::event::{GeneratePasswordEvent, RegenerateRadiusSecretEvent, UnixPasswordChangeEvent},
    idm::oauth2::{
        AccessTokenRequest, AccessTokenResponse, AuthorisePermitSuccess, Oauth2Error,
        TokenRevokeRequest,
    },
    idm::server::IdmServerTransaction,
    idm::serviceaccount::{DestroyApiTokenEvent, GenerateApiTokenEvent},
    modify::{Modify, ModifyInvalid, ModifyList},
    value::{OauthClaimMapJoin, PartialValue, Value},
};

use netidmd_lib::prelude::*;

#[cfg(feature = "dev-oauth2-device-flow")]
use std::collections::BTreeSet;

use super::QueryServerWriteV1;

impl QueryServerWriteV1 {
    #[instrument(level = "debug", skip_all)]
    async fn modify_from_parts(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: &str,
        proto_ml: &ProtoModifyList,
        filter: Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name)
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let mdf = match ModifyEvent::from_parts(
            ident,
            target_uuid,
            proto_ml,
            filter,
            &mut idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err=?e, "Failed to begin modify during modify_from_parts");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(level = "debug", skip_all)]
    async fn modify_from_internal_parts(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: &str,
        ml: &ModifyList<ModifyInvalid>,
        filter: Filter<FilterInvalid>,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name)
            .inspect_err(|err| {
                error!(?err, "Error resolving id to target");
            })?;

        let f_uuid = filter_all!(f_eq(Attribute::Uuid, PartialValue::Uuid(target_uuid)));
        // Add any supplemental conditions we have.
        let joined_filter = Filter::join_parts_and(f_uuid, filter);

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            ml,
            &joined_filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify during modify_from_internal_parts");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_create(
        &self,
        client_auth_info: ClientAuthInfo,
        req: CreateRequest,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let crt = match CreateEvent::from_message(ident, &req, &mut idms_prox_write.qs_write) {
            Ok(c) => c,
            Err(e) => {
                admin_warn!(err = ?e, "Failed to begin create");
                return Err(e);
            }
        };

        trace!(?crt, "Begin create event");

        idms_prox_write
            .qs_write
            .create(&crt)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_modify(
        &self,
        client_auth_info: ClientAuthInfo,
        req: ModifyRequest,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let mdf = match ModifyEvent::from_message(ident, &req, &mut idms_prox_write.qs_write) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify during handle_modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_delete(
        &self,
        client_auth_info: ClientAuthInfo,
        req: DeleteRequest,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let del = match DeleteEvent::from_message(ident, &req, &mut idms_prox_write.qs_write) {
            Ok(d) => d,
            Err(e) => {
                error!(err = ?e, "Failed to begin delete");
                return Err(e);
            }
        };

        trace!(?del, "Begin delete event");

        idms_prox_write
            .qs_write
            .delete(&del)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internalpatch(
        &self,
        client_auth_info: ClientAuthInfo,
        filter: Filter<FilterInvalid>,
        update: ProtoEntry,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Given a protoEntry, turn this into a modification set.
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        // Transform the ProtoEntry to a Modlist
        let modlist =
            ModifyList::from_patch(&update, &mut idms_prox_write.qs_write).map_err(|e| {
                error!(err = ?e, "Invalid Patch Request");
                e
            })?;

        let mdf =
            ModifyEvent::from_internal_parts(ident, &modlist, &filter, &idms_prox_write.qs_write)
                .map_err(|e| {
                error!(err = ?e, "Failed to begin modify during handle_internalpatch");
                e
            })?;

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_internaldelete(
        &self,
        client_auth_info: ClientAuthInfo,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let del = match DeleteEvent::from_parts(ident, &filter, &mut idms_prox_write.qs_write) {
            Ok(d) => d,
            Err(e) => {
                error!(err = ?e, "Failed to begin delete");
                return Err(e);
            }
        };

        trace!(?del, "Begin delete event");

        idms_prox_write
            .qs_write
            .delete(&del)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_reviverecycled(
        &self,
        client_auth_info: ClientAuthInfo,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let rev = match ReviveRecycledEvent::from_parts(ident, &filter, &idms_prox_write.qs_write) {
            Ok(r) => r,
            Err(e) => {
                error!(err = ?e, "Failed to begin revive");
                return Err(e);
            }
        };

        trace!(?rev, "Begin revive event");

        idms_prox_write
            .qs_write
            .revive_recycled(&rev)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_service_account_credential_generate(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<String, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        // given the uuid_or_name, determine the target uuid.
        // We can either do this by trying to parse the name or by creating a filter
        // to find the entry - there are risks to both TBH ... especially when the uuid
        // is also an entries name, but that they aren't the same entry.

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let gpe = GeneratePasswordEvent::from_parts(ident, target_uuid).map_err(|e| {
            error!(
                err = ?e,
                "Failed to begin handle_service_account_credential_generate",
            );
            e
        })?;
        idms_prox_write
            .generate_service_account_password(&gpe)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_service_account_api_token_generate(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        label: String,
        expiry: Option<OffsetDateTime>,
        read_write: bool,
        compact: bool,
        eventid: Uuid,
    ) -> Result<String, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let gte = GenerateApiTokenEvent {
            ident,
            target,
            label,
            expiry,
            read_write,
            compact,
        };

        idms_prox_write
            .service_account_generate_api_token(&gte, ct)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
            .map(|token| token.to_string())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_service_account_api_token_destroy(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        token_id: Uuid,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let dte = DestroyApiTokenEvent {
            ident,
            target,
            token_id,
        };

        idms_prox_write
            .service_account_destroy_api_token(&dte)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_account_user_auth_token_destroy(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        token_id: Uuid,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let dte = DestroySessionTokenEvent {
            ident,
            target,
            token_id,
        };

        idms_prox_write
            .account_destroy_session_token(&dte)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    /// Terminate every active netidm session the calling user holds.
    ///
    /// US5 self-service surface per `specs/009-rp-logout/spec.md`. Used by
    /// `POST /v1/self/logout_all`. Enumerates the caller's `UserAuthTokenSession`
    /// values and funnels each through
    /// [`netidmd_lib::idm::logout::terminate_session`] so refresh-token
    /// revocation and back-channel delivery (once US3 lands) fire per
    /// session. Non-revoked sessions are the target; already-revoked ones
    /// are skipped. The CLI token used to make this call is itself
    /// invalidated as part of the termination.
    ///
    /// Returns the count of sessions terminated.
    ///
    /// # Errors
    ///
    /// Propagates any `OperationError` from identity validation, UAT
    /// enumeration, or underlying session-termination.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_user_logout_all_sessions(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
    ) -> Result<usize, OperationError> {
        let _ = eventid;
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target = ident.get_uuid().ok_or_else(|| {
            error!("Invalid identity - no uuid present");
            OperationError::InvalidState
        })?;

        let count = terminate_all_sessions_for(&mut idms_prox_write, target)?;
        idms_prox_write.commit().map(|_| count)
    }

    /// Terminate every active netidm session a named user holds.
    ///
    /// US5 admin surface. Used by `POST /v1/person/{id}/logout_all`.
    /// ACP-gated via the underlying write identity; non-admin callers are
    /// rejected at the `target_to_account` step.
    ///
    /// Returns the target user's UUID and the count of sessions terminated.
    ///
    /// # Errors
    ///
    /// Propagates any `OperationError` from identity validation, target
    /// resolution, UAT enumeration, or underlying session-termination.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_admin_logout_all_sessions(
        &self,
        client_auth_info: ClientAuthInfo,
        target: String,
        eventid: Uuid,
    ) -> Result<(Uuid, usize), OperationError> {
        let _ = eventid;
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let _ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(target.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let count = terminate_all_sessions_for(&mut idms_prox_write, target_uuid)?;
        idms_prox_write.commit().map(|_| (target_uuid, count))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_logout(
        &self,
        client_auth_info: ClientAuthInfo,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        // We specifically need a uat here to assess the auth type!
        let validate_result =
            idms_prox_write.validate_client_auth_info_to_ident(client_auth_info, ct);

        let ident = match validate_result {
            Ok(ident) => ident,
            Err(OperationError::SessionExpired) | Err(OperationError::NotAuthenticated) => {
                return Ok(())
            }
            Err(err) => {
                error!(?err, "Invalid identity");
                return Err(err);
            }
        };

        if !ident.can_logout() {
            info!("Ignoring request to logout session - these sessions are not recorded");
            return Ok(());
        };

        let target = ident.get_uuid().ok_or_else(|| {
            error!("Invalid identity - no uuid present");
            OperationError::InvalidState
        })?;

        let token_id = ident.get_session_id();

        let dte = DestroySessionTokenEvent {
            ident,
            target,
            token_id,
        };

        idms_prox_write
            .account_destroy_session_token(&dte)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdate(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<(CUSessionToken, CUStatus), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        idms_prox_write
            .init_credential_update(&InitCredentialUpdateEvent::new(ident, target_uuid), ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .map_err(|e| {
                error!(
                    err = ?e,
                    "Failed to begin init_credential_update",
                );
                e
            })
            .map(|(tok, sta)| {
                (
                    CUSessionToken {
                        token: tok.token_enc.to_string(),
                    },
                    sta.into(),
                )
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid),
    )]
    pub async fn handle_idmcredentialupdateintent(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        ttl: Option<Duration>,
        eventid: Uuid,
    ) -> Result<CUIntentToken, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        idms_prox_write
            .init_credential_update_intent(
                &InitCredentialUpdateIntentEvent::new(ident, target_uuid, ttl),
                ct,
            )
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .map_err(|e| {
                error!(
                    err = ?e,
                    "Failed to begin init_credential_update_intent",
                );
                e
            })
            .map(|tok| CUIntentToken {
                token: tok.intent_id,
                expiry_time: tok.expiry_time,
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid),
    )]
    pub async fn handle_idm_credential_update_intent_send(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        max_ttl: Option<Duration>,
        email: Option<String>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .inspect_err(|err| {
                error!(?err, "Error resolving id to target");
            })?;

        let event = InitCredentialUpdateIntentSendEvent {
            ident,
            target,
            max_ttl,
            email,
        };

        idms_prox_write
            .init_credential_update_intent_send(event, ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .inspect_err(|err| {
                error!(?err, "Failed to process init_credential_update_intent_send",);
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialexchangeintent(
        &self,
        intent_id: String,
        eventid: Uuid,
    ) -> Result<(CUSessionToken, CUStatus), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let intent_token = CredentialUpdateIntentTokenExchange { intent_id };
        // TODO: this is throwing a 500 error when a session is already in use, that seems bad?
        idms_prox_write
            .exchange_intent_credential_update(intent_token, ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .map_err(|e| {
                error!(
                    err = ?e,
                    "Failed to begin exchange_intent_credential_update",
                );
                e
            })
            .map(|(tok, sta)| {
                (
                    CUSessionToken {
                        token: tok.token_enc.to_string(),
                    },
                    sta.into(),
                )
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idm_credential_revoke_intent(
        &self,
        intent_id: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let intent_token = CredentialUpdateIntentTokenExchange { intent_id };
        idms_prox_write
            .revoke_credential_update_intent(intent_token, ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .inspect_err(|err| {
                error!(?err, "Failed to perfect exchange_intent_credential_update",);
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdatecommit(
        &self,
        session_token: CUSessionToken,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let session_token = JweCompact::from_str(session_token.token.as_str())
            .map(|token_enc| CredentialUpdateSessionToken { token_enc })
            .map_err(|err| {
                error!(?err, "malformed token");
                OperationError::InvalidRequestState
            })?;

        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        idms_prox_write
            .commit_credential_update(&session_token, ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .map_err(|e| {
                error!(
                    err = ?e,
                    "Failed to begin commit_credential_update",
                );
                e
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmcredentialupdatecancel(
        &self,
        session_token: CUSessionToken,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let session_token = JweCompact::from_str(session_token.token.as_str())
            .map(|token_enc| CredentialUpdateSessionToken { token_enc })
            .map_err(|err| {
                error!(?err, "malformed token");
                OperationError::InvalidRequestState
            })?;

        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        idms_prox_write
            .cancel_credential_update(&session_token, ct)
            .and_then(|tok| idms_prox_write.commit().map(|_| tok))
            .map_err(|e| {
                error!(
                    err = ?e,
                    "Failed to begin commit_credential_cancel",
                );
                e
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_service_account_into_person(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        idms_prox_write
            .service_account_into_person(&ident, target_uuid)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_regenerateradius(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        eventid: Uuid,
    ) -> Result<String, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let rrse = RegenerateRadiusSecretEvent::from_parts(
            // &idms_prox_write.qs_write,
            ident,
            target_uuid,
        )
        .map_err(|e| {
            error!(
                err = ?e,
                "Failed to begin idm_account_regenerate_radius",
            );
            e
        })?;

        idms_prox_write
            .regenerate_radius_secret(&rrse)
            .and_then(|r| idms_prox_write.commit().map(|_| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_purgeattribute(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        attr: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let target_attr = Attribute::from(attr.as_str());
        let mdf = match ModifyEvent::from_target_uuid_attr_purge(
            ident,
            target_uuid,
            target_attr,
            filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify during purge attribute");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_removeattributevalues(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        attr: String,
        values: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;
        let target_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(uuid_or_name.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving id to target");
                e
            })?;

        let proto_ml = ProtoModifyList::new_list(
            values
                .into_iter()
                .map(|v| ProtoModify::Removed(attr.clone(), v))
                .collect(),
        );

        let mdf = match ModifyEvent::from_parts(
            ident,
            target_uuid,
            &proto_ml,
            filter,
            &mut idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        name = "append_attribute",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_appendattribute(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        attr: String,
        values: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // We need to turn these into proto modlists so they can be converted
        // and validated.
        let proto_ml = ProtoModifyList::new_list(
            values
                .into_iter()
                .map(|v| ProtoModify::Present(attr.clone(), v))
                .collect(),
        );
        self.modify_from_parts(client_auth_info, &uuid_or_name, &proto_ml, filter)
            .await
    }

    #[instrument(
        level = "info",
        name = "set_attribute",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_setattribute(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        attr: String,
        values: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // We need to turn these into proto modlists so they can be converted
        // and validated.
        let proto_ml = ProtoModifyList::new_list(
            std::iter::once(ProtoModify::Purged(attr.clone()))
                .chain(
                    values
                        .into_iter()
                        .map(|v| ProtoModify::Present(attr.clone(), v)),
                )
                .collect(),
        );
        self.modify_from_parts(client_auth_info, &uuid_or_name, &proto_ml, filter)
            .await
    }

    #[instrument(
        level = "info",
        name = "ssh_key_create",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_sshkeycreate(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        tag: &str,
        key: &str,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let v_sk = Value::new_sshkey_str(tag, key)?;

        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ml = ModifyList::new_append(Attribute::SshPublicKey, v_sk);

        self.modify_from_internal_parts(client_auth_info, &uuid_or_name, &ml, filter)
            .await
    }

    #[instrument(
        level = "info",
        name = "idm_account_unix_extend",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmaccountunixextend(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        ux: AccountUnixExtend,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let AccountUnixExtend { gidnumber, shell } = ux;
        // The filter_map here means we only create the mods if the gidnumber or shell are set
        // in the actual request.
        let mods: Vec<_> = iter::once(Some(Modify::Present(
            Attribute::Class,
            EntryClass::PosixAccount.into(),
        )))
        .chain(iter::once(
            gidnumber
                .as_ref()
                .map(|_| Modify::Purged(Attribute::GidNumber)),
        ))
        .chain(iter::once(gidnumber.map(|n| {
            Modify::Present(Attribute::GidNumber, Value::new_uint32(n))
        })))
        .chain(iter::once(
            shell
                .as_ref()
                .map(|_| Modify::Purged(Attribute::LoginShell)),
        ))
        .chain(iter::once(shell.map(|s| {
            Modify::Present(Attribute::LoginShell, Value::new_iutf8(s.as_str()))
        })))
        .flatten()
        .collect();

        let ml = ModifyList::new_list(mods);

        let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Account.into()));

        self.modify_from_internal_parts(client_auth_info, &uuid_or_name, &ml, filter)
            .await
    }

    #[instrument(
        level = "info",
        name = "idm_group_unix_extend",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmgroupunixextend(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        gx: GroupUnixExtend,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // The if let Some here means we only create the mods if the gidnumber is set
        // in the actual request.

        let gidnumber_mods = if let Some(gid) = gx.gidnumber {
            [
                Some(Modify::Purged(Attribute::GidNumber)),
                Some(Modify::Present(
                    Attribute::GidNumber,
                    Value::new_uint32(gid),
                )),
            ]
        } else {
            [None, None]
        };
        let mods: Vec<_> = iter::once(Some(Modify::Present(
            Attribute::Class,
            EntryClass::PosixGroup.into(),
        )))
        .chain(gidnumber_mods)
        .flatten()
        .collect();

        let ml = ModifyList::new_list(mods);

        let filter = filter_all!(f_eq(Attribute::Class, EntryClass::Group.into()));

        self.modify_from_internal_parts(client_auth_info, &uuid_or_name, &ml, filter)
            .await
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_idmaccountunixsetcred(
        &self,
        client_auth_info: ClientAuthInfo,
        uuid_or_name: String,
        cred: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let target_uuid = Uuid::parse_str(uuid_or_name.as_str()).or_else(|_| {
            idms_prox_write
                .qs_write
                .name_to_uuid(uuid_or_name.as_str())
                .inspect_err(|err| {
                    if &OperationError::NoMatchingEntries == err {
                        info!("Account not found");
                    } else {
                        info!(?err, "Error resolving from gidnumber ...");
                    }
                })
        })?;

        let upce = UnixPasswordChangeEvent::from_parts(
            // &idms_prox_write.qs_write,
            ident,
            target_uuid,
            cred,
        )
        .map_err(|e| {
            error!(err = ?e, "Failed to begin UnixPasswordChangeEvent");
            e
        })?;
        idms_prox_write
            .set_unix_account_password(&upce)
            .and_then(|_| idms_prox_write.commit())
            .map(|_| ())
    }

    #[instrument(level = "debug", skip_all)]
    pub async fn handle_image_update(
        &self,
        client_auth_info: ClientAuthInfo,
        request_filter: Filter<FilterInvalid>,
        image: Option<ImageValue>,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .inspect_err(|err| {
                error!(?err, "Invalid identity in handle_image_update");
            })?;

        let modlist = if let Some(image) = image {
            ModifyList::new_purge_and_set(Attribute::Image, Value::Image(image))
        } else {
            ModifyList::new_purge(Attribute::Image)
        };

        let mdf = ModifyEvent::from_internal_parts(
            ident,
            &modlist,
            &request_filter,
            &idms_prox_write.qs_write,
        )
        .inspect_err(|err| {
            error!(?err, "Failed to begin modify during handle_image_update");
        })?;

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_scopemap_update(
        &self,
        client_auth_info: ClientAuthInfo,
        group: String,
        scopes: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml = ModifyList::new_append(
            Attribute::OAuth2RsScopeMap,
            Value::new_oauthscopemap(group_uuid, scopes.into_iter().collect()).ok_or_else(
                || OperationError::InvalidAttribute("Invalid Oauth Scope Map syntax".to_string()),
            )?,
        );

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_scopemap_delete(
        &self,
        client_auth_info: ClientAuthInfo,
        group: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml =
            ModifyList::new_remove(Attribute::OAuth2RsScopeMap, PartialValue::Refer(group_uuid));

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_claimmap_update(
        &self,
        client_auth_info: ClientAuthInfo,
        claim_name: String,
        group: String,
        claims: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml = ModifyList::new_append(
            Attribute::OAuth2RsClaimMap,
            Value::new_oauthclaimmap(claim_name, group_uuid, claims.into_iter().collect())
                .ok_or_else(|| {
                    OperationError::InvalidAttribute("Invalid Oauth Claim Map syntax".to_string())
                })?,
        );

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_claimmap_join_update(
        &self,
        client_auth_info: ClientAuthInfo,
        claim_name: String,
        join: ProtoOauth2ClaimMapJoin,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let join = match join {
            ProtoOauth2ClaimMapJoin::Csv => OauthClaimMapJoin::CommaSeparatedValue,
            ProtoOauth2ClaimMapJoin::Ssv => OauthClaimMapJoin::SpaceSeparatedValue,
            ProtoOauth2ClaimMapJoin::Array => OauthClaimMapJoin::JsonArray,
        };

        let ml = ModifyList::new_append(
            Attribute::OAuth2RsClaimMap,
            Value::OauthClaimMap(claim_name, join),
        );

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_claimmap_delete(
        &self,
        client_auth_info: ClientAuthInfo,
        claim_name: String,
        group: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml = ModifyList::new_remove(
            Attribute::OAuth2RsClaimMap,
            PartialValue::OauthClaim(claim_name, group_uuid),
        );

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_sup_scopemap_update(
        &self,
        client_auth_info: ClientAuthInfo,
        group: String,
        scopes: Vec<String>,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        // Because this is from internal, we can generate a real modlist, rather
        // than relying on the proto ones.
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml = ModifyList::new_append(
            Attribute::OAuth2RsSupScopeMap,
            Value::new_oauthscopemap(group_uuid, scopes.into_iter().collect()).ok_or_else(
                || OperationError::InvalidAttribute("Invalid Oauth Scope Map syntax".to_string()),
            )?,
        );

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_sup_scopemap_delete(
        &self,
        client_auth_info: ClientAuthInfo,
        group: String,
        filter: Filter<FilterInvalid>,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .map_err(|e| {
                error!(err = ?e, "Invalid identity");
                e
            })?;

        let group_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(group.as_str())
            .map_err(|e| {
                error!(err = ?e, "Error resolving group name to target");
                e
            })?;

        let ml = ModifyList::new_remove(
            Attribute::OAuth2RsSupScopeMap,
            PartialValue::Refer(group_uuid),
        );

        let mdf = match ModifyEvent::from_internal_parts(
            ident,
            &ml,
            &filter,
            &idms_prox_write.qs_write,
        ) {
            Ok(m) => m,
            Err(e) => {
                error!(err = ?e, "Failed to begin modify");
                return Err(e);
            }
        };

        trace!(?mdf, "Begin modify event");

        idms_prox_write
            .qs_write
            .modify(&mdf)
            .and_then(|_| idms_prox_write.commit().map(|_| ()))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_authorise_permit(
        &self,
        client_auth_info: ClientAuthInfo,
        consent_req: String,
        eventid: Uuid,
    ) -> Result<AuthorisePermitSuccess, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let ident = idms_prox_write
            .validate_client_auth_info_to_ident(client_auth_info, ct)
            .inspect_err(|err| {
                error!(?err, "Invalid identity");
            })?;

        idms_prox_write
            .check_oauth2_authorise_permit(&ident, &consent_req, ct)
            .and_then(|r| idms_prox_write.commit().map(|()| r))
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_token_exchange(
        &self,
        client_auth_info: ClientAuthInfo,
        token_req: AccessTokenRequest,
        eventid: Uuid,
    ) -> Result<AccessTokenResponse, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self
            .idms
            .proxy_write(ct)
            .await
            .map_err(Oauth2Error::ServerError)?;
        // Now we can send to the idm server for authorisation checking.
        let resp = idms_prox_write.check_oauth2_token_exchange(&client_auth_info, &token_req, ct);

        match &resp {
            Err(Oauth2Error::InvalidGrant) | Ok(_) => {
                idms_prox_write.commit().map_err(Oauth2Error::ServerError)?;
            }
            _ => {}
        };

        resp
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_oauth2_token_revoke(
        &self,
        client_auth_info: ClientAuthInfo,
        intr_req: TokenRevokeRequest,
        eventid: Uuid,
    ) -> Result<(), Oauth2Error> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self
            .idms
            .proxy_write(ct)
            .await
            .map_err(Oauth2Error::ServerError)?;
        idms_prox_write
            .oauth2_token_revoke(&client_auth_info, &intr_req, ct)
            .and_then(|()| idms_prox_write.commit().map_err(Oauth2Error::ServerError))
    }

    /// Dispatch an OIDC RP-Initiated Logout 1.0 end-session request to the
    /// library layer, commit the resulting session-termination write, and
    /// return the outcome (redirect or render confirmation) back to the
    /// HTTP layer.
    ///
    /// # Errors
    ///
    /// Propagates [`OperationError`] from
    /// [`netidmd_lib::idm::server::IdmServerProxyWriteTransaction::handle_oauth2_rp_initiated_logout`]
    /// — primarily `NoMatchingEntries` if `client_id` is not a registered
    /// OAuth2 client, and any DB-write errors that surface from the
    /// session-termination step.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_oauth2_rp_initiated_logout(
        &self,
        client_id: String,
        id_token_hint: Option<String>,
        post_logout_redirect_uri: Option<String>,
        state: Option<String>,
        eventid: Uuid,
    ) -> Result<netidmd_lib::idm::logout::OidcLogoutOutcome, OperationError> {
        let _ = eventid;
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let outcome = idms_prox_write.handle_oauth2_rp_initiated_logout(
            &client_id,
            id_token_hint.as_deref(),
            post_logout_redirect_uri.as_deref(),
            state,
        )?;
        idms_prox_write.commit()?;
        Ok(outcome)
    }

    #[cfg(feature = "dev-oauth2-device-flow")]
    pub async fn handle_oauth2_device_flow_start(
        &self,
        client_auth_info: ClientAuthInfo,
        client_id: &str,
        scope: &Option<BTreeSet<String>>,
        eventid: Uuid,
    ) -> Result<netidm_proto::oauth2::DeviceAuthorizationResponse, Oauth2Error> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self
            .idms
            .proxy_write(ct)
            .await
            .map_err(Oauth2Error::ServerError)?;
        idms_prox_write
            .handle_oauth2_start_device_flow(client_auth_info, client_id, scope, eventid)
            .and_then(|res| {
                idms_prox_write.commit().map_err(Oauth2Error::ServerError)?;
                Ok(res)
            })
    }

    #[instrument(
        level = "info",
        skip_all,
        fields(uuid = ?eventid)
    )]
    pub async fn handle_jit_provision_oauth2_account(
        &self,
        provider_uuid: Uuid,
        claims: netidmd_lib::idm::authsession::handler_oauth2_client::ExternalUserClaims,
        desired_name: String,
        eventid: Uuid,
        _client_auth_info: ClientAuthInfo,
    ) -> Result<Uuid, OperationError> {
        let _ = eventid;
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let person_uuid =
            idms_prox_write.jit_provision_oauth2_account(provider_uuid, &claims, &desired_name)?;

        // Reconcile upstream group memberships against the connector's
        // mapping (DL25+). In this PR `claims.groups` is always empty; once
        // per-connector PRs populate it, this runs for real.
        if let Err(e) = idms_prox_write.reconcile_upstream_memberships_for_provider(
            person_uuid,
            provider_uuid,
            &claims.groups,
        ) {
            // Never block auth on a reconciliation error (FR-018).
            warn!(
                ?e,
                ?provider_uuid,
                ?person_uuid,
                "reconcile_upstream_memberships failed during JIT provision; proceeding"
            );
        }

        idms_prox_write.commit().map(|_| person_uuid)
    }

    /// Attempt to link an existing Person account to an OAuth2 provider by verified email.
    /// Returns `Ok(Some(uuid))` if a match was found and linked, `Ok(None)` if no match.
    pub async fn handle_link_account_by_email(
        &self,
        provider_uuid: Uuid,
        claims: netidmd_lib::idm::authsession::handler_oauth2_client::ExternalUserClaims,
        eventid: Uuid,
        _client_auth_info: ClientAuthInfo,
    ) -> Result<Option<Uuid>, OperationError> {
        let _ = eventid;
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let maybe_uuid = idms_prox_write.find_and_link_account_by_email(provider_uuid, &claims)?;

        if let Some(person_uuid) = maybe_uuid {
            if let Err(e) = idms_prox_write.reconcile_upstream_memberships_for_provider(
                person_uuid,
                provider_uuid,
                &claims.groups,
            ) {
                warn!(
                    ?e,
                    ?provider_uuid,
                    ?person_uuid,
                    "reconcile_upstream_memberships failed during link-by-email; proceeding"
                );
            }
        }

        idms_prox_write.commit().map(|_| maybe_uuid)
    }

    /// Derive a unique Netidm username from external identity claims, performing
    /// collision resolution (_2…_100 suffix) if the preferred name is taken.
    pub async fn handle_derive_jit_username(
        &self,
        claims: netidmd_lib::idm::authsession::handler_oauth2_client::ExternalUserClaims,
        _client_auth_info: ClientAuthInfo,
    ) -> Result<String, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        idms_prox_write
            .derive_jit_username(&claims)
            .and_then(|name| idms_prox_write.commit().map(|_| name))
    }

    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_wg_tunnel_create(
        &self,
        _client_auth_info: ClientAuthInfo,
        req: netidm_proto::wg::WgTunnelCreate,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        idms_prox_write
            .wg_tunnel_create(&req)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_wg_tunnel_delete(
        &self,
        _client_auth_info: ClientAuthInfo,
        name: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        idms_prox_write
            .wg_tunnel_delete(&name)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_wg_token_create(
        &self,
        _client_auth_info: ClientAuthInfo,
        tunnel_name: String,
        req: netidm_proto::wg::WgTokenCreate,
        eventid: Uuid,
    ) -> Result<netidm_proto::wg::WgTokenCreatedResponse, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        // Resolve the tunnel UUID.
        let tunnel_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(tunnel_name.as_str())
            .map_err(|_| OperationError::NoMatchingEntries)?;
        let resp = idms_prox_write.wg_token_create(tunnel_uuid, &tunnel_name, &req)?;
        idms_prox_write.commit()?;
        Ok(resp)
    }

    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_wg_token_delete(
        &self,
        _client_auth_info: ClientAuthInfo,
        tunnel_name: String,
        token_name: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let tunnel_uuid = idms_prox_write
            .qs_write
            .name_to_uuid(tunnel_name.as_str())
            .map_err(|_| OperationError::NoMatchingEntries)?;
        idms_prox_write
            .wg_token_delete(tunnel_uuid, &token_name)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_wg_connect(
        &self,
        _client_auth_info: ClientAuthInfo,
        caller_name: String,
        req: netidm_proto::wg::WgConnectRequest,
        eventid: Uuid,
    ) -> Result<netidm_proto::wg::WgConnectResponse, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        let resp = idms_prox_write.wg_connect(&caller_name, &req, ct)?;
        idms_prox_write.commit()?;
        Ok(resp)
    }

    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_wg_update_last_seen(
        &self,
        peer_uuid: Uuid,
        ts: time::OffsetDateTime,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        idms_prox_write
            .wg_update_last_seen(peer_uuid, ts)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_wg_peer_delete(
        &self,
        _client_auth_info: ClientAuthInfo,
        peer_uuid: Uuid,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;
        idms_prox_write
            .wg_peer_delete(peer_uuid)
            .and_then(|_| idms_prox_write.commit())
    }

    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_saml_complete_login(
        &self,
        provider_name: String,
        encoded_response: String,
        request_id: String,
        eventid: Uuid,
    ) -> Result<compact_jwt::JwsCompact, OperationError> {
        let ct = duration_from_epoch_now();
        let mut idms_prox_write = self.idms.proxy_write(ct).await?;

        let provider = idms_prox_write
            .get_saml_client_provider_by_name(&provider_name)
            .ok_or(OperationError::NoMatchingEntries)?;

        let token =
            idms_prox_write.saml_complete_login(&provider, &encoded_response, &request_id, ct)?;

        idms_prox_write
            .commit()
            .map_err(|_| OperationError::InvalidState)?;

        Ok(token)
    }

    /// Add a post-logout redirect URI to the OAuth2 client's
    /// `OAuth2RsPostLogoutRedirectUri` allowlist. Idempotent: adding a URI
    /// already present succeeds with no side effect. Rejects malformed URIs
    /// (non-absolute, unparseable).
    ///
    /// # Errors
    /// * `OperationError::InvalidAttribute` — the URI does not parse as an
    ///   absolute URL.
    /// * `OperationError::NoMatchingEntries` — no OAuth2 client with the
    ///   given `client_name` exists.
    /// * Other `OperationError` variants from the underlying search/modify.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_oauth2_client_post_logout_redirect_uri_add(
        &self,
        client_auth_info: ClientAuthInfo,
        client_name: String,
        uri: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let _ = eventid;
        handle_oauth2_post_logout_uri_add(&self.idms, client_auth_info, client_name, uri).await
    }

    /// Remove a post-logout redirect URI from the OAuth2 client's allowlist.
    /// Idempotent: removing a URI not present returns `Ok(())` with no side
    /// effect.
    ///
    /// # Errors
    /// * `OperationError::InvalidAttribute` — the URI does not parse.
    /// * `OperationError::NoMatchingEntries` — no OAuth2 client with the
    ///   given `client_name` exists.
    /// * Other `OperationError` variants from the underlying search/modify.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_oauth2_client_post_logout_redirect_uri_remove(
        &self,
        client_auth_info: ClientAuthInfo,
        client_name: String,
        uri: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let _ = eventid;
        handle_oauth2_post_logout_uri_remove(&self.idms, client_auth_info, client_name, uri).await
    }

    /// Set (replace) the OAuth2 client's `OAuth2RsBackchannelLogoutUri`.
    /// Single-value: re-invoking replaces the previous URI. Rejects
    /// malformed URIs.
    ///
    /// # Errors
    /// * `OperationError::InvalidAttribute` — the URI does not parse.
    /// * `OperationError::NoMatchingEntries` — no OAuth2 client with the
    ///   given `client_name` exists.
    /// * Other `OperationError` variants from the underlying search/modify.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_oauth2_client_backchannel_logout_uri_set(
        &self,
        client_auth_info: ClientAuthInfo,
        client_name: String,
        uri: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let _ = eventid;
        handle_oauth2_backchannel_uri_set(&self.idms, client_auth_info, client_name, uri).await
    }

    /// Clear the OAuth2 client's `OAuth2RsBackchannelLogoutUri`. Idempotent:
    /// clearing an already-absent attribute returns `Ok(())` with no side
    /// effect.
    ///
    /// # Errors
    /// * `OperationError::NoMatchingEntries` — no OAuth2 client with the
    ///   given `client_name` exists.
    /// * Other `OperationError` variants from the underlying search/modify.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_oauth2_client_backchannel_logout_uri_clear(
        &self,
        client_auth_info: ClientAuthInfo,
        client_name: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let _ = eventid;
        handle_oauth2_backchannel_uri_clear(&self.idms, client_auth_info, client_name).await
    }

    /// Add a group mapping (`<upstream>:<group-uuid>`) to an OAuth2 upstream
    /// client. Rejects the operation if another mapping for the same
    /// `upstream` name already exists on the connector (FR-007a).
    ///
    /// # Errors
    /// * `OperationError::InvalidAttribute` — the supplied `netidm_group_uuid`
    ///   is not a valid UUID, or a mapping for `upstream` already exists on
    ///   this connector.
    /// * `OperationError::NoMatchingEntries` — no OAuth2 upstream client with
    ///   the given `client_name` exists.
    /// * Other `OperationError` variants from the underlying search/modify.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_oauth2_client_group_mapping_add(
        &self,
        client_auth_info: ClientAuthInfo,
        client_name: String,
        upstream: String,
        netidm_group_uuid: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        handle_group_mapping_add(
            &self.idms,
            client_auth_info,
            EntryClass::OAuth2Client,
            Attribute::OAuth2GroupMapping,
            client_name,
            upstream,
            netidm_group_uuid,
        )
        .await
    }

    /// Remove a group mapping by upstream name from an OAuth2 upstream client.
    /// If no mapping for `upstream` exists on the connector the call is a
    /// successful no-op (FR-007b — eagerness deferred to login-time reconcile).
    ///
    /// # Errors
    /// * `OperationError::NoMatchingEntries` — no OAuth2 upstream client with
    ///   the given `client_name` exists.
    /// * Other `OperationError` variants from the underlying search/modify.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_oauth2_client_group_mapping_remove(
        &self,
        client_auth_info: ClientAuthInfo,
        client_name: String,
        upstream: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        handle_group_mapping_remove(
            &self.idms,
            client_auth_info,
            EntryClass::OAuth2Client,
            Attribute::OAuth2GroupMapping,
            client_name,
            upstream,
        )
        .await
    }

    /// Add a group mapping (`<upstream>:<group-uuid>`) to a SAML upstream
    /// client. Rejects the operation if another mapping for the same
    /// `upstream` name already exists on the connector (FR-007a).
    ///
    /// # Errors
    /// Mirrors `handle_oauth2_client_group_mapping_add`.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_saml_client_group_mapping_add(
        &self,
        client_auth_info: ClientAuthInfo,
        client_name: String,
        upstream: String,
        netidm_group_uuid: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        handle_group_mapping_add(
            &self.idms,
            client_auth_info,
            EntryClass::SamlClient,
            Attribute::SamlGroupMapping,
            client_name,
            upstream,
            netidm_group_uuid,
        )
        .await
    }

    /// Remove a group mapping by upstream name from a SAML upstream client.
    /// If no mapping for `upstream` exists on the connector the call is a
    /// successful no-op (FR-007b).
    ///
    /// # Errors
    /// Mirrors `handle_oauth2_client_group_mapping_remove`.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_saml_client_group_mapping_remove(
        &self,
        client_auth_info: ClientAuthInfo,
        client_name: String,
        upstream: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        handle_group_mapping_remove(
            &self.idms,
            client_auth_info,
            EntryClass::SamlClient,
            Attribute::SamlGroupMapping,
            client_name,
            upstream,
        )
        .await
    }

    /// Set (replace) the SAML service provider's Single Logout Service
    /// URL. Single-value: re-invoking replaces the previous URL. Rejects
    /// malformed URLs.
    ///
    /// # Errors
    /// * `OperationError::InvalidAttribute` — the URL does not parse.
    /// * `OperationError::NoMatchingEntries` — no SAML client with the
    ///   given `client_name` exists.
    /// * Other `OperationError` variants from the underlying search/modify.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_saml_client_slo_url_set(
        &self,
        client_auth_info: ClientAuthInfo,
        client_name: String,
        url: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let _ = eventid;
        handle_saml_slo_url_set(&self.idms, client_auth_info, client_name, url).await
    }

    /// Clear the SAML service provider's Single Logout Service URL.
    /// Idempotent.
    ///
    /// # Errors
    /// * `OperationError::NoMatchingEntries` — no SAML client with the
    ///   given `client_name` exists.
    /// * Other `OperationError` variants from the underlying search/modify.
    #[instrument(level = "info", skip_all, fields(uuid = ?eventid))]
    pub async fn handle_saml_client_slo_url_clear(
        &self,
        client_auth_info: ClientAuthInfo,
        client_name: String,
        eventid: Uuid,
    ) -> Result<(), OperationError> {
        let _ = eventid;
        handle_saml_slo_url_clear(&self.idms, client_auth_info, client_name).await
    }
}

/// Shared implementation for the OAuth2 / SAML `add-group-mapping` handlers.
///
/// Encapsulates the identity validation, uniqueness check against the existing
/// mapping values, and modify-append into one place. The variant is selected
/// by `class` (`OAuth2Client` vs. `SamlClient`) and `attr`
/// (`OAuth2GroupMapping` vs. `SamlGroupMapping`).
/// Append a post-logout redirect URI to the named OAuth2 client's
/// `OAuth2RsPostLogoutRedirectUri` set. Idempotent: if the URI is already
/// present, commit and return `Ok(())` without producing a duplicate.
async fn handle_oauth2_post_logout_uri_add(
    idms: &std::sync::Arc<IdmServer>,
    client_auth_info: ClientAuthInfo,
    client_name: String,
    uri: String,
) -> Result<(), OperationError> {
    use url::Url;

    let parsed = Url::parse(uri.trim()).map_err(|_| {
        OperationError::InvalidAttribute(format!(
            "post_logout_redirect_uri '{}' is not a valid absolute URL",
            uri
        ))
    })?;

    let ct = duration_from_epoch_now();
    let mut idms_prox_write = idms.proxy_write(ct).await?;

    let ident = idms_prox_write
        .validate_client_auth_info_to_ident(client_auth_info, ct)
        .map_err(|e| {
            error!(err = ?e, "Invalid identity");
            e
        })?;

    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::OAuth2Client.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&client_name))
    ]));

    // Idempotent: if already present, commit and return Ok without modify.
    let entries = idms_prox_write.qs_write.internal_search(filter.clone())?;
    let entry = entries.first().ok_or(OperationError::NoMatchingEntries)?;
    if let Some(existing_set) = entry
        .get_ava_set(Attribute::OAuth2RsPostLogoutRedirectUri)
        .and_then(|vs| vs.as_url_set())
    {
        if existing_set.contains(&parsed) {
            return idms_prox_write.commit().map(|_| ());
        }
    }

    let ml = ModifyList::new_append(Attribute::OAuth2RsPostLogoutRedirectUri, Value::Url(parsed));

    let mdf = ModifyEvent::from_internal_parts(ident, &ml, &filter, &idms_prox_write.qs_write)
        .map_err(|e| {
            error!(err = ?e, "Failed to begin modify for post_logout_redirect_uri add");
            e
        })?;

    idms_prox_write
        .qs_write
        .modify(&mdf)
        .and_then(|_| idms_prox_write.commit().map(|_| ()))
}

/// Remove a post-logout redirect URI from the named OAuth2 client's
/// `OAuth2RsPostLogoutRedirectUri` set. Idempotent.
async fn handle_oauth2_post_logout_uri_remove(
    idms: &std::sync::Arc<IdmServer>,
    client_auth_info: ClientAuthInfo,
    client_name: String,
    uri: String,
) -> Result<(), OperationError> {
    use url::Url;

    let parsed = Url::parse(uri.trim()).map_err(|_| {
        OperationError::InvalidAttribute(format!(
            "post_logout_redirect_uri '{}' is not a valid absolute URL",
            uri
        ))
    })?;

    let ct = duration_from_epoch_now();
    let mut idms_prox_write = idms.proxy_write(ct).await?;

    let ident = idms_prox_write
        .validate_client_auth_info_to_ident(client_auth_info, ct)
        .map_err(|e| {
            error!(err = ?e, "Invalid identity");
            e
        })?;

    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::OAuth2Client.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&client_name))
    ]));

    let ml = ModifyList::new_remove(
        Attribute::OAuth2RsPostLogoutRedirectUri,
        PartialValue::Url(parsed),
    );

    let mdf = ModifyEvent::from_internal_parts(ident, &ml, &filter, &idms_prox_write.qs_write)
        .map_err(|e| {
            error!(err = ?e, "Failed to begin modify for post_logout_redirect_uri remove");
            e
        })?;

    idms_prox_write
        .qs_write
        .modify(&mdf)
        .and_then(|_| idms_prox_write.commit().map(|_| ()))
}

/// Set the OAuth2 client's back-channel logout endpoint URI. Purges any
/// existing value — this attribute is single-value at the schema level.
async fn handle_oauth2_backchannel_uri_set(
    idms: &std::sync::Arc<IdmServer>,
    client_auth_info: ClientAuthInfo,
    client_name: String,
    uri: String,
) -> Result<(), OperationError> {
    use url::Url;

    let parsed = Url::parse(uri.trim()).map_err(|_| {
        OperationError::InvalidAttribute(format!(
            "backchannel_logout_uri '{}' is not a valid absolute URL",
            uri
        ))
    })?;

    let ct = duration_from_epoch_now();
    let mut idms_prox_write = idms.proxy_write(ct).await?;

    let ident = idms_prox_write
        .validate_client_auth_info_to_ident(client_auth_info, ct)
        .map_err(|e| {
            error!(err = ?e, "Invalid identity");
            e
        })?;

    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::OAuth2Client.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&client_name))
    ]));

    // Single-value: purge first, then append, within one modify list.
    let ml = ModifyList::new_list(vec![
        Modify::Purged(Attribute::OAuth2RsBackchannelLogoutUri),
        Modify::Present(Attribute::OAuth2RsBackchannelLogoutUri, Value::Url(parsed)),
    ]);

    let mdf = ModifyEvent::from_internal_parts(ident, &ml, &filter, &idms_prox_write.qs_write)
        .map_err(|e| {
            error!(err = ?e, "Failed to begin modify for backchannel_logout_uri set");
            e
        })?;

    idms_prox_write
        .qs_write
        .modify(&mdf)
        .and_then(|_| idms_prox_write.commit().map(|_| ()))
}

/// Clear the OAuth2 client's back-channel logout endpoint URI. Idempotent.
async fn handle_oauth2_backchannel_uri_clear(
    idms: &std::sync::Arc<IdmServer>,
    client_auth_info: ClientAuthInfo,
    client_name: String,
) -> Result<(), OperationError> {
    let ct = duration_from_epoch_now();
    let mut idms_prox_write = idms.proxy_write(ct).await?;

    let ident = idms_prox_write
        .validate_client_auth_info_to_ident(client_auth_info, ct)
        .map_err(|e| {
            error!(err = ?e, "Invalid identity");
            e
        })?;

    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::OAuth2Client.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&client_name))
    ]));

    let ml = ModifyList::new_purge(Attribute::OAuth2RsBackchannelLogoutUri);

    let mdf = ModifyEvent::from_internal_parts(ident, &ml, &filter, &idms_prox_write.qs_write)
        .map_err(|e| {
            error!(err = ?e, "Failed to begin modify for backchannel_logout_uri clear");
            e
        })?;

    idms_prox_write
        .qs_write
        .modify(&mdf)
        .and_then(|_| idms_prox_write.commit().map(|_| ()))
}

/// Enumerate every non-revoked `UserAuthTokenSession` value on the target
/// Person entry and funnel each through
/// [`netidmd_lib::idm::logout::terminate_session`]. Returns the count of
/// sessions actually terminated. Already-revoked sessions are skipped.
///
/// Shared by the US5 self-service and admin actor handlers.
fn terminate_all_sessions_for(
    idms_prox_write: &mut netidmd_lib::idm::server::IdmServerProxyWriteTransaction<'_>,
    target_uuid: Uuid,
) -> Result<usize, OperationError> {
    use netidmd_lib::idm::logout::terminate_session;
    use netidmd_lib::value::SessionState;

    let entry = idms_prox_write
        .qs_write
        .internal_search_uuid(target_uuid)
        .map_err(|e| {
            error!(err = ?e, "Failed to load target entry for logout-all");
            e
        })?;

    let session_ids: Vec<Uuid> = entry
        .get_ava_as_session_map(Attribute::UserAuthTokenSession)
        .map(|map| {
            map.iter()
                .filter_map(|(sid, session)| match session.state {
                    SessionState::RevokedAt(_) => None,
                    _ => Some(*sid),
                })
                .collect()
        })
        .unwrap_or_default();

    let mut terminated: usize = 0;
    for sid in session_ids {
        terminate_session(idms_prox_write, target_uuid, sid)?;
        terminated += 1;
    }
    Ok(terminated)
}

/// Set the SAML SP's Single Logout Service URL (single-value).
async fn handle_saml_slo_url_set(
    idms: &std::sync::Arc<IdmServer>,
    client_auth_info: ClientAuthInfo,
    client_name: String,
    url: String,
) -> Result<(), OperationError> {
    use url::Url;

    let parsed = Url::parse(url.trim()).map_err(|_| {
        OperationError::InvalidAttribute(format!(
            "saml_single_logout_service_url '{}' is not a valid absolute URL",
            url
        ))
    })?;

    let ct = duration_from_epoch_now();
    let mut idms_prox_write = idms.proxy_write(ct).await?;

    let ident = idms_prox_write
        .validate_client_auth_info_to_ident(client_auth_info, ct)
        .map_err(|e| {
            error!(err = ?e, "Invalid identity");
            e
        })?;

    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::SamlClient.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&client_name))
    ]));

    let ml = ModifyList::new_list(vec![
        Modify::Purged(Attribute::SamlSingleLogoutServiceUrl),
        Modify::Present(Attribute::SamlSingleLogoutServiceUrl, Value::Url(parsed)),
    ]);

    let mdf = ModifyEvent::from_internal_parts(ident, &ml, &filter, &idms_prox_write.qs_write)
        .map_err(|e| {
            error!(err = ?e, "Failed to begin modify for saml SLO URL set");
            e
        })?;

    idms_prox_write
        .qs_write
        .modify(&mdf)
        .and_then(|_| idms_prox_write.commit().map(|_| ()))
}

/// Clear the SAML SP's Single Logout Service URL. Idempotent.
async fn handle_saml_slo_url_clear(
    idms: &std::sync::Arc<IdmServer>,
    client_auth_info: ClientAuthInfo,
    client_name: String,
) -> Result<(), OperationError> {
    let ct = duration_from_epoch_now();
    let mut idms_prox_write = idms.proxy_write(ct).await?;

    let ident = idms_prox_write
        .validate_client_auth_info_to_ident(client_auth_info, ct)
        .map_err(|e| {
            error!(err = ?e, "Invalid identity");
            e
        })?;

    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, EntryClass::SamlClient.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&client_name))
    ]));

    let ml = ModifyList::new_purge(Attribute::SamlSingleLogoutServiceUrl);

    let mdf = ModifyEvent::from_internal_parts(ident, &ml, &filter, &idms_prox_write.qs_write)
        .map_err(|e| {
            error!(err = ?e, "Failed to begin modify for saml SLO URL clear");
            e
        })?;

    idms_prox_write
        .qs_write
        .modify(&mdf)
        .and_then(|_| idms_prox_write.commit().map(|_| ()))
}

async fn handle_group_mapping_add(
    idms: &std::sync::Arc<IdmServer>,
    client_auth_info: ClientAuthInfo,
    class: EntryClass,
    attr: Attribute,
    client_name: String,
    upstream: String,
    netidm_group_uuid: String,
) -> Result<(), OperationError> {
    use std::str::FromStr;

    let ct = duration_from_epoch_now();
    let mut idms_prox_write = idms.proxy_write(ct).await?;

    let ident = idms_prox_write
        .validate_client_auth_info_to_ident(client_auth_info, ct)
        .map_err(|e| {
            error!(err = ?e, "Invalid identity");
            e
        })?;

    // Validate the supplied UUID before we go any further — rejects early
    // with a clear error instead of storing garbage.
    let _parsed = Uuid::from_str(netidm_group_uuid.trim()).map_err(|_| {
        OperationError::InvalidAttribute(format!(
            "netidm_group_uuid '{}' is not a valid UUID",
            netidm_group_uuid
        ))
    })?;

    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, class.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&client_name))
    ]));

    // Load the existing entry and check for a prefix collision on `upstream`.
    let entries = idms_prox_write.qs_write.internal_search(filter.clone())?;
    let entry = entries.first().ok_or(OperationError::NoMatchingEntries)?;

    if let Some(existing) = entry.get_ava_set(&attr).and_then(|vs| vs.as_utf8_iter()) {
        for value in existing {
            if let Some((existing_upstream, _)) = value.rsplit_once(':') {
                if existing_upstream == upstream {
                    return Err(OperationError::InvalidAttribute(format!(
                        "mapping for upstream '{}' already exists on connector '{}'; \
                         remove it first to change it",
                        upstream, client_name
                    )));
                }
            }
        }
    }

    // Construct the stored value and append via a modify-event.
    let new_value = format!("{}:{}", upstream, netidm_group_uuid.trim());
    let ml = ModifyList::new_append(attr, Value::new_utf8s(&new_value));

    let mdf = match ModifyEvent::from_internal_parts(ident, &ml, &filter, &idms_prox_write.qs_write)
    {
        Ok(m) => m,
        Err(e) => {
            error!(err = ?e, "Failed to begin modify for group-mapping add");
            return Err(e);
        }
    };

    idms_prox_write
        .qs_write
        .modify(&mdf)
        .and_then(|_| idms_prox_write.commit().map(|_| ()))
}

/// Shared implementation for the OAuth2 / SAML `remove-group-mapping`
/// handlers. Idempotent: removing a non-existent mapping returns `Ok(())`
/// with no side effect.
async fn handle_group_mapping_remove(
    idms: &std::sync::Arc<IdmServer>,
    client_auth_info: ClientAuthInfo,
    class: EntryClass,
    attr: Attribute,
    client_name: String,
    upstream: String,
) -> Result<(), OperationError> {
    let ct = duration_from_epoch_now();
    let mut idms_prox_write = idms.proxy_write(ct).await?;

    let ident = idms_prox_write
        .validate_client_auth_info_to_ident(client_auth_info, ct)
        .map_err(|e| {
            error!(err = ?e, "Invalid identity");
            e
        })?;

    let filter = filter_all!(f_and!([
        f_eq(Attribute::Class, class.into()),
        f_eq(Attribute::Name, PartialValue::new_iname(&client_name))
    ]));

    // Load the entry and find the full value whose upstream prefix matches.
    let entries = idms_prox_write.qs_write.internal_search(filter.clone())?;
    let entry = entries.first().ok_or(OperationError::NoMatchingEntries)?;

    let matching_value = entry
        .get_ava_set(&attr)
        .and_then(|vs| vs.as_utf8_iter())
        .and_then(|mut iter| {
            iter.find(|value| {
                value
                    .rsplit_once(':')
                    .map(|(name, _)| name == upstream)
                    .unwrap_or(false)
            })
            .map(str::to_string)
        });

    let Some(full_value) = matching_value else {
        // Idempotent no-op: nothing to remove.
        idms_prox_write.commit().map(|_| ())?;
        return Ok(());
    };

    let ml = ModifyList::new_remove(attr, PartialValue::new_utf8s(&full_value));

    let mdf = match ModifyEvent::from_internal_parts(ident, &ml, &filter, &idms_prox_write.qs_write)
    {
        Ok(m) => m,
        Err(e) => {
            error!(err = ?e, "Failed to begin modify for group-mapping remove");
            return Err(e);
        }
    };

    idms_prox_write
        .qs_write
        .modify(&mdf)
        .and_then(|_| idms_prox_write.commit().map(|_| ()))
}
