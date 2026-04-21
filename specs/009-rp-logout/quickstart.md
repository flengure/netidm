# Quickstart — PR-RP-LOGOUT

Manual smoke-test scenarios for this feature. Each scenario maps to an acceptance scenario in `spec.md`; they are intended to be run against a live netidmd after the feature ships, either locally or in staging. `/speckit-implement` produces unit + integration tests that cover the same logic — quickstart is the manual equivalent for tag-time verification (spec task T048-analogue).

All scenarios assume a running `netidmd` at `https://idm.example.test` with at least one person (`alice`), admin access via `netidm login`, and a pre-created test OAuth2 client (`portainer`) with redirect URI `https://portainer.example.test/oauth2/callback`.

---

## Scenario 1 — OIDC end-session round-trip

**Maps to**: US1 acceptance scenario 1; SC-001.

1. `netidm system oauth2-client add-post-logout-redirect-uri portainer https://portainer.example.test/logout`
2. In a browser, complete a normal OIDC login to the `portainer` client. Capture the ID token from the token response.
3. Visit
   `https://idm.example.test/oauth2/openid/portainer/end_session_endpoint?id_token_hint=<id_token>&post_logout_redirect_uri=https%3A%2F%2Fportainer.example.test%2Flogout&state=abc123`
4. **Expect**: browser ends at `https://portainer.example.test/logout?state=abc123`.
5. Open a new tab to `https://idm.example.test/` — should prompt for auth (session ended).
6. Attempt to use any refresh token that was paired with the ID token — `/oauth2/token` returns `invalid_grant`.

---

## Scenario 2 — Unregistered redirect → confirmation page

**Maps to**: US1 acceptance scenario 3; SC-002.

1. Attempt a logout using a `post_logout_redirect_uri` that is NOT in the allowlist:
   `…/oauth2/openid/portainer/end_session_endpoint?id_token_hint=<id_token>&post_logout_redirect_uri=https%3A%2F%2Fevil.example.test%2F`
2. **Expect**: HTTP 200 with `Content-Type: text/html`; the body is the `logged_out.html` template. Browser stays on the netidm origin.
3. `evil.example.test` is never visited (check browser dev tools network panel).
4. The netidm session is still terminated (confirmed by step 5 of Scenario 1).

---

## Scenario 3 — Malformed ID token → confirmation page, no redirect

**Maps to**: US1 acceptance scenario 4.

1. Craft a request with `id_token_hint=garbage.invalid.token`.
2. **Expect**: HTTP 200 with the confirmation page. No redirect even if `post_logout_redirect_uri=…` is supplied.

---

## Scenario 4 — Back-channel logout delivery

**Maps to**: US3 acceptance scenario 1; SC-003.

1. Stand up a small HTTP endpoint on the same machine that logs incoming POST bodies to stdout:
   `python3 -m http.server 9090 --bind 127.0.0.1` (and pipe requests to a log).
2. `netidm system oauth2-client set-backchannel-logout-uri portainer http://127.0.0.1:9090/bcl`
3. Perform Scenario 1 end-to-end.
4. Within 1 second of the logout, the test HTTP endpoint receives a POST to `/bcl` with `Content-Type: application/x-www-form-urlencoded` and body `logout_token=<jws>`.
5. Decode the JWS (e.g. `jwt decode <token>` or `python -c "import jwt; ..."`). **Expect** claims:
   - `iss = https://idm.example.test/oauth2/openid/portainer`
   - `aud = portainer`
   - `sub = <alice's uuid>`
   - `sid = <the UAT uuid that was terminated>`
   - `events = {"http://schemas.openid.net/event/backchannel-logout": {}}`
   - `typ` header = `logout+jwt`

---

## Scenario 5 — Back-channel endpoint unreachable → retry then fail

**Maps to**: US3 acceptance scenario 5; SC-004; SC-008.

1. Configure `OAuth2RsBackchannelLogoutUri` to a URL that refuses connections: `http://127.0.0.1:1/bcl`.
2. Perform Scenario 1.
3. **Expect**: the user's browser logout completes on time (no hang). `netidm logout-deliveries list --pending` shows the pending record with `attempts >= 1` and a `next_attempt` in the near future.
4. Wait ≈ 24 h (or manipulate `next_attempt` via DB to exercise the final failure transition). The record moves to `failed`; `netidm logout-deliveries list --failed` shows it.
5. **Restart** netidmd mid-scenario (between retry attempts). **Expect**: on next boot, the worker picks up the `pending` record and continues attempting — no records lost.

---

## Scenario 6 — SAML SLO (SessionIndex present)

**Maps to**: US4 acceptance scenario 1; SC-005.

1. Register a test SamlClient (`gitea-saml`); complete a normal SAML SSO login, noting the `SessionIndex` value emitted in the `<AuthnStatement>`.
2. Have the SP (or a test tool like `samltest.id`) issue a signed `<LogoutRequest>` containing:
   - `<saml:NameID>` = alice
   - `<samlp:SessionIndex>` = the captured value
3. Send via SOAP binding to `https://idm.example.test/saml/gitea-saml/slo/soap`.
4. **Expect**: a signed `<LogoutResponse>` with `<StatusCode>Success</StatusCode>`. Alice's netidm session ends. Other sessions alice has (if any) at other SPs remain.

---

## Scenario 7 — SAML SLO (SessionIndex absent)

**Maps to**: US4 acceptance scenario 2.

1. Alice has two active SAML sessions at `gitea-saml` (two browsers). Each has a distinct `SessionIndex`.
2. Send a signed `<LogoutRequest>` with `<NameID>alice</NameID>` and NO `<SessionIndex>`.
3. **Expect**: both sessions at `gitea-saml` are terminated. Any sessions alice has at *other* SPs remain active.

---

## Scenario 8 — SAML SLO signature invalid → no session ends

**Maps to**: US4 acceptance scenario 3.

1. Tamper with a previously valid `<LogoutRequest>` so the signature no longer verifies.
2. Send it.
3. **Expect**: signed `<LogoutResponse>` with `<StatusCode>Responder</StatusCode>`. Alice's SAML sessions are all still active.

---

## Scenario 9 — SAML SessionIndex backfill covers pre-existing sessions

**Maps to**: SC-009.

1. On a DL25 netidmd (before the migration), have alice log in to `gitea-saml` — at this point SessionIndex emission doesn't exist.
2. Upgrade the DB to DL26 (run netidmd with DL26 code). Migration runs.
3. `netidm person show alice` (with enough verbosity) lists alice's now-active SAML sessions; each has a non-empty `SessionIndex`.
4. Issue a `<LogoutRequest>` from `gitea-saml` carrying that backfilled `SessionIndex` → session ends (Scenario 6 semantics).

---

## Scenario 10 — Self-service log out everywhere (US5)

**Maps to**: US5 acceptance scenario 1.

1. As alice, log in from three browsers (laptop, phone, work machine). Verify via `netidm self list-sessions` (or equivalent) that three UATs exist.
2. `netidm self logout-all`
3. **Expect**: `Terminated 3 sessions.` All three browsers are now logged out of netidm on next request.
4. The CLI auth token used for this very call is now invalid — the next `netidm` command prompts for a fresh login.

---

## Scenario 11 — Admin log out everywhere (US5 admin path)

**Maps to**: US5 acceptance scenario 3.

1. Alice is suspected compromised. As admin: `netidm person logout-all alice`
2. **Expect**: `Terminated N sessions for alice (<uuid>).`
3. Alice's next request from any browser prompts for fresh auth.

---

## Scenario 12 — Delivery-queue admin inspection

**Maps to**: FR-009, SC-004.

1. Generate some deliveries by completing Scenario 4 (success) and Scenario 5 (failing).
2. `netidm logout-deliveries list --succeeded` — shows the successful one.
3. `netidm logout-deliveries list --failed` — shows the eventually-failed one.
4. `netidm logout-deliveries show <uuid>` on the failed record — shows endpoint, attempt count, claim set.

---

## Smoke-test exit criteria

All 12 scenarios above complete without surprises. None of them should require any test tooling beyond a browser, `curl`, a minimal local HTTP server, and the `netidm` CLI.

`cargo test` (default features) must pass. `cargo clippy --all-features -- -D warnings` clean. `cargo fmt --check` clean.
