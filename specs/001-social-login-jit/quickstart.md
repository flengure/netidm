# Quickstart: Social Login with JIT Provisioning

**Branch**: `001-social-login-jit` | **Date**: 2026-04-16

This guide validates the feature end-to-end after implementation.

---

## Prerequisites

- Kanidm server running locally with admin access
- GitHub OAuth App created at https://github.com/settings/developers
  - Callback URL: `https://<kanidm-host>/ui/login/oauth2_landing`
- OR Google OAuth2 credentials from Google Cloud Console
  - Authorized redirect URI: `https://<kanidm-host>/ui/login/oauth2_landing`

---

## Setup: GitHub Provider

```bash
# 1. Register the provider
kanidm system oauth2 create-github mygithub <CLIENT_ID> <CLIENT_SECRET> -H https://localhost:8443 -D admin

# 2. Add the callback URL
kanidm system oauth2 add-redirect-url mygithub https://localhost:8443/ui/login/oauth2_landing \
  -H https://localhost:8443 -D admin

# 3. Enable JIT provisioning
kanidm system oauth2 enable-jit-provisioning mygithub -H https://localhost:8443 -D admin

# 4. Verify configuration
kanidm system oauth2 get mygithub -H https://localhost:8443 -D admin
# Expect: jit_provisioning: true, userinfo_endpoint set, claim maps present
```

---

## Setup: Google Provider

```bash
kanidm system oauth2 create-google mygoogle <CLIENT_ID> <CLIENT_SECRET> -H https://localhost:8443 -D admin
kanidm system oauth2 add-redirect-url mygoogle https://localhost:8443/ui/login/oauth2_landing \
  -H https://localhost:8443 -D admin
kanidm system oauth2 enable-jit-provisioning mygoogle -H https://localhost:8443 -D admin
```

---

## Validation: First-Time Login (Happy Path)

1. Open a browser and navigate to `https://localhost:8443/ui/login`
2. Click "Sign in with GitHub" (or Google) — should appear in the login UI
3. Complete authentication at the provider
4. **Expect**: Redirected to `/ui/login/provision` showing a confirmation page with:
   - Pre-filled proposed username (from GitHub `login` / Google email local-part)
   - Display name (from provider)
   - Email (if available)
5. Confirm or edit the username, click "Create my account"
6. **Expect**: Redirected to the Kanidm home/app page — logged in
7. Verify account was created:
   ```bash
   kanidm account get <proposed-username> -H https://localhost:8443 -D admin
   # Expect: account exists with correct displayName, mail (if available)
   ```

---

## Validation: Returning User

1. Log out
2. Click "Sign in with GitHub" again using the same GitHub account
3. **Expect**: No confirmation page shown — logged in directly to the existing account
4. Verify no duplicate account was created

---

## Validation: JIT Disabled

```bash
kanidm system oauth2 disable-jit-provisioning mygithub -H https://localhost:8443 -D admin
```

1. Attempt first-time login with a new GitHub account (never logged in before)
2. **Expect**: Login denied with message "Account provisioning is not enabled for this provider."

---

## Validation: Username Collision

1. Pre-create an account with the same username as your GitHub `login`:
   ```bash
   kanidm person create <your-github-login> "Test Collision" -H https://localhost:8443 -D admin
   ```
2. Attempt first-time GitHub login
3. **Expect**: Confirmation page shows a suggested alternate username (e.g. `<login>_2`)
4. Confirm and verify the account is created with the alternate username

---

## Validation: Abandoned Confirmation Page

1. Trigger a first-time social login → reach the confirmation page
2. Close the browser tab without submitting
3. Wait 10+ minutes
4. Attempt the same social login again
5. **Expect**: A fresh confirmation page appears (previous session cleanly expired, no errors)

---

## Tests

```bash
# Run all tests
cargo test

# Run specific integration test module (once written)
cargo test --test oauth2_jit_provisioning
```
