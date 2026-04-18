# Quickstart: SSO Login Choice UX Validation

**Branch**: `005-sso-login-choice`
**Phase**: 1 — Design

## Prerequisites

```bash
# Start netidmd from server/daemon/
cargo build -p netidm_server_daemon -p netidm
cd server/daemon && cargo run -- ...

# Create a test OAuth2 client provider
./target/debug/netidm \
  --url https://localhost:8443 \
  --accept-invalid-certs \
  login -D admin -C /tmp/netidm-dev/chain.pem

./target/debug/netidm \
  --url https://localhost:8443 \
  --accept-invalid-certs \
  oauth2-client create \
  --name github-test \
  --client-id test-client-id \
  --client-secret test-secret \
  --auth-url https://github.com/login/oauth/authorize \
  --token-url https://github.com/login/oauth/access_token
```

---

## Scenario 1: Login page with SSO provider configured (US1, FR-001)

```bash
# Load the login page
curl -s https://localhost:8443/ui/login --insecure | grep -i "sso\|provider\|github"
```

**Expected**: HTML contains a button/link with text "Sign in with github-test" (or its display name).

**Browser test**: Navigate to `https://localhost:8443/ui/login`. The "Sign in with github-test" button must appear ABOVE the "Use internal authentication" toggle. The username form must not be immediately visible.

---

## Scenario 2: Login page with no SSO providers (US1, FR-005)

```bash
# Remove all OAuth2 client providers or test on a fresh instance with none configured
curl -s https://localhost:8443/ui/login --insecure | grep -i "sso\|provider\|internal authentication"
```

**Expected**: HTML does NOT contain "Sign in with", "Use internal authentication", or a divider. Page renders identically to the current login page — only the username form is visible.

---

## Scenario 3: SSO button redirects to provider (US1, FR-003)

```bash
# Click the SSO button (follow redirect)
curl -v https://localhost:8443/ui/sso/github-test --insecure 2>&1 | grep "< Location"
```

**Expected**: `302` redirect with `Location` pointing to `https://github.com/login/oauth/authorize?client_id=...&state=...&redirect_uri=...`

---

## Scenario 4: Unknown provider returns 404 (security boundary)

```bash
curl -v https://localhost:8443/ui/sso/nonexistent --insecure 2>&1 | grep "< HTTP"
```

**Expected**: `404 Not Found`

---

## Scenario 5: "Use internal authentication" toggle reveals username form (US1, FR-004, FR-006)

**Browser test only** (requires JavaScript):
1. Navigate to `https://localhost:8443/ui/login`
2. SSO section is visible; username form is hidden
3. Click "Use internal authentication"
4. Username form becomes visible — NO full page reload (URL stays the same, page content expands inline)

---

## Scenario 6: `?next=` preserved through SSO flow (FR-007)

```bash
# Initiate SSO with a next parameter
curl -v "https://localhost:8443/ui/sso/github-test?next=/ui/apps" --insecure 2>&1 | grep -E "< Location|Set-Cookie.*next"
```

**Expected**: `302` to provider auth URL AND `Set-Cookie` containing the next path cookie.

---

## Scenario 7: Remembered internal auth preference (US2, FR-010)

**Browser test**:
1. Log in using internal auth (username + password)
2. Log out
3. Navigate to `https://localhost:8443/ui/login`

**Expected**: Username form is immediately visible (not hidden behind the toggle). SSO provider buttons are still accessible but the form is pre-expanded.

**Cookie check**:
```bash
# Inspect auth_method_pref cookie after internal login
# (use browser devtools Application → Cookies → localhost)
# Should see: auth_method_pref = "internal"
```

---

## Scenario 8: SSO button branding (US3, FR-002, FR-008)

```bash
# Set display name on the provider
./target/debug/netidm oauth2-client set-display-name github-test "GitHub"

# Load login page and verify button text
curl -s https://localhost:8443/ui/login --insecure | grep "Sign in with GitHub"
```

**Expected**: Button label shows "GitHub", not "github-test".

---

## Scenario 9: Mobile viewport (FR-009)

**Browser test**: Open `https://localhost:8443/ui/login` in Chrome DevTools with iPhone SE viewport (375×667).

**Expected**: SSO buttons fill full width, no horizontal scrollbar, all text readable, touch targets at minimum 44px height.

---

## Regression: Existing internal auth flows (SC-003)

```bash
# Full internal auth flow still works
curl -v -c /tmp/cookies.txt -b /tmp/cookies.txt \
  -X POST https://localhost:8443/ui/login/begin \
  --data "username=idm_admin" \
  --insecure
# Follow through TOTP / password steps as normal
```

**Expected**: All existing auth paths (password, TOTP, passkey, backup code) complete without regression.
