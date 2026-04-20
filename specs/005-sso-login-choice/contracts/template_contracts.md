# Template Contracts: SSO Login Choice UX

**Branch**: `005-sso-login-choice`
**Phase**: 1 — Design

## login.html — Modified Structure

Template path: `server/core/templates/login.html`

### When SSO providers are configured (FR-001, FR-003, FR-004, FR-006)

```html
(% extends "login_base.html" %)
(% block logincontainer %)

(% if let Some(error) = display_ctx.error %)
  <div class="alert alert-danger" role="alert">(( error ))</div>
(% endif %)

(% if !display_ctx.available_sso_providers.is_empty() %)
  <div id="sso-section">
    (% for provider in display_ctx.available_sso_providers %)
    <a href="/ui/sso/(( provider.name ))" class="btn btn-outline-secondary w-100 mb-2">
      (% if let Some(logo) = provider.logo_uri %)
        <img src="(( logo ))" alt="" class="sso-logo me-2" height="20" />
      (% endif %)
      Sign in with (( provider.display_name ))
    </a>
    (% endfor %)
  </div>

  <div class="d-flex align-items-center my-3">
    <hr class="flex-grow-1" />
    <span class="mx-2 text-muted small">or</span>
    <hr class="flex-grow-1" />
  </div>

  <button
    type="button"
    class="btn btn-link p-0 mb-3"
    id="toggle-internal-auth"
    onclick="document.getElementById('internal-auth').classList.toggle('d-none')"
  >Use internal authentication</button>
(% endif %)

<div id="internal-auth" (% if !display_ctx.available_sso_providers.is_empty() && !display_ctx.show_internal_first %) class="d-none"(% endif %)>
  <label for="username" class="form-label">Username</label>
  <form id="login" action="/ui/login/begin" method="post">
    <!-- existing form fields unchanged -->
    ...
  </form>
</div>

(% endblock %)
```

### Contract rules

| Condition | Rendered output |
|-----------|----------------|
| `available_sso_providers` is empty | Only the username form — identical to current page. No SSO section, no divider, no toggle. |
| `available_sso_providers` has 1+ providers, `show_internal_first` false | SSO buttons first, divider, toggle button, username form hidden (`d-none`) |
| `available_sso_providers` has 1+ providers, `show_internal_first` true | SSO buttons first, divider, toggle button, username form visible (no `d-none`) |
| Provider has `logo_uri` | `<img>` rendered inside button |
| Provider has no `logo_uri` | Button renders text only — no broken image placeholder |

### `LoginView` — New Field

```rust
struct LoginView {
    display_ctx: LoginDisplayCtx,
    username: String,
    remember_me: bool,
    show_internal_first: bool,   // NEW: derived from COOKIE_AUTH_METHOD_PREF == "internal"
}
```

---

## login_base.html — Unchanged

No changes to `server/core/templates/login_base.html`.

---

## Mobile Viewport Contract (FR-009)

SSO buttons use `w-100` Bootstrap class (full-width block). No horizontal overflow possible. Touch targets: Bootstrap's `btn` class ensures minimum 44px height. Verified via browser devtools mobile emulation.
