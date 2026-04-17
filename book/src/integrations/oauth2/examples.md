# Example OAuth2 Configurations

> [!WARNING]
>
> Web applications that authenticate with Netidm **must** be served over HTTPS.

> [!TIP]
>
> More examples can be found in the
> [Show and tell category](https://github.com/flengure/netidm/discussions/categories/show-and-tell) of Netidm's GitHub
> discussions.

## Apache `mod_auth_openidc`

Add the following to a `mod_auth_openidc.conf`. It should be included in a `mods_enabled` folder or with an appropriate
include.

```conf
# NB: may be just path, reduces copy-paste
OIDCRedirectURI /oauth2/callback
OIDCCryptoPassphrase <random password here>
OIDCProviderMetadataURL https://idm.example.com/oauth2/openid/<client name>/.well-known/openid-configuration
OIDCScope "openid"
OIDCUserInfoTokenMethod authz_header
OIDCClientID <client name>
OIDCClientSecret <client password>
OIDCPKCEMethod S256
OIDCCookieSameSite On
# Set the `REMOTE_USER` field to the `preferred_username` instead of the UUID.
# Remember that the username can change, but this can help with systems like Nagios which use this as a display name.
# OIDCRemoteUserClaim preferred_username
```

Other scopes can be added as required to the `OIDCScope` line, eg: `OIDCScope "openid scope2 scope3"`

In the virtual host, to handle OIDC redirect, a special location _must_ be defined:

```apache
# NB: you must allocate this virtual location matching OIDCRedirectURI and allow it for _any valid user_
<Location /oauth2/callback>
    AuthType openid-connect
    Require valid-user
</Location>
```

In the virtual host, to protect a location/directory
[see wiki](https://github.com/OpenIDC/mod_auth_openidc/wiki/Authorization):

```apache
<Directory /foo>
    AuthType openid-connect

    # you can authorize by the groups if you requested OIDCScope "openid groups"
    # Require claim groups:<spn | uuid>
    Require claim groups:apache_access_allowed@example.com

    # or authorize by exact preferred_username
    # Require user john.doe
</Directory>
```

## Gitea

[Gitea](https://docs.gitea.com/) is a painless, self-hosted, all-in-one software development service. It has built in
support for [external authentication](https://docs.gitea.com/administration/authentication) including OAuth2.

To set up a Gitea instance to authenticate with Netidm:

1. Add an email address to your regular Netidm account, if it doesn't have one already:

   ```sh
   netidm person update your_username -m your_username@example.com
   ```

2. Create a new Netidm group for your Gitea users (`gitea_users`), and add your regular account to it:

   ```sh
   netidm group create gitea_users
   netidm group add-members gitea_users your_username
   ```

3. Create a new OAuth2 application configuration in Netidm (`gitea`), configure the redirect URL, and scope access to
   the `gitea_users` group:

   ```sh
   netidm system oauth2 create gitea Gitea https://gitea.example.com/user/login
   netidm system oauth2 add-redirect-url gitea https://gitea.example.com/user/oauth2/netidm/callback
   netidm system oauth2 update-scope-map gitea gitea_users email openid profile groups
   ```

4. Gitea currently [does not support PKCE](https://github.com/go-gitea/gitea/issues/21376) in their OIDC implementation.
   If you do not perform this step, you will see an error like
   `No PKCE code challenge was provided with client in enforced PKCE mode.` in your Netidm server logs. Therefore, we
   have to disable PKCE for Gitea:

   ```sh
   netidm system oauth2 warning-insecure-client-disable-pkce gitea
   ```

5. Get the `gitea` OAuth2 client secret from Netidm:

   ```sh
   netidm system oauth2 show-basic-secret gitea
   ```

6. Log in to Gitea with an administrator account and go to Site Administration -> Identity & Access -> Authentication
   Sources, and "Add Authentication Source", then provide the following details:
   - **Type**: `OAuth2`
   - **Name**: `netidm`, in case you want to choose a different name, make sure to update `netidm` in the redirect URL
     in step 3. The full redirect URL is provided at the bottom of the current configuration page in Gitea.
   - **OAuth2 Provider**: `OpenID Connect`
   - **Client ID (key)**: `gitea`
   - **Client Secret**: [from show-basic-secret above]
   - **OpenID Connect Auto Discovery URL**:
     `https://idm.example.com/oauth2/openid/gitea/.well-known/openid-configuration`

   Alternatively, you can provide the configuration via the CLI:

   ```sh
   gitea admin auth add-oauth \
       --provider=openidConnect \
       --name=netidm \
       --key=gitea \
       --secret=[from show-basic-secret above] \
       --auto-discover-url=https://idm.example.com/oauth2/openid/gitea/.well-known/openid-configuration \
   ```

You should now see a "Sign in with Netidm" button on your Gitea login page.

You may additionally want to configure:

- A Gitea themed icon in Netidm for the `gitea` OAuth2 application:
  ```sh
  curl -LO https://gitea.example.com/assets/img/logo.svg
  netidm system oauth2 set-image gitea logo.svg svg
  rm logo.svg
  ```

- To disable password authentication in Gitea, add the following
  [configuration](https://docs.gitea.com/next/administration/config-cheat-sheet) to `app.ini`:

  ```ini
  [service]
  ALLOW_ONLY_EXTERNAL_REGISTRATION = true
  SHOW_REGISTRATION_BUTTON = false
  ENABLE_PASSWORD_SIGNIN_FORM = false
  ```

## GitLab

[GitLab](https://gitlab.com) is a Git-based software development platform, which
[supports OpenID Connect](https://docs.gitlab.com/ee/administration/auth/oidc.html) on
[self-managed installations](https://docs.gitlab.com/ee/install/) _only_ (ie: **not** GitLab.com).

To set up a self-managed GitLab instance to authenticate with Netidm:

1. Add an email address to your regular Netidm account, if it doesn't have one already:

   ```sh
   netidm person update your_username -m your_username@example.com
   ```

2. Create a new Netidm group for your GitLab users (`gitlab_users`), and add your regular account to it:

   ```sh
   netidm group create gitlab_users
   netidm group add-members gitlab_users your_username
   ```

3. Create a new OAuth2 application configuration in Netidm (`gitlab`), configure the redirect URL, and scope access to
   the `gitlab_users` group:

   ```sh
   netidm system oauth2 create gitlab GitLab https://gitlab.example.com/users/sign_in
   netidm system oauth2 add-redirect-url gitlab https://gitlab.example.com/users/auth/openid_connect/callback
   netidm system oauth2 update-scope-map gitlab gitlab_users email openid profile groups
   ```

4. Get the `gitlab` OAuth2 client secret from Netidm:

   ```sh
   netidm system oauth2 show-basic-secret gitlab
   ```

5. Configure GitLab to authenticate to Netidm with OpenID Connect in `/etc/gitlab/gitlab.rb`:

   ```ruby
   # Allow OpenID Connect for single sign on
   gitlab_rails['omniauth_allow_single_sign_on'] = ['openid_connect']

   # Automatically approve any account from an OmniAuth provider.
   #
   # This is insecure if you *don't* control *all* the providers in use.
   # For example, if you allowed sign in Netidm *and* with some public identity
   # provider, it will let anyone with an account sign in to your GitLab
   # instance.
   gitlab_rails['omniauth_block_auto_created_users'] = false

   # Automatically link existing users to Netidm by email address.
   #
   # This is insecure if users are allowed to change their own email address
   # in Netidm (disabled by default), or any provider doesn't validate
   # ownership of email addresses.
   gitlab_rails['omniauth_auto_link_user'] = ['openid_connect']

   # Update the user's profile with info from Netidm whenever they log in.
   # GitLab locks these fields when sync is enabled.
   gitlab_rails['omniauth_sync_profile_from_provider'] = ['openid_connect']
   gitlab_rails['omniauth_sync_profile_attributes'] = ['name', 'email']

   # Connect to Netidm
   gitlab_rails['omniauth_providers'] = [
     {
       name: "openid_connect",
       label: "Netidm",
       icon: "https://idm.example.com/pkg/img/logo-192.png",
       args: {
         name: "openid_connect",
         scope: ["openid","profile","email"],
         response_type: "code",
         # Point this at your Netidm host. "gitlab" is the OAuth2 client ID.
         # Don't include a trailing slash!
         issuer: "https://idm.example.com/oauth2/openid/gitlab",
         discovery: true,
         client_auth_method: "query",
         # Key the GitLab identity by UUID.
         uid_field: "sub",
         pkce: true,
         client_options: {
           # OAuth2 client ID
           identifier: "gitlab",
           secret: "YOUR NETIDM BASIC SECRET HERE",
           redirect_uri: "https://gitlab.example.com/users/auth/openid_connect/callback"
         }
       },
     },
   ]
   ```

   > [!TIP]
   >
   > If you're running GitLab in Docker (or other container platform), you can add this configuration to the
   > `GITLAB_OMNIBUS_CONFIG` environment variable.

6. Restart GitLab (`gitlab-ctl reconfigure`), and wait for it to come back up again (this may take several minutes).

Once GitLab is up and running, you should now see a "Netidm" option on your GitLab sign-in page below the normal login
form.

Once you've got everything working, you may wish configure GitLab to:

- [Automatically redirect to the `openid_connect` provider at the login form](https://docs.gitlab.com/ee/integration/omniauth.html#sign-in-with-a-provider-automatically)

- [Disable password authentication in GitLab](https://docs.gitlab.com/ee/administration/settings/sign_in_restrictions.html#password-authentication-enabled)

- [Disable new sign-ups in GitLab](https://docs.gitlab.com/ee/administration/settings/sign_up_restrictions.html)

More information about these features is available in GitLab's documentation.

## JetBrains Hub and YouTrack

> These instructions were tested with the on-prem version of JetBrains YouTrack 2024.3.44799 and its built-in Hub.

[JetBrains Hub](https://www.jetbrains.com/hub/) is an authentication and authorisation system for TeamCity and YouTrack,
which also provides a "single pane of glass" view of those applications.

TeamCity is a CI/CD tool, and YouTrack is a project and issue management tool.

The on-prem version of YouTrack comes with a built-in version of Hub, which it uses for all authentication.

[JetBrains Hub supports OAuth2](https://www.jetbrains.com/help/hub/oauth2-authentication-module.html), but has some
limitations:

- JetBrains Hub's OAuth2 Auth Module does not support PKCE (as a client),
  [which is a security issue][pkce-disable-security].

- JetBrains Hub does not automatically update profile attributes after account creation.

  However, users can update their own profile manually.

- JetBrains Hub does not support using an auto-configuration URL, which means you have to set a lot of options manually
  (which this guide will describe).

To set up YouTrack (with its built-in JetBrains Hub) to authenticate with Netidm using OAuth2:

1. Add an email address to your regular Netidm account, if it doesn't have one already:

   ```sh
   netidm person update your_username -m your_username@example.com
   ```

2. Create a new Netidm group for your YouTrack users (`youtrack_users`), and add your regular account to it:

   ```sh
   netidm group create youtrack_users
   netidm group add-members youtrack_users your_username
   ```

3. Create a new OAuth2 application configuration in Netidm (`youtrack`), disable the PKCE requirement
   ([this is insecure][pkce-disable-security], but YouTrack doesn't support it), and scope access to the
   `youtrack_users` group:

   ```sh
   netidm system oauth2 create youtrack YouTrack https://youtrack.example.com
   netidm system oauth2 warning-insecure-client-disable-pkce youtrack
   netidm system oauth2 update-scope-map gitlab gitlab_users email openid profile groups
   ```

4. **(optional)** By default, Netidm presents the account's full SPN (eg: `your_username@idm.example.com`) as its
   "preferred username".

   You can set `youtrack` to use a short username (eg: `your_username`) with:

   ```sh
   netidm system oauth2 prefer-short-username youtrack
   ```

5. Log in to YouTrack with an account that has full system administrator rights.

6. Open the Auth Modules configuration in YouTrack (<kbd>⚙️ Administration</kbd> → <kbd>Access Management</kbd> →
   <kbd>Auth Modules</kbd>)

7. Click <kbd>New module</kbd> → <kbd>OAuth2</kbd>, and enter the following details:

   - Name: `Netidm`
   - Authorization URL: `https://idm.example.com/ui/oauth2`

   Click Create, and you'll be taken to the Auth Module's settings page.

8. Copy the <kbd>Redirect URI</kbd> from YouTrack and set it in Netidm:

   ```sh
   netidm system oauth2 add-redirect-url youtrack https://youtrack.example.com/hub/...
   ```

9. Configure the Netidm Auth Module as follows:

   <dl>

   <dt>Button image</dt>

   <dd>

   Upload a Netidm or other organisational logo.

   This will appear on the login form (with no text) to prompt users to sign in.

   By default, this is the OAuth2 logo.

   </dd>

   <dt>Client ID</dt>

   <dd>

   `youtrack`

   </dd>

   <dt>Client secret</dt>

   <dd>

   Copy the secret from the output of this command:

   ```sh
   netidm system oauth2 show-basic-secret youtrack
   ```

   </dd>

   <dt>Extension grant</dt>

   <dd>

   _Leave blank_

   </dd>

   <dt><strong>Authorization Service Endpoints</strong></dt>
    <dd></dd>

   <dt>Authorization URL</dt>

   <dd>

   `https://idm.example.com/ui/oauth2`

   </dd>

   <dt>Token endpoint URL</dt>

   <dd>

   `https://idm.example.com/oauth2/token`

   </dd>

   <dt>User data endpoint URL</dt>

   <dd>

   `https://idm.example.com/oauth2/openid/youtrack/userinfo`

   </dd>

   <dt>Email endpoint URL</dt>

   <dd>

   _Leave blank_

   </dd>

   <dt>Avatar endpoint URL</dt>

   <dd>

   _Leave blank_

   </dd>

   <dt><strong>Field mapping</strong></dt>
    <dd></dd>

   <dt>User ID</dt>

   <dd>

   `sub`

   </dd>

   <dt>Username</dt>

   <dd>

   `preferred_username`

   </dd>

   <dt>Full name</dt>

   <dd>

   `name`

   </dd>

   <dt>Email</dt>

   <dd>

   `email`

   </dd>

   <dt><strong>Additional settings</strong></dt>
    <dd></dd>

   <dt>Scope</dt>

   <dd>

   `openid,profile,email`

   </dd>

   <dt>User creation</dt>

   <dd>Enabled</dd>

   </dl>

10. Click <kbd>Save</kbd> at the bottom of the page.

11. Click <kbd>Enable module</kbd> at the top of the page.

12. Click <kbd>Test login...</kbd> at the top of the page to try logging in with Netidm.

    You may need to allow pop-ups for YouTrack in your browser for this to work.

YouTrack's log in page should now have show the button image you set for Netidm below the normal log in form – which you
can use to log in with Netidm.

[pkce-disable-security]: ../../frequently_asked_questions.md#why-is-disabling-pkce-considered-insecure

## Miniflux

Miniflux is a feedreader that supports OAuth 2.0 and OpenID connect. It automatically appends the `.well-known` parts to
the discovery endpoint. The application name in the redirect URL needs to match the `OAUTH2_PROVIDER` name.

```conf
OAUTH2_PROVIDER = "oidc";
OAUTH2_CLIENT_ID = "miniflux";
OAUTH2_CLIENT_SECRET = "<oauth2_rs_basic_secret>";
OAUTH2_REDIRECT_URL = "https://feeds.example.com/oauth2/oidc/callback";
OAUTH2_OIDC_DISCOVERY_ENDPOINT = "https://idm.example.com/oauth2/openid/<name>";
```

## Nextcloud

Install `user_oidc` [from the Nextcloud App store](https://apps.nextcloud.com/apps/user_oidc) - it can also be found in
the Apps section of your deployment as "OpenID Connect user backend".

In the `Administration settings > OpenID Connect` settings menu of Nextcloud, configure the discovery URL and client ID
and secret.

If your Netidm server is hosted on a local network top-level domain from RFC 6762 (for example: `.home`, `.local`,
`.internal`, …) or resolves to a local address, you need to allow remote servers with local addresses in Nextcloud's
`config.php`:

```php
'allow_local_remote_servers' => true,
```

If you forget this, you may see the following error in logs:

```bash
Host 172.24.11.129 was not connected to because it violates local access rules
```

You may optionally choose to add:

```php
'allow_user_to_change_display_name' => false,
'allow_user_to_change_email' => false,
'lost_password_link' => 'disabled',
```

You can choose to disable other login methods with:

```bash
php occ config:app:set --value=0 user_oidc allow_multiple_user_backends
```

You can login directly by appending `?direct=1` to your login page. You can re-enable other backends by setting the
value to `1`

## OAuth2 Proxy

OAuth2 Proxy is a reverse proxy that provides authentication with OpenID Connect identity providers. It is typically
used to secure web applications without native OpenID Connect support.

Prepare the environment. Due to a
[lack of public client support](https://github.com/oauth2-proxy/oauth2-proxy/issues/1714) we have to set it up as a
basic client.

```bash
netidm system oauth2 create webapp 'webapp.example.com' 'https://webapp.example.com'
netidm system oauth2 add-redirect-url webapp 'https://webapp.example.com/oauth2/callback'
netidm system oauth2 update-scope-map webapp webapp_admin email openid
netidm system oauth2 get webapp
netidm system oauth2 show-basic-secret webapp
<SECRET>
```

Create a user group.

```bash
netidm group create 'webapp_admin'
```

Setup the claim-map to add `webapp_group` to the userinfo claim.

```bash
netidm system oauth2 update-claim-map-join 'webapp' 'webapp_group' array
netidm system oauth2 update-claim-map 'webapp' 'webapp_group' 'webapp_admin' 'webapp_admin'
```

Authorize users for the application. Additionally OAuth2 Proxy requires all users have an email, reference this issue
for more details:

- <https://github.com/oauth2-proxy/oauth2-proxy/issues/2667>

```bash
netidm person update '<user>' --legalname 'Personal Name' --mail 'user@example.com'
netidm group add-members 'webapp_admin' '<user>'
```

And add the following to your OAuth2 Proxy config.

```toml
provider = "oidc"
scope = "openid email"
# change to match your netidm domain and client id
oidc_issuer_url = "https://idm.example.com/oauth2/openid/webapp"
# client ID from `netidm system oauth2 create`
client_id = "webapp"
# redirect URL from `netidm system oauth2 add-redirect-url webapp`
redirect_url = "https://webapp.example.com/oauth2/callback"
# claim name from `netidm system oauth2 update-claim-map-join`
oidc_groups_claim = "webapp_group"
# user group from `netidm group create`
allowed_groups = ["webapp_admin"]
# secret from `netidm system oauth2 show-basic-secret webapp`
client_secret = "<SECRET>"
```

## OPKSSH

[OPKSSH](https://github.com/openpubkey/opkssh) is a tool of the [OpenPubkey](https://github.com/openpubkey/openpubkey)
project. It enables SSH to be used with OpenID Connect allowing access to be managed via identities like
`alice@example.com` instead of long-lived private keys. It does not replace SSH, but instead generates private keys on
the fly, and augments the verification process on the server side.

To set up OPKSSH to authenticate with Netidm:

1. Add an email address to your regular Netidm account, if it doesn't have one already:

   ```sh
   netidm person update alice -m alice@example.com
   ```

2. Create a new Netidm group for your OPKSSH users (`opkssh_users`), and add your regular account to it:

   ```sh
   netidm group create opkssh_users
   netidm group add-members opkssh_users alice
   ```

3. Create a new OAuth2 application configuration in Netidm (`opkssh`), configure the redirect URL, and scope access to
   the `opkssh_users` group:

   ```sh
   # The redirect origin is set to localhost for local callbacks
   netidm system oauth2 create-public opkssh opkssh http://localhost:3000

   # Add the specific redirect URIs used by OPKSSH
   netidm system oauth2 add-redirect-url opkssh http://localhost:3000/login-callback
   netidm system oauth2 add-redirect-url opkssh http://localhost:10001/login-callback
   netidm system oauth2 add-redirect-url opkssh http://localhost:11110/login-callback

   # Explicitly allow localhost redirects for this client
   netidm system oauth2 enable-localhost-redirects opkssh

   # Map the group created earlier to the required OIDC scopes
   netidm system oauth2 update-scope-map opkssh opkssh_users email openid profile groups
   ```

4. On the SSH server side, [install opkssh](https://github.com/openpubkey/opkssh#installing-on-a-server) and allow your
   user to connect via:

   ```sh
   # where 'user' is the linux user
   sudo opkssh add user alice@example.com https://idm.example.com/oauth2/openid/opkssh
   ```

5. On the SSH client side, [install opkssh](https://github.com/openpubkey/opkssh#getting-started) and login via Netidm:

   ```sh
   opkssh login --provider=https://idm.example.com/oauth2/openid/opkssh,opkssh
   ```

6. Use SSH as you would normally:

   ```sh
   ssh user@your-server-hostname
   ```

## Outline

> These instructions were tested with self-hosted Outline 0.86.1.

Outline is a wiki / knowledge base which [can be self-hosted][outline-self].

Self-hosted [Outline supports authentication with OpenID Connect][outline-oidc], with some limitations:

- PKCE is only enabled via OIDC discovery.
  - **WARNING**: With manual OAuth2 configuration [Outline does not support PKCE][outline-pkce],
    [which is a security issue][pkce-disable-security].

- Outline does not support group or ACL delegation.

  On a new Outline installation, the first user who authenticates to Outline will be granted administrative rights.

- Outline _only_ automatically updates the user's email address on log in.

  It will set the user's preferred name on _first_ log in _only_.

To set up a _new_ self-hosted Outline instance to authenticate with Netidm:

1. Add an email address to your regular Netidm account, if it doesn't have one already:

   ```sh
   netidm person update your_username -m your_username@example.com
   ```

2. Create a new Netidm group for your Outline users (`outline_users`), and **only** add your regular account to it:

   ```sh
   netidm group create outline
   netidm group add-members outline_users your_username
   ```

   **Warning:** don't add any other users when first setting up Outline. The first user who logs in will gain
   administrative rights.

3. Create a new OAuth2 application configuration in Netidm (`outline`), configure the redirect URL, and scope access to
   the `outline_users` group:

   ```sh
   netidm system oauth2 create outline Outline https://outline.example.com
   netidm system oauth2 add-redirect-url outline https://outline.example.com/auth/oidc.callback
   netidm system oauth2 update-scope-map outline outline_users email openid profile groups
   ```

4. Get the `outline` OAuth2 client secret from Netidm:

   ```sh
   netidm system oauth2 show-basic-secret outline
   ```

5. Configure Outline to authenticate to Netidm with OpenID Connect in Outline's environment file (`docker.env` /
   `.env`):

   ```ini
   OIDC_CLIENT_ID=outline
   OIDC_CLIENT_SECRET=YOUR NETIDM BASIC SECRET HERE
   # Use OIDC discovery with PKCE support
   OIDC_ISSUER_URL=https://idm.example.com/oauth2/openid/outline
   # Prevent redirect loop on logout
   OIDC_DISABLE_REDIRECT=true
   # Outline doesn't seem to actually use this.
   OIDC_USERNAME_CLAIM=preferred_username
   OIDC_DISPLAY_NAME=Netidm
   OIDC_SCOPES=openid profile email
   ```

6. Restart Outline and wait for it to come back up again.

Outline's login form should now show a <kbd>Continue with Netidm</kbd> button, which can be used to sign in.

### Migrating between Outline authentication providers

> [!WARNING]
>
> While Outline supports multiple authentication providers, we'd recommend running Outline with a _single_
> authentication provider (once you've tested it works correctly).
>
> When _migrating_ from one authentication provider to another, Outline will attempt to match based on email address.
> This can be vulnerable to account take-over if email addresses are _not_ validated in _all_ providers and Outline is
> configured with multiple authentication providers.

Each Outline user only has a single credential associated with it (provider + `sub`), even if Outline is configured to
use multiple identity providers. This is set to the last-used credential on login (detailed below).

When using Netidm, `sub` is the user's UUID, and is stable even if their Netidm account is renamed or changes email
address – but Outline will only update the email address automatically.

When a user authenticates to Outline, it will attempt to match the credential with an Outline user:

1. Find a matching user by credential (provider + `sub`).

2. If there is a matching user, the user is logged in.

3. Find a matching user by email address.

4. If there's no matching Outline user with that email address, Outline will create a new user account (if allowed by
   <kbd>Security</kbd> →
   <kbd>Access</kbd> → <kbd>Allowed domains</kbd>), and the user is logged in.

   If a user account is not allowed to be created, the login will be rejected.

5. If the matching user's credential _is_ associated with _this_ provider,
   [Outline will (currently) reject the login attempt](https://github.com/outline/outline/blob/ce987d23edbb7be940d26e2cc7df8c1e51aabc3c/server/commands/userProvisioner.ts#L86-L94).

6. At this point, the matching user's credential must be associated with a different provider, and it is treated as a
   migration.

   Outline replaces the matching user's credential with the one currently used, and logs them in.

As long as all email addresses are verified _and_ unique to a single account in each provider, this should allow you to
easily and securely migrate from one identity provider to another.

However, if emails are not verified in even a _single_ provider, this could make Outline vulnerable to account
take-over.

Outline has _no UI_ for managing or displaying external credentials, so it's difficult to troubleshoot.

[outline-oidc]: https://docs.getoutline.com/s/hosting/doc/oidc-8CPBm6uC0I
[outline-pkce]: https://github.com/outline/outline/discussions/7706
[outline-self]: https://docs.getoutline.com/s/hosting

## ownCloud

> These instructions were tested with ownCloud 10.15.10.

To set up an ownCloud instance to authenticate with Netidm:

1. Install the [ownCloud OpenID Connect app](https://marketplace.owncloud.com/apps/openidconnect) (for web auth) **and**
   [ownCloud OAuth2 app][owncloud-oauth2-app] (for desktop and mobile app auth) from the ownCloud Market.

2. Add an email address to your regular Netidm account, if it doesn't have one already:

   ```sh
   netidm person update your_username -m your_username@example.com
   ```

3. Create a new Netidm group for your ownCloud users (`owncloud_users`), and add your regular account to it:

   ```sh
   netidm group create owncloud_users
   netidm group add-members owncloud_users your_username
   ```

4. Create a new OAuth2 application configuration in Netidm (`owncloud`), allow use of legacy crypto
   ([ownCloud does not support `ES256`](https://github.com/owncloud/openidconnect/issues/313)), configure the redirect
   URLs, and scope access to the `owncloud_users` group:

   ```sh
   netidm system oauth2 create owncloud ownCloud https://owncloud.example.com
   netidm system oauth2 warning-enable-legacy-crypto owncloud
   netidm system oauth2 add-redirect-url owncloud https://owncloud.example.com/apps/openidconnect/redirect
   netidm system oauth2 update-scope-map owncloud owncloud_users email openid profile groups
   ```

5. **(optional)** By default, Netidm presents the account's full SPN (eg: `your_username@idm.example.com`) as its
   "preferred username". You can set `owncloud` to use a short username (eg: `your_username`) with:

   ```sh
   netidm system oauth2 prefer-short-username owncloud
   ```

6. Get the `owncloud` OAuth2 client secret from Netidm:

   ```sh
   netidm system oauth2 show-basic-secret owncloud
   ```

7. Set [ownCloud's session cookie `SameSite` value to `Lax`][owncloud-samesite]:

   - For manual installations, add the option `'http.cookie.samesite' => 'Lax',` to `config.php`.
   - For Docker installations, set the `OWNCLOUD_HTTP_COOKIE_SAMESITE` environment variable to `Lax`, then stop and
     start the container.

   When ownCloud and Netidm are on different top-level domains
   ([as we recommend](../../choosing_a_domain_name.md#subdomains-and-cross-origin-policy)), ownCloud's default
   `SameSite=Strict` session cookie policy causes browsers to drop the session cookie when Netidm redirects back to
   ownCloud, which then causes their OIDC library to [send an invalid token request to Netidm][owncloud-session-bug],
   which Netidm (correctly) rejects.

8. Create a JSON configuration file (`oidc-config.json`) for ownCloud's OIDC App.

   To key users by UID (most secure configuration, but not suitable if you have existing ownCloud accounts) – so their
   UID is their ownCloud username, use this configuration:

   ```json
   {
     "provider-url": "https://idm.example.com/oauth2/openid/owncloud",
     "client-id": "owncloud",
     "client-secret": "YOUR CLIENT SECRET HERE",
     "loginButtonName": "Netidm",
     "mode": "userid",
     "search-attribute": "sub",
     "auto-provision": {
       "enabled": true,
       "email-claim": "email",
       "display-name-claim": "name",
       "update": { "enabled": true }
     },
     "scopes": ["openid", "profile", "email"]
   }
   ```

   To key users by email address (vulnerable to account take-over, but allows for migrating existing ownCloud accounts),
   modify the `mode` and `search-attribute` settings to use the `email` attribute:

   ```json
   {
     "mode": "email",
     "search-attribute": "email"
   }
   ```

9. Deploy the config file you created with [`occ`][occ].

   [The exact command varies][occ] depending on how you've deployed ownCloud.

   ```sh
   occ config:app:set openidconnect openid-connect --value="$(<oidc-config.json)"
   ```

ownCloud's login page should now show "Alternative logins" below the normal login form, which you can use to sign in.

> [!WARNING]
>
> **Do not** configure [OIDC Service Discovery][owncloud-oidcsd] rewrite rules (`/.well-known/openid-configuration`) in
> ownCloud – **this breaks the ownCloud desktop and mobile clients**.
>
> The ownCloud desktop and mobile clients use [hard coded secrets][owncloud-secrets] which **cannot** be entered into
> Netidm, because this is a security risk.
>
> With the [ownCloud OAuth2 app][owncloud-oauth2-app] installed, the ownCloud clients will instead authenticate to
> ownCloud Server as an OAuth provider (which has [the hard coded secrets][owncloud-secrets] installed by default),
> which then in turn can authenticate to ownCloud locally or to Netidm with your own client ID/secret.
>
> To use OIDC Service Discovery with the ownCloud clients, you'd need to create OAuth2 client configurations in Netidm
> for the ownCloud Android, desktop and iOS apps, and get those secrets added to the clients either by:
>
> - modifying and recompiling the apps yourself from source, or,
> - [using an iOS MDM configuration][owncloud-ios-mdm] (iOS only), or,
> - [requesting branded apps as part of an ownCloud Enterprise subscription][owncloud-branding]
>
> Setting that up is beyond the scope of this document.

[owncloud-branding]: https://doc.owncloud.com/server/next/admin_manual/enterprise/clients/creating_branded_apps.html
[owncloud-oidcsd]: https://doc.owncloud.com/server/next/admin_manual/configuration/user/oidc/oidc.html#set-up-service-discovery
[owncloud-samesite]: https://doc.owncloud.com/server/next/admin_manual/configuration/server/config_sample_php_parameters.html#define-how-to-relax-same-site-cookie-settings
[owncloud-secrets]: https://doc.owncloud.com/server/next/admin_manual/configuration/user/oidc/oidc.html#client-ids-secrets-and-redirect-uris
[owncloud-session-bug]: https://github.com/jumbojett/OpenID-Connect-PHP/issues/453
[owncloud-oauth2-app]: https://marketplace.owncloud.com/apps/oauth2
[owncloud-ios-mdm]: https://doc.owncloud.com/ios-app/12.2/appendices/mdm.html#oauth2-based-authentication
[occ]: https://doc.owncloud.com/server/next/admin_manual/configuration/server/occ_command.html

## Velociraptor

Velociraptor supports OIDC. To configure it select "Authenticate with SSO" then "OIDC" during the interactive
configuration generator. Alternately, you can set the following keys in server.config.yaml:

```yaml
GUI:
  authenticator:
    type: OIDC
    oidc_issuer: https://idm.example.com/oauth2/openid/:client_id:/
    oauth_client_id: <client name/>
    oauth_client_secret: <client secret>
```

Velociraptor does not support PKCE. You will need to run the following:

```bash
netidm system oauth2 warning-insecure-client-disable-pkce <client name>
```

Initial users are mapped via their email in the Velociraptor server.config.yaml config:

```yaml
GUI:
  initial_users:
    - name: <email address>
```

Accounts require the `openid` and `email` scopes to be authenticated. It is recommended you limit these to a group with
a scope map due to Velociraptors high impact.

```bash
# netidm group create velociraptor_users
# netidm group add_members velociraptor_users ...
netidm system oauth2 create_scope_map <client name> velociraptor_users openid email
```

## Grafana

Grafana is a open source analytics and interactive visualization web application. It provides charts, graphs and alerts
when connected to supported data source.

Create Grafana user groups:

```bash
netidm group create 'grafana_superadmins'
netidm group create 'grafana_admins'
netidm group create 'grafana_editors'
netidm group create 'grafana_users'
```

Prepare the environment:

```bash
netidm system oauth2 create grafana "grafana.domain.name" https://grafana.domain.name
netidm system oauth2 set-landing-url grafana 'https://grafana.domain.name/login/generic_oauth'
netidm system oauth2 update-scope-map grafana grafana_users email openid profile groups
netidm system oauth2 enable-pkce grafana
netidm system oauth2 get grafana
netidm system oauth2 show-basic-secret grafana
<SECRET>
```

Setup the claim-map that will set what role each group will map to in Grafana:

```bash
netidm system oauth2 update-claim-map-join 'grafana' 'grafana_role' array
netidm system oauth2 update-claim-map 'grafana' 'grafana_role' 'grafana_superadmins' 'GrafanaAdmin'
netidm system oauth2 update-claim-map 'grafana' 'grafana_role' 'grafana_admins' 'Admin'
netidm system oauth2 update-claim-map 'grafana' 'grafana_role' 'grafana_editors' 'Editor'
```

Don't forget that every Grafana user needs be member of one of above group and have name and e-mail:

```bash
netidm person update <user> --legalname "Personal Name" --mail "user@example.com"
netidm group add-members 'grafana_users' 'my_user_group_or_user_name'
```

And add the following to your Grafana config:

```ini
[auth.generic_oauth]
enabled = true
name = Netidm
client_id = grafana
client_secret = <SECRET>
scopes = openid,profile,email,groups
auth_url = https://idm.example.com/ui/oauth2
token_url = https://idm.example.com/oauth2/token
api_url = https://idm.example.com/oauth2/openid/grafana/userinfo
use_pkce = true
use_refresh_token = true
allow_sign_up = true
login_attribute_path = preferred_username
groups_attribute_path = groups
role_attribute_path = contains(grafana_role[*], 'GrafanaAdmin') && 'GrafanaAdmin' || contains(grafana_role[*], 'Admin') && 'Admin' || contains(grafana_role[*], 'Editor') && 'Editor' || 'Viewer'
allow_assign_grafana_admin = true
```

## Vouch Proxy

> [!WARNING]
>
> Vouch proxy requires a unique identifier but does not use the proper scope, "sub". It uses the fields "username" or
> "email" as primary identifiers instead. As a result, this can cause user or deployment issues, at worst security
> bypasses. You should avoid Vouch Proxy if possible due to these issues.
>
> - <https://github.com/vouch/vouch-proxy/issues/309>
> - <https://github.com/vouch/vouch-proxy/issues/310>

&nbsp;

> [!NOTE]
>
> You need to run at least version 0.37.0

Vouch Proxy supports multiple OAuth and OIDC login providers. To configure it you need to pass:

```yaml
oauth:
  auth_url: https://idm.wherenetidmruns.com/ui/oauth2
  callback_url: https://login.wherevouchproxyruns.com/auth
  client_id: <name> # Found in netidm system oauth2 get XXXX (should be the same as XXXX)
  client_secret: <oauth2_rs_basic_secret> # Found in netidm system oauth2 get XXXX
  code_challenge_method: S256
  provider: oidc
  scopes:
    - email # Required due to vouch proxy reliance on mail as a primary identifier
  token_url: https://idm.wherenetidmruns.com/oauth2/token
  user_info_url: https://idm.wherenetidmruns.com/oauth2/openid/<name>/userinfo
```

The `email` scope needs to be passed and thus the mail attribute needs to exist on the account:

```bash
netidm person update <ID> --mail "YYYY@somedomain.com" --name idm_admin
```
