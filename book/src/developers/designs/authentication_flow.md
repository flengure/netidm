# User Authentication Flow

This authentication flow is for interactive users. If you're using a
[service account](../../accounts/service_accounts.md), use
[Bearer authentication](../../accounts/service_accounts.html#api-tokens-with-netidm-httpsrest-api) with the token.

1. Client sends an init request. This can be either:
   1. `AuthStep::Init` which just includes the username, or
   2. `AuthStep::Init2` which can request a "privileged" session
2. The server responds with a list of authentication methods. (`AuthState::Choose(Vec<AuthAllowed>)`)
3. Client requests auth with a method (`AuthStep::Begin(AuthMech)`)
4. Server responds with an acknowledgement (`AuthState::Continue(Vec<AuthAllowed>)`). This is so the challenge can be
   included in the response, for Passkeys or other challenge-response methods.
   - If required, this challenge/response continues in a loop until the requirements are satisfied. For example, TOTP
     and then Password.
5. The result is returned, either:
   - Success, with the User Auth Token as a `String`.
   - Denied, with a reason as a `String`.

```mermaid
sequenceDiagram;
    autonumber
    participant Client
    participant Netidm
    
    Note over Client: "I'm Ferris and I want to start auth!"
    Client ->> Netidm: AuthStep::Init(username)
    Note over Netidm: "You can use the following methods"
    Netidm ->> Client: AuthState::Choose(Vec<AuthAllowed>)

    loop Authentication Checks
        Note over Client: I want to use this mechanism
        Client->>Netidm: AuthStep::Begin(AuthMech)
        Note over Netidm: Ok, you can do that.
        Netidm->>Client: AuthState::Continue(Vec<AuthAllowed>)
        Note over Client: Here is my credential
        Client->>Netidm: AuthStep::Cred(AuthCredential)
        Note over Netidm: Netidm validates the Credential,<br /> and if more methods are required,<br /> return them.
        Netidm->>Client: AuthState::Continue(Vec<AuthAllowed>)
        Note over Client, Netidm: If there's no more credentials required, break the loop.

    end

    Note over Client,Netidm: If Successful, return the auth token
    Netidm->>Client: AuthState::Success(String Token)

    Note over Client,Netidm: If Failed, return that and a message why.
    Netidm-xClient: AuthState::Denied(String Token)
```
