# OpenShift Connector

The OpenShift connector authenticates users via the built-in OAuth2 server in an OpenShift
cluster. Endpoints are auto-discovered from the OpenShift well-known configuration; no manual
endpoint configuration is required.

## Prerequisites

Register an OAuth client in OpenShift. Create a manifest file:

```yaml
# oauth-client.yaml
apiVersion: oauth.openshift.io/v1
kind: OAuthClient
metadata:
  name: netidm
grantMethod: auto
redirectURIs:
  - https://<your-netidm-domain>/ui/login/oauth2_landing
```

Apply it:

```bash
oc apply -f oauth-client.yaml
```

Then create a secret for the OAuth client. OpenShift generates the secret automatically when
you use the web console, or set one explicitly in the manifest with `secret: <value>`.

## Creating the connector

```bash
netidm system oauth2 create-openshift \
    --name myopenshift \
    --issuer https://api.mycluster.example.com:6443 \
    --client-id  netidm \
    --client-secret <CLIENT_SECRET>
```

The `--issuer` is the Kubernetes API server URL. Authorization and token endpoints are derived
automatically from the well-known OpenShift OAuth configuration.

Enable JIT provisioning:

```bash
netidm system oauth2 enable-jit-provisioning --name myopenshift
```

## Restricting by OpenShift group

To require membership in specific OpenShift groups, set the `connector_openshift_groups`
attribute via the REST API:

```bash
# PATCH /v1/oauth2/_client/myopenshift
# { "connector_openshift_groups": ["developers", "ops"] }
```

## Custom CA certificate

For clusters with a self-signed API server certificate:

```bash
# PATCH /v1/oauth2/_client/myopenshift
# { "connector_openshift_root_ca": "<PEM certificate content>" }
```

Or to skip verification entirely (development only):

```bash
# { "connector_openshift_insecure_ca": "true" }
```

## Reference

| Attribute | Description |
|---|---|
| `connector_openshift_issuer` | OpenShift API server URL (well-known discovery base) |
| `connector_openshift_groups` | Required OpenShift group names (multi-value) |
| `connector_openshift_insecure_ca` | Skip TLS certificate verification |
| `connector_openshift_root_ca` | PEM CA certificate for cluster TLS |
