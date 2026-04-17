# Monitoring the platform

The monitoring design of Netidm is still very much in its infancy -
[take part in the discussion at github.com/flengure/netidm/issues/216](https://github.com/flengure/netidm/issues/216).

## netidmd status endpoint

netidmd currently responds to HTTP GET requests at the `/status` endpoint with a JSON object of either "true" or
"false". `true` indicates that the platform is responding to requests.

| URL                | `<hostname>/status`                              |
| ------------------ | ------------------------------------------------ |
| Example URL        | `https://example.com/status`                     |
| Expected response  | One of either `true` or `false` (without quotes) |
| Additional Headers | x-netidm-opid                                    |
| Content Type       | application/json                                 |
| Cookies            | netidm-session                                   |

## OpenTelemetry Tracing

Configure OTLP trace exports by setting a `otel_grpc_url` in the server configuration. This'll enable
[OpenTelemetry traces](https://opentelemetry.io) to be sent for observability use cases.

Example:

```toml
otel_grpc_url = "http://my-otel-host:4317"
```

### Relevant environment variables

We're trying to align with the
[OpenTelemetry standards](https://opentelemetry.io/docs/specs/otel/configuration/sdk-environment-variables/).

| Variable                     | What it Does                                                                                                   | Example Value                                                           |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------- |
| `NETIDM_OTEL_GRPC_URL`       | Sets the endpoint that logs will be sent via GRPC>                                                             | `http://localhost:4317` if you're testing locally.                      |
| `OTEL_EXPORTER_OTLP_HEADERS` | Sets headers when the tonic exporter sends events                                                              | `authorization=<mysupersecrettoken>` will send an authorization header. |
| `OTEL_SERVICE_NAME`          | Sets the `service.name` field, if unset we force it to `netidmd` because the SDK defaults to `unknown_service` | `test_netidmd`                                                          |

### Troubleshooting

#### Max Span Size Exceeded

On startup, we run some big processes that might hit a "max trace size" in certain configurations. Grafana Tempo
defaults to 5MB, which is sensible for most things, but ... 😁

Grafana Tempo [config to allow larger spans](https://grafana.com/docs/tempo/latest/troubleshooting/response-too-large/):

```yaml
distributor:
  receivers:
    otlp:
      protocols:
        grpc:
          max_recv_msg_size_mib: 20
```
