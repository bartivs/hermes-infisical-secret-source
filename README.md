# Hermes Agent Infisical Secret Source

Secure, self-hosted **Infisical secret management for Hermes Agent**. This
standalone Hermes plugin loads API keys, messaging tokens, browser credentials,
and other environment variables from an Infisical project at Hermes startup.

[![Hermes Agent](https://img.shields.io/badge/Hermes%20Agent-plugin-7c3aed)](https://github.com/NousResearch/hermes-agent)
[![Infisical](https://img.shields.io/badge/Infisical-machine%20identity-0b7285)](https://infisical.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Repository status:** private beta. The API is intentionally small while
> the integration is validated against Hermes Agent releases.

## Why use this integration?

Hermes Agent normally reads provider credentials from its local dotenv
configuration. This plugin replaces a large collection of local secrets with one scoped Infisical
machine-identity token. Secrets remain centrally managed, auditable, and easy
to rotate.

### Features

- Infisical Cloud and self-hosted Infisical support
- Read-only bulk export from a selected project, environment, and folder
- Machine identity authentication using the official Infisical CLI
- Optional root-only token file, avoiding a token in the local dotenv configuration
- Hermes-native precedence, provenance labels, protected bootstrap token, and
  startup timeout handling
- No secret values in plugin logs, exceptions, or Git configuration
- Fail-open startup behavior: Hermes continues with already-loaded credentials
  if Infisical is temporarily unavailable
- No extra Python dependency for the plugin itself

## Quick start

### 1. Create a scoped Infisical identity

In Infisical:

1. Create or select a project for Hermes, for example `hermes-barti`.
2. Add an environment such as `prod`.
3. Add secrets using the exact environment variable names Hermes expects, for
   example `OPENROUTER_API_KEY`, `TELEGRAM_BOT_TOKEN`, or
   `FIRECRAWL_API_KEY`.
4. Create a machine identity with **read-only** access to this project.
5. Generate its Universal Auth access token.

Use a dedicated project rather than granting Hermes access to unrelated
application secrets.

### 2. Install the plugin

```bash
hermes plugins install bartivs/hermes-infisical-secret-source --enable
```

Pin a reviewed commit in production:

```bash
hermes plugins install bartivs/hermes-infisical-secret-source \
  --ref <reviewed-commit-sha> --enable
```

### 3. Configure the source

The simplest setup keeps the machine token in Hermes' protected dotenv configuration:

```yaml
# $HERMES_HOME/config.yaml
secrets:
  infisical:
    enabled: true
    project_id: "<infisical-project-uuid>"
    environment: prod
    domain: "https://app.infisical.com/api"
    override_existing: true
```

```dotenv
# Hermes dotenv configuration — bootstrap credential only
INFISICAL_TOKEN=<machine-identity-access-token>
```

For a self-hosted Infisical instance:

```yaml
secrets:
  infisical:
    enabled: true
    project_id: "<project-uuid>"
    environment: prod
    domain: "http://192.168.1.112/api"
```

Restart Hermes after configuration:

```bash
systemctl --user restart hermes-gateway
```

## Root-only token file

For a root-run Hermes gateway, a token file keeps the bootstrap credential out
of the local dotenv configuration:

```bash
install -d -m 700 /etc/infisical
install -o root -g root -m 600 /dev/null /etc/infisical/hermes.token
# Enter the machine-identity token into this root-only file using a trusted editor.
```

Configure the source:

```yaml
secrets:
  infisical:
    enabled: true
    project_id: "<project-uuid>"
    environment: prod
    domain: "http://192.168.1.112/api"
    token_file: /etc/infisical/hermes.token
    cli_path: /usr/local/bin/infisical
    override_existing: true
```

The token file accepts either `INFISICAL_TOKEN=value` or a raw token. Keep it
owned by root with mode `0600`.

## Configuration reference

| Key | Default | Description |
|---|---|---|
| `enabled` | `false` | Enable the Infisical source. |
| `project_id` | empty | Infisical project UUID. Required. |
| `environment` | `prod` | Infisical environment slug. |
| `secret_path` | `/` | Infisical folder path to export. |
| `domain` | `https://app.infisical.com/api` | Infisical API domain; use `/api` for self-hosted deployments. |
| `cli_path` | `infisical` | Infisical CLI executable path. |
| `token_env` | `INFISICAL_TOKEN` | Bootstrap token environment variable. |
| `token_file` | empty | Optional raw or EnvironmentFile-style token path. |
| `timeout_seconds` | `120` | Hermes source fetch timeout. |
| `cli_timeout_seconds` | `30` | Infisical CLI subprocess timeout. |
| `override_existing` | `true` | Let Infisical values replace matching `.env` values. |

The plugin invokes the official CLI as an argument list, never through a
shell. The token is passed through the child process environment and is never
placed in CLI arguments.

## Hermes and Infisical architecture

```text
Infisical project (read-only machine identity)
                    |
                    v
      INFISICAL_TOKEN or root-only token file
                    |
                    v
     Official Infisical CLI: export --format=dotenv
                    |
                    v
     Hermes secret-source orchestrator and provenance
                    |
                    v
     Hermes provider, browser, and messaging environment
```

The plugin only fetches values. Hermes owns conflict resolution, environment
mutation, source ordering, protected bootstrap variables, and startup
reporting.

## Security guidance

- Give the machine identity read-only access to a dedicated project.
- Do not store Infisical tokens in `config.yaml`, Git, issue reports, or logs.
- Prefer `token_file` on root-run servers; use mode `0600` and root ownership.
- Use a pinned plugin commit for production installations.
- Remove duplicate provider credentials from the local dotenv configuration after verifying
  the Infisical source works.
- Rotate the machine identity token in Infisical and update the token file; then
  restart Hermes.
- Restrict self-hosted Infisical to the LAN or a private network. Do not expose
  its API or Hermes' token file publicly.

## Troubleshooting

### Source is not loading

Check that the plugin is enabled and the configuration section is present:

```bash
hermes plugins list
hermes config get secrets.infisical.enabled
hermes config get secrets.infisical.project_id
```

### Token or project authorization fails

Confirm that the token belongs to a machine identity with read access to the
configured project and that the project UUID is correct. Run the CLI manually
without printing the token:

```bash
INFISICAL_TOKEN_FILE=/etc/infisical/hermes.token
set -a
. "$INFISICAL_TOKEN_FILE"
set +a
INFISICAL_DOMAIN="http://192.168.1.112/api" \
  infisical export --env=prod --projectId=<project-uuid> --format=dotenv
```

### Hermes starts but old values remain

Set `override_existing: true`, restart the gateway, and remove old values from
the local dotenv configuration once the source is confirmed. Hermes' source precedence still
protects bootstrap credentials and resolves conflicts with other secret
sources.

### Infisical is slow or unavailable

Increase `cli_timeout_seconds` and verify LAN connectivity. The plugin reports
the failure without blocking Hermes startup; existing environment values remain
available.

## Development

The plugin follows Hermes' `SecretSource` contract:

- `fetch()` is synchronous, non-interactive, and never raises.
- The fetcher hands its mapping to Hermes' standard loader and does not mutate process state.
- CLI execution uses Hermes' audited `run_secret_cli()` helper.
- The source is disabled unless explicitly configured.

Run the test suite in a Hermes source checkout or environment:

```bash
python -m pytest -q
```

## Related projects

- [Hermes Agent](https://github.com/NousResearch/hermes-agent)
- [Infisical](https://github.com/Infisical/infisical)
- [Infisical CLI](https://github.com/Infisical/infisical/tree/main/cli)

## License

MIT — see [LICENSE](LICENSE).
