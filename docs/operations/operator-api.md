# Local operator API

ARTEMIS provides a loopback-only control API. It is intentionally not a remote service: the implementation does not terminate TLS, integrate an external identity provider, or accept non-loopback binds.

## Start

Create a server-side token map and export it through an environment variable. Keep the JSON and tokens out of source control, shell history, logs, and tickets.

```json
{
  "REPLACE_WITH_AT_LEAST_24_RANDOM_CHARACTERS": {
    "operator_id": "local-admin",
    "role": "admin"
  }
}
```

Run:

```bash
export ARTEMIS_OPERATOR_CREDENTIALS_JSON='{"REPLACE_WITH_AT_LEAST_24_RANDOM_CHARACTERS":{"operator_id":"local-admin","role":"admin"}}'
python artemis.py --policy policy.example.json --runtime-db runs/runtime.sqlite3 \
  --runtime-action serve-api --api-host 127.0.0.1 --api-port 8765
```

The example token is a placeholder, not a usable credential. Generate a unique high-entropy token for each operator and provision the mapping through a protected secret/configuration mechanism. The server does not create or print tokens.

## Roles and routes

- `viewer`: `GET /health`, `GET /jobs/{job_id}`
- `operator`: viewer routes plus `POST /jobs/{job_id}/cancel`
- `approver`: viewer routes plus `POST /approvals/{approval_id}/decision`
- `admin`: all above plus `POST /approvals/{approval_id}/revoke`

The `operator_id` and role are read from the server-side token map; request JSON cannot override them. Approval decisions still enforce requester/approver separation. Request bodies are capped at 8 KiB. The API is not exposed remotely; use an independently secured deployment gateway if remote access becomes a requirement, after adding TLS and a supported identity provider.

This API does not provide tool dispatch, assessment creation, arbitrary file access, or a dashboard. It does not make ARTEMIS's legacy assessment engine route through `AuthorizationGateway`.
