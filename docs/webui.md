# setec web UI

The setec server serves a web UI at its root (`https://<setec-host>/`) for
browsing, inspecting, and editing secrets.

- **Browse**: list every secret you have `info` access to, with its active
  version and last access time. Type to filter.
- **Inspect**: open a secret to see all its versions. Values stay hidden until
  you click **Reveal** (requires `get`), and binary values are shown as a hex
  dump. Every reveal is recorded in the audit log.
- **Edit**: create secrets and add versions (typed or uploaded as a file),
  make a version active, delete old versions, or delete a whole secret (you
  must type its name to confirm). Each action needs the matching permission
  (`put`, `activate`, `delete`); the UI hides controls you cannot use.

## Security

The UI uses the same Tailscale identity and ACLs as the API. The JSON API
(`/api/*`) still refuses all browser requests. The UI has its own endpoints
under `/ui/`, which only accept same-origin POSTs that carry the `HX-Request`
header, so other sites cannot trigger them (CSRF). Responses carry a strict
Content-Security-Policy with no inline scripts.

## Local development

To work on the UI without joining a tailnet, run the server in dev mode with
`--dev-listen`. It serves plain HTTP and treats every caller as a user with
full access, so only ever bind it to localhost:

```sh
go run ./cmd/setec server --dev --dev-listen=localhost:8080 --state-dir=/tmp/setec-dev
SETEC_SERVER=http://localhost:8080 go run ./cmd/setec put example/secret
```

Templates live in `server/templates`, and static assets (including a vendored
copy of [htmx](https://htmx.org)) in `server/static`. Both are embedded in the
binary.
