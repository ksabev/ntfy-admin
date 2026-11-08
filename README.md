# ntfy-admin

A small web admin panel for self-hosted [ntfy](https://ntfy.sh) servers.

ntfy can manage users, access rules and tokens, but the server's own web app
only lets you manage *your own* account. Everything else needs the CLI inside the
container. ntfy-admin is the missing admin page:

- **Users:** create, delete, change or generate passwords, password reset links, roles, tiers
- **Access rules:** per user and for anonymous visitors, with `*` wildcards
- **Access matrix:** effective permission for every user × topic, resolved the
  same way ntfy resolves it (own most specific rule → anonymous rules → server default)
- **Access tokens:** one per device or service, with label and expiry, last used
  time and IP, revoke with one click. Values are hidden until you click *Show*.
- **Onboarding:** a printable card with the server, username, a fresh password
  and a QR code per topic the user can read (opens the ntfy app, already subscribed)
- **Topics:** who can read and who can publish, optional display names, *send a test message*
- **Export:** who-can-what as YAML, for docs or git. No passwords, no token values.
- **Many servers:** add, edit and remove ntfy servers in the UI, each with its own admin login
  and its own public URL (the one QR codes point to). First start without a server shows a setup screen.
- **Two modes:** a regular admin panel, and a **super admin** panel (red UI) that uses ntfy's
  admin socket for what ntfy refuses over HTTP: roles and admin users.

It is a thin layer over **ntfy's own admin API**. It has no user database and stores
no secrets: you log in with an ntfy admin account. No Docker socket, and no access
to ntfy's files. It works with SQLite or PostgreSQL ntfy, in Docker or with systemd.

Single static Go binary with a plain HTML/JS UI (no build step). The image is
about 10 MB, distroless, and runs as non-root.

## Requirements

- ntfy **2.36 or newer** for everything (token management, admin socket).
  Older servers still get users and access rules; the token tab turns itself off.
- Auth enabled in ntfy (`auth-file` or `database-url`), and at least one **admin** user.

## Quick start (docker compose)

Run the panel twice: a regular admin panel for daily work, and a super admin
panel for the rare role or admin-user change. They share `/data`, so a server
added in one shows up in the other.

```yaml
services:
  ntfy:
    image: binwiederhier/ntfy:v2.37.2
    command: ["serve"]
    environment:
      NTFY_BASE_URL: https://ntfy.example.com
      NTFY_AUTH_FILE: /var/lib/ntfy/user.db
      NTFY_AUTH_DEFAULT_ACCESS: deny-all
      NTFY_BEHIND_PROXY: "true"
      NTFY_EXPERIMENTAL_LISTEN_ADMIN_UNIX: /run/ntfy/admin.sock   # for the super panel
    volumes:
      - ./ntfy/lib:/var/lib/ntfy
      - ntfy-run:/run/ntfy
    ports: ["8082:80"]

  ntfy-admin:                           # regular admin: HTTP admin API only
    image: ntfy-admin:latest            # docker build -t ntfy-admin .
    environment: &seed                  # seeds the first server on first start; then use the UI
      NTFY_ADMIN_SERVER_NAME: Home
      NTFY_ADMIN_NTFY_URL: http://ntfy:80                  # how the panel reaches ntfy
      NTFY_ADMIN_PUBLIC_URL: https://ntfy.example.com      # how phones reach ntfy (QR codes)
      NTFY_ADMIN_SOCKET: /run/ntfy/admin.sock              # only the super panel uses it
    volumes:
      - ./ntfy-admin:/data
    ports: ["8083:8080"]

  ntfy-admin-super:                     # super admin: admin socket, red UI
    image: ntfy-admin:latest
    environment:
      <<: *seed
      NTFY_ADMIN_SUPER: "true"
    group_add: ["0"]                    # ntfy runs as root: its socket is root:root 0660
    volumes:
      - ntfy-run:/run/ntfy
      - ./ntfy-admin:/data
    ports: ["127.0.0.1:8084:8080"]      # keep it close, see Security

volumes:
  ntfy-run:
```

Create the first admin once, then log in:

```sh
docker compose exec ntfy ntfy user add --role=admin yourname
```

Without the `NTFY_ADMIN_NTFY_URL` seed, the panel starts with a setup screen: enter
the server's URLs and admin credentials, and it is saved only if the login works.
`./ntfy-admin` must be writable by uid 65532 (`chown 65532 ./ntfy-admin`).

## Regular vs super admin

| | Regular (`NTFY_ADMIN_SUPER=false`) | Super (`NTFY_ADMIN_SUPER=true`) |
|---|---|---|
| Talks to ntfy over | HTTP admin API | admin socket where configured, else HTTP |
| Users, access rules, tokens, reset links | yes | yes |
| Change roles, create or edit **admin** users | no: ntfy refuses this over HTTP | yes |
| Tokens of admin users | hidden | yes |
| Looks | calm | red, striped, a little uncomfortable on purpose |

ntfy's admin socket is still marked *experimental* (since 2.36). The socket is the
authorization: anything that can open it is an admin. Mount it only into the super
panel. If ntfy runs as a non-root user, run the super panel with the same `user:`
or group instead of `group_add: ["0"]`.

## Configuration

All settings are environment variables:

| Variable | Default | |
|---|---|---|
| `NTFY_ADMIN_SUPER` | `false` | Super admin mode (see above) |
| `NTFY_ADMIN_SERVER_NAME`, `NTFY_ADMIN_NTFY_URL`, `NTFY_ADMIN_PUBLIC_URL`, `NTFY_ADMIN_SOCKET` | (none) | Seed the first server on first start. After that, servers live in `/data/servers.json` and are managed in the UI. |
| `NTFY_ADMIN_LOCK_SERVERS` | `false` | Make the server list read-only in the UI |
| `NTFY_ADMIN_LISTEN` | `:8080` | Listen address |
| `NTFY_ADMIN_DATA_DIR` | `/data` | `servers.json` and topic notes. No secrets. |
| `NTFY_ADMIN_SESSION_TTL` | `12h` | Login lifetime |
| `NTFY_ADMIN_BASE_PATH` | (none) | Serve under a sub-path, e.g. `/admin` |
| `NTFY_ADMIN_BEHIND_PROXY` | `false` | Trust `X-Forwarded-For` for the client IP (rate limiting, audit log) |
| `NTFY_ADMIN_COOKIE_SECURE` | `auto` | `auto` sets `Secure` when the request came over HTTPS (or `X-Forwarded-Proto: https`) |

The public URL matters: ntfy does not expose its `base-url` over the API, so QR codes
and examples are built from the public URL you set per server.

## Users that come from the config file

Users, rules and tokens defined in ntfy's `server.yml` (`auth-users`,
`auth-access`, `auth-tokens`) are **provisioned**: ntfy rebuilds them on every start
and refuses API changes to them. The panel shows them with a *provisioned* badge,
read-only. Pick one source of truth per user: the config file or this panel.

## Security

- **Login.** Only ntfy accounts with the `admin` role can log in, per server. Your password is
  checked by ntfy and then forgotten: the panel swaps it for a short-lived ntfy
  token (label `ntfy-admin session`, expires with the session, revoked at logout).
- **Sessions.** Kept in memory: a restart logs everyone out. The cookie is
  `HttpOnly` and `SameSite=Strict`. Every change also needs a per-session CSRF
  header. Failed logins are rate limited per IP.
- **Token values.** They never appear in lists. *Show* fetches one on demand, and
  that action is audit-logged.
- **Audit log.** Every change is logged to stdout (`action=… admin=… ip=…`), and ntfy
  logs it too.
- **Server list.** Any logged-in admin can add or edit servers. Re-pointing a server's URL
  logs everyone out of it, so tokens are never sent to the new target; lock the list with
  `NTFY_ADMIN_LOCK_SERVERS` if several teams share one panel.
- **Exposure.** The panel can read every token, and the super panel can create admins. Keep it on your
  LAN or VPN, or put SSO (Authelia, Authentik, oauth2-proxy) in front of it. Don't
  publish it on the internet like ntfy itself.
- **Hardening.** Strict CSP (no inline script or style), distroless non-root image.

## Development

```sh
docker compose -f test/compose.yml up -d --build    # ntfy 2.37 + regular and super panel
docker compose -f test/compose.yml exec ntfy sh -c 'NTFY_PASSWORD=adminpass123 ntfy user add --role=admin admin'
test/e2e.sh                                         # end-to-end tests against the real server (curl + jq)
```

Regular panel: http://127.0.0.1:18081 · super panel: http://127.0.0.1:18082 ·
ntfy: http://127.0.0.1:18080

No Go on the host? Build with `docker build -t ntfy-admin .`.

## License

Apache-2.0. Not affiliated with the ntfy project.
