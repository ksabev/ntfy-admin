# Security

## What the panel can do

Someone logged in to the panel can do whatever ntfy's admin API allows for that server:

- the **regular panel**: create and delete users, change their passwords, read and
  revoke every token of a non-admin user, and grant access to any topic;
- the **super panel**, on top of that: create admins, demote or delete admins, and read
  admins' tokens.

Treat both like an admin console: **keep them off the internet**, even when ntfy itself
is public.

## Logins

- Only ntfy accounts with the **admin** role can log in, separately for each server.
- The password goes to ntfy once (`GET /v1/account`) and is then swapped for a
  short-lived ntfy token (label `ntfy-admin session`, expiring with the session). The
  panel never stores passwords.
- Sessions live in memory: restarting the panel logs everyone out. Logout, and a
  clean shutdown, revoke the session's ntfy tokens.
- Failed logins are limited to 8 per IP per 10 minutes. The client IP is also passed
  to ntfy, so ntfy's own rate limiting sees the real client when ntfy has
  `behind-proxy` set.
- Cookie: `HttpOnly`, `SameSite=Strict`, `Secure` over HTTPS. Every change also needs
  a per-session CSRF header.

## Token values

Token lists contain only the token's first characters and an opaque ID. The full
value comes from ntfy when someone clicks *Show*, and every *Show* is written to the
audit log. Exports never contain token values.

## The admin socket

ntfy's admin socket has no authentication: whoever can open the file is an admin.

- Mount it into the super panel only.
- The regular panel ignores socket settings, even ones stored in the shared `servers.json`.
- Opening it needs the socket's group (see [installation](install.md#the-admin-socket)).
  The panel process is never root.

## The server list

Any logged-in admin can add or change servers. Two safeguards:

- Changing a server's URL or socket logs everyone out of it first, so session tokens
  are never sent to the new target.
- A login sends the password to the server's URL as stored. If people you don't fully
  trust share one panel, lock the list (`NTFY_ADMIN_LOCK_SERVERS=true`) and manage
  `servers.json` yourself.

Before any server exists, the setup screen is open without a login. It saves a server
only after a successful admin login to that server. To skip the setup screen
altogether, seed the server with environment variables.

## Exposure

- Put the regular panel behind a reverse proxy that allows only private networks or
  your VPN, or behind SSO (Authelia, Authentik, oauth2-proxy). Examples are in
  [installation](install.md#reverse-proxy).
- An IP allow-list on the proxy only works if the proxy sees real client IPs. If
  another proxy or a NAT in front of it rewrites them to private addresses, the
  allow-list lets everyone in.
- Keep the super panel on localhost or a LAN address and reach it through an SSH
  tunnel or the LAN, not through the proxy.

## Hardening

- Strict Content Security Policy: no inline scripts or styles, no third-party origins.
  All DOM is built with `textContent`.
- `X-Frame-Options: DENY`, `nosniff`, `no-referrer`. API responses are `no-store`.
- Request bodies are limited to 64 KB, unknown JSON fields are rejected, and every name,
  topic and label is validated with ntfy's own rules before it reaches ntfy.
- The QR endpoint encodes only `ntfy://` and `http(s)://` links (max 512 characters)
  and needs a login.
- Distroless image, non-root user, no shell.

## Audit log

Every change is logged to stdout:

```
level=INFO msg=audit ip=10.0.20.17 server=home action=token.create admin=kamen user=publisher label="garage door sensor"
```

Actions: `login`, `logout`, `logout_all`, `server.setup|add|update|remove`,
`user.create|update|delete|reset_link`, `access.set|delete`,
`token.create|reveal|delete`, `topic.note|forget`, `publish`, `export`.
ntfy logs the same changes on its side, tagged `admin`.

## Reporting a problem

Open an issue, or for anything sensitive, contact the maintainer directly.
