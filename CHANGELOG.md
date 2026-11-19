# Changelog

## 0.2.4 (2026-11-19)

- No more flash of unstyled content on page load in Firefox
  ([#2](https://github.com/ksabev/ntfy-admin/issues/2)). Screens start hidden with the
  `hidden` attribute instead of a CSS class, and the UI starts after the stylesheet has
  loaded.

## 0.2.3 (2026-11-18)

- `NTFY_ADMIN_BASE_PATH` works behind proxies that strip the sub-path, such as Apache
  with `ProxyPass /admin http://host:port`, as well as those that forward it
  ([#1](https://github.com/ksabev/ntfy-admin/issues/1)).
- Docs: Apache example for running under a sub-path.

## 0.2.2 (2026-11-11)

- Dialogs close after a successful save (new topic note, access rule, server, ...).
  Before, the form stayed open as if nothing happened.
- Onboarding: with more than 3 topics the QR codes get smaller; click one to show it
  alone and large, so the phone can't scan its neighbour by mistake.
- Onboarding warns that the ntfy app keeps one user per server: adding a second user on
  a phone replaces the first, and all other topics on that server stop working.
- Docs: ntfy is dropping the `experimental-` prefix of `listen-admin-unix`.

## 0.2.1 (2026-11-08)

- Published images on `ghcr.io/ksabev/ntfy-admin` for amd64, arm64 and armv7, built
  by GitHub Actions. CI runs the end-to-end suite against a real ntfy on every push.
- Documentation points to the published image.

## 0.2.0 (2026-11-08)

- **Many servers:** add, edit and remove ntfy servers in the UI (`/data/servers.json`).
  Environment variables now only seed the first server; `NTFY_ADMIN_LOCK_SERVERS`
  freezes the list.
- **Setup screen** on first start without servers. A server is saved only after a
  working admin login.
- One browser session can be logged in to several servers.
- **Super admin mode** (`NTFY_ADMIN_SUPER=true`): only this mode uses admin sockets
  (roles, admin users). Red, striped UI. Regular and super panels can share `/data`.
- Topic notes are stored per server.
- `scripts/deprovision.py` and a guide for migrating away from `auth-users`.
- Documentation in `docs/`.

## 0.1.0 (2026-11-08)

- First version: users, access rules, access matrix, tokens (ntfy 2.36+), onboarding
  cards with QR codes, topic notes, test messages and YAML export.
- Works over ntfy's HTTP admin API or its admin socket.
- Login with an ntfy admin account, swapped for a short-lived ntfy token.
