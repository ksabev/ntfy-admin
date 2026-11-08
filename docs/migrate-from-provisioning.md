# Migrating from `auth-users` (provisioned users)

ntfy can define users, rules and tokens in its config file:

```yaml
auth-users:
  - "phil:$2a$10$...:user"
auth-access:
  - "phil:alerts:rw"
auth-tokens:
  - "phil:tk_...:laptop"
```

ntfy marks these rows **provisioned**. It rebuilds them on every start and refuses to
change them through the admin API (HTTP 409), so ntfy-admin shows them read-only.

To manage them in the panel, turn them into normal rows. **No password or token
changes:** phones, scripts and bridges keep working.

> The order matters. If you only delete `auth-*` from the config, ntfy **deletes those
> users and tokens** at the next start. Mark the rows as normal first, then remove the
> config.

## Steps

The example assumes Docker Compose, SQLite, and the user database at
`./ntfy/lib/user.db` on the host. (For PostgreSQL, run the same `UPDATE` statements
with `psql`.)

1. **Back up.**
   ```sh
   mkdir -p backup
   cp ntfy/lib/user.db backup/user.db
   cp ntfy/config/server.yml backup/server.yml
   cp docker-compose.yml backup/
   ```
2. **Stop ntfy** (the rows can't change under a running server):
   ```sh
   docker compose stop ntfy
   ```
3. **De-provision** with [`scripts/deprovision.py`](../scripts/deprovision.py) (Python 3,
   standard library only):
   ```sh
   python3 scripts/deprovision.py ntfy/lib/user.db
   # user: 4 rows de-provisioned
   # user_access: 5 rows de-provisioned
   # user_token: 5 rows de-provisioned
   # still provisioned: 0
   ```
   It is the same as:
   ```sql
   UPDATE user        SET provisioned = 0 WHERE provisioned = 1;
   UPDATE user_access SET provisioned = 0 WHERE provisioned = 1;
   UPDATE user_token  SET provisioned = 0 WHERE provisioned = 1;
   ```
4. **Remove `auth-users`, `auth-access` and `auth-tokens`** from ntfy's config (file or
   `NTFY_AUTH_USERS` / `NTFY_AUTH_ACCESS` / `NTFY_AUTH_TOKENS` environment variables).
5. **Upgrade ntfy if needed** (2.36+ for the full panel), and add the admin socket if you
   run the super panel.
6. **Start ntfy**, then check that nothing says *server config* any more:
   ```sh
   docker compose up -d ntfy
   docker compose exec ntfy ntfy user list
   ```
7. **Test a token without sending a notification:**
   ```sh
   curl -H "Authorization: Bearer tk_..." https://ntfy.example.com/v1/account
   ```
8. Make sure you have an admin account (`ntfy user change-role <name> admin`), then log
   in to the panel.

## Rollback

```sh
docker compose stop ntfy
cp backup/user.db ntfy/lib/user.db
cp backup/server.yml ntfy/config/server.yml
cp backup/docker-compose.yml .
docker compose up -d ntfy
```

A database that a newer ntfy has opened may not go back to an older version (ntfy
refuses to start on a schema it doesn't know). That is why the backup is taken before
the upgrade.

## Tested

This procedure was rehearsed on ntfy 2.25 → 2.37.2, then run on a production server.
All passwords and all five tokens kept working, and the former provisioned users could
be edited through the API.
