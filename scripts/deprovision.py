#!/usr/bin/env python3
"""Turn ntfy's provisioned users/rules/tokens into normal rows (SQLite user database).

Run with ntfy STOPPED, before removing auth-users/auth-access/auth-tokens from ntfy's
config; otherwise ntfy deletes those rows at the next start. Nothing else changes:
passwords and token values stay the same. See docs/migrate-from-provisioning.md.

    python3 deprovision.py /path/to/user.db
"""
import sqlite3
import sys

TABLES = ("user", "user_access", "user_token")


def main(path):
    db = sqlite3.connect(path)
    try:
        for table in TABLES:
            n = db.execute("UPDATE %s SET provisioned = 0 WHERE provisioned = 1" % table).rowcount
            print("%s: %d rows de-provisioned" % (table, n))
        db.commit()
        left = sum(db.execute("SELECT COUNT(*) FROM %s WHERE provisioned = 1" % t).fetchone()[0] for t in TABLES)
    finally:
        db.close()
    print("still provisioned:", left)
    return 1 if left else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1]))
