# Migrations

> **Status: REFERENCE** · Last verified: 2026-10-09
> Pointer page: this folder holds no migration guides; schema migrations are documented with the Postgres schema.

There is currently no Java-to-go-signal migration guide and no major-version upgrade guide in this folder.

Database schema migrations are embedded SQL files applied by the Postgres migrator. The file layout, ordering, locking and per-version tables are described in [../storage/schema-postgres.md](../storage/schema-postgres.md).
