# migrate-fusionauth

A one-shot tool to migrate Storj satellite users to FusionAuth.

## Overview

The tool reads per-satellite CSV exports from Redash (Spanner backend), detects cross-satellite email conflicts, and produces a FusionAuth bulk-import JSON file. A second subcommand sends forgot-password emails to conflict users so they can set a new password after migration.

## Prerequisites

- Go 1.25+
- Redash access to each satellite's Spanner DB
- FusionAuth tenant ID and per-satellite Application IDs

## Step 1 — Export CSVs from Redash

Run the following query against each satellite's Spanner DB in Redash and download the result as CSV:

```sql
SELECT
  id,
  email,
  normalized_email,
  full_name,
  created_at,
  external_id,
  mfa_enabled,
  mfa_secret_key,
  mfa_recovery_codes,
  password_hash,
  status
FROM users
WHERE status = 1
  AND tenant_id IS NULL
```

> `tenant_id IS NULL` limits the export to Storj-native accounts (excludes partner/whitelabel tenants).
> SSO users (those with a non-empty `external_id`) are automatically skipped during export.

Save each file, e.g. `us1.csv`, `eu1.csv`, `ap1.csv`.

## Step 2 — Build the FusionAuth import file

```bash
go run . export \
  --csv-us1 us1.csv        --app-id-us1 <FA_APP_ID_US1> \
  --csv-eu1 eu1.csv        --app-id-eu1 <FA_APP_ID_EU1> \
  --csv-ap1 ap1.csv        --app-id-ap1 <FA_APP_ID_AP1> \
  --fusionauth-tenant-id <FA_TENANT_ID> \
  --exclude-email-domains storj.io \
  --output fusionauth-import.json \
  --conflict-output conflict-users.json
```

Use `--dry-run` to print statistics without writing any files.

### Conflict detection

A **conflict** is when the same email (case-insensitive) exists on more than one satellite. Conflict users are exported **without a password** — they must reset it after migration. A single FusionAuth registration is created for the highest-precedence satellite (default order: `us1 > eu1 > ap1`, configurable via `--conflict-precedence`).

Non-conflict users are exported with their bcrypt password hash split into the components FusionAuth expects (`factor`, `salt`, `password`).

Both groups are written to `fusionauth-import.json`. A separate `conflict-users.json` lists each conflict user's email, satellites, and FusionAuth application ID — used in Step 4.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--csv-{us1,eu1,ap1,qa}` | | Path to the Redash CSV for that satellite |
| `--app-id-{us1,eu1,ap1,qa}` | | FusionAuth Application ID for that satellite |
| `--fusionauth-tenant-id` | | FusionAuth tenant ID |
| `--conflict-precedence` | `us1,eu1,ap1` | Satellite priority for conflict users (highest first) |
| `--exclude-email-domains` | | Comma-separated domains to skip (e.g. `storj.io`) |
| `--output` | `fusionauth-import.json` | Output file for the FusionAuth import payload |
| `--conflict-output` | `conflict-users.json` | Output file listing conflict users |
| `--dry-run` | `false` | Print stats without writing files |

## Step 3 — Import into FusionAuth

Use the FusionAuth bulk import API:

```bash
curl -s -X POST https://<FA_HOST>/api/user/import \
  -H "Authorization: <FA_API_KEY>" \
  -H "Content-Type: application/json" \
  -d @fusionauth-import.json
```

## Step 4 — Send password resets to conflict users

```bash
go run . send-password-resets \
  --fusionauth-url https://<FA_HOST> \
  --api-key <FA_API_KEY> \
  --conflict-file conflict-users.json
```

This calls FusionAuth's `/api/user/forgot-password` for each conflict user, triggering a password-reset email. Use `--dry-run` to preview what would be sent without making any HTTP requests.

## Step 5 — Backfill external_id in satellite DBs

After import, each FusionAuth user has a new FA UUID. This command queries the FA API, matches users to the original CSVs by email, and generates per-satellite SQL files with `UPDATE` statements to write those FA UUIDs back into the satellite's `external_id` column.

```bash
go run . backfill-external-ids \
  --fusionauth-url https://<FA_HOST> \
  --api-key <FA_API_KEY> \
  --csv-us1 us1.csv \
  --csv-eu1 eu1.csv \
  --csv-ap1 ap1.csv \
  --output-dir ./sql
```

This writes one file per satellite (e.g. `sql/us1-backfill-external-ids.sql`):

```sql
-- Satellite: us1
-- Generated: 2026-02-26T13:00:00Z
-- 12345 statements

UPDATE users SET external_id = 'fa-uuid-...' WHERE normalized_email = 'ALICE@EXAMPLE.COM';
...
```

Hand the appropriate file to DevOps to run against each satellite's Spanner instance via `spanner-cli` or `gcloud spanner databases execute-sql`.

Use `--dry-run` to print match/missing statistics without writing any files.

> **Note:** `external_id` is also auto-populated on each user's first login — the satellite maps the FA `sub` claim to the local user by email. The backfill is only needed if you require `external_id` to be set before users log in.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--fusionauth-url` | | FusionAuth base URL |
| `--api-key` | | FusionAuth API key |
| `--csv-{us1,eu1,ap1,qa}` | | Same CSVs used in the export step |
| `--output-dir` | `.` | Directory for generated `.sql` files |
| `--dry-run` | `false` | Print stats without writing files |

## User data mapping

| Satellite field | FusionAuth field | Notes |
|----------------|-----------------|-------|
| `id` | `data.storjUserId` | Original satellite UUID |
| `email` | `email` | |
| `password_hash` | `password` + `salt` + `factor` | bcrypt split; omitted for conflict users |
| `status = 1` | `verified: true` | |
| `created_at` | `insertInstant` | Unix milliseconds |
| `mfa_secret_key` + `mfa_recovery_codes` | `twoFactor` | TOTP secret converted from base32 to base64 |
| `satellite name` | `data.sourceSatellite`, `registrations[].applicationId` | |
