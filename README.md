# migrate-fusionauth

A one-shot tool to migrate Storj satellite users to FusionAuth.

## Overview

The tool reads per-satellite CSV exports (from Redash or directly from the satellite DB), detects cross-satellite email conflicts, and produces a FusionAuth bulk-import JSON file. A second subcommand sends forgot-password emails to conflict users so they can set a new password after migration.

## Prerequisites

- Go 1.25+
- Access to each satellite's DB (via Redash or direct export)
- FusionAuth tenant ID and per-satellite Application IDs

## Step 1 — Export CSVs

### From Redash (default)

Run the following query against each satellite's Spanner DB in Redash and download the result as CSV:

```sql
SELECT
  id,
  email,
  normalized_email,
  full_name,
  created_at,
  external_id,
  tenant_id,
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
> SSO users (those with a non-empty `external_id`) are included in the export without a password; their old `external_id` values are preserved in `data.previousExternalIds` for rollback.

### From direct satellite DB exports (`--raw-csv`)

If exporting directly from the satellite database instead of Redash, pass `--raw-csv` to the `export` and `backfill-external-ids` commands. In this mode:

- `id` is read as a plain UUID string (e.g. `550e8400-e29b-41d4-a716-446655440000`) rather than hex-encoded bytes.
- `password_hash` is read as a plain string rather than hex-encoded bytes.
- `created_at` is parsed as `2006-01-02 15:04:05.999999 -07:00` rather than the Redash format `01/02/06 15:04`.

Save each file, e.g. `us1.csv`, `eu1.csv`, `ap1.csv`.

## Step 2 — Build the FusionAuth import file

```bash
go run . export \
  --csv-us1 us1.csv \
  --csv-eu1 eu1.csv \
  --csv-ap1 ap1.csv \
  --fusionauth-tenant-id <FA_TENANT_ID> \
  --app-id <FA_APP_ID> \
  --exclude-email-domains storj.io \
  --output fusionauth-import.json \
  --conflict-output conflict-users.json
```

Use `--dry-run` to print statistics without writing any files.

### Identity provider linking

If users with a non-empty `external_id` should be linked to a FusionAuth identity provider (e.g. Microsoft Entra), pass `--identity-provider-id`:

```bash
go run . export \
  ... \
  --identity-provider-id <FA_IDP_UUID>
```

The `external_id` value is expected to be either `<prefix>:<UserID>` (e.g. `entra:abc123`) or just `<UserID>`. The tool extracts the `UserID` part and embeds it as a `link` on each affected user in the export JSON. During import (Step 3) the tool performs a two-step process for these users: bulk import first, then `POST /api/identity-provider/link` to attach the IdP identity.

### Conflict detection

A **conflict** is when the same email (case-insensitive) exists on more than one satellite. Conflict users are exported **without a password** — they must reset it after migration. A single FusionAuth registration is created for the highest-precedence satellite (default order: `us1 > eu1 > ap1 > slc`, configurable via `--conflict-precedence`).

Non-conflict users are exported with their bcrypt password hash split into the components FusionAuth expects (`factor`, `salt`, `password`).

Both groups are written to `fusionauth-import.json`. A separate `conflict-users.json` lists each conflict user's email, satellites, and FusionAuth application ID — used in Step 4.

### Flags

| Flag                         | Default                  | Description                                                                                             |
|------------------------------|--------------------------|---------------------------------------------------------------------------------------------------------|
| `--csv-{us1,eu1,ap1,qa,slc}` |                          | Path to the CSV for that satellite                                                                      |
| `--fusionauth-tenant-id`     |                          | FusionAuth tenant ID                                                                                    |
| `--app-id`                   |                          | FusionAuth Application ID (shared across all satellites)                                                |
| `--identity-provider-id`     |                          | FusionAuth IdP UUID; when set, users with a non-empty `external_id` get a `link` embedded in the export |
| `--conflict-precedence`      | `us1,eu1,ap1,slc`        | Satellite priority for conflict users (highest first)                                                   |
| `--exclude-email-domains`    |                          | Comma-separated domains to skip (e.g. `storj.io`)                                                       |
| `--raw-csv`                  | `false`                  | Parse CSVs as direct satellite exports rather than Redash format                                        |
| `--output`                   | `fusionauth-import.json` | Output file for the FusionAuth import payload                                                           |
| `--conflict-output`          | `conflict-users.json`    | Output file listing conflict users                                                                      |
| `--dry-run`                  | `false`                  | Print stats without writing files                                                                       |

## Step 3 — Import into FusionAuth

```bash
go run . import \
  --fusionauth-url https://<FA_HOST> \
  --fusionauth-tenant-id <FA_TENANT_ID> \
  --api-key <FA_API_KEY> \
  --input fusionauth-import.json
```

The tool splits the file into batches (default 1000 users each) and sends them sequentially to `/api/user/import`, logging progress after each batch. Use `--batch-size` to tune if needed.

For users that carry an identity provider `link` (set during export via `--identity-provider-id`), the import performs a second step after each batch: it looks up each such user by email (`GET /api/user?email=...`) and calls `POST /api/identity-provider/link` to attach the IdP identity. Link failures are logged as warnings and do not abort the import.

| Flag                     | Default                  | Description                               |
|--------------------------|--------------------------|-------------------------------------------|
| `--fusionauth-url`       |                          | FusionAuth base URL                       |
| `--fusionauth-tenant-id` |                          | FusionAuth tenant ID                      |
| `--api-key`              |                          | FusionAuth API key                        |
| `--input`                | `fusionauth-import.json` | Import file from Step 2                   |
| `--batch-size`           | `1000`                   | Users per request                         |
| `--dry-run`              | `false`                  | Print batch plan without sending requests |

## Step 4 — Send password resets to conflict users

```bash
go run . send-password-resets \
  --fusionauth-url https://<FA_HOST> \
  --fusionauth-tenant-id <FA_TENANT_ID> \
  --api-key <FA_API_KEY> \
  --conflict-file conflict-users.json
```

This calls FusionAuth's `/api/user/forgot-password` for each conflict user, triggering a password-reset email. The tenant ID is sent as `X-FusionAuth-TenantId` to ensure the correct user is targeted when the same email exists across multiple tenants. The `applicationId` stored in the conflict file is included in the request body to select the application's email template; it does not affect which user receives the reset.

Use `--dry-run` to preview what would be sent without making any HTTP requests.

| Flag                     | Default               | Description                                      |
|--------------------------|-----------------------|--------------------------------------------------|
| `--fusionauth-url`       |                       | FusionAuth base URL                              |
| `--fusionauth-tenant-id` |                       | FusionAuth tenant ID                             |
| `--api-key`              |                       | FusionAuth API key                               |
| `--conflict-file`        | `conflict-users.json` | Conflict users file from Step 2                  |
| `--dry-run`              | `false`               | Print what would be sent without making requests |

## Step 5 — Backfill external_id in satellite DBs

After import, each FusionAuth user has a new FA UUID. This command queries the FA API, matches users to the original CSVs by email, and generates per-satellite SQL files with `UPDATE` statements to write those FA UUIDs back into the satellite's `external_id` column.

```bash
go run . backfill-external-ids \
  --fusionauth-url https://<FA_HOST> \
  --fusionauth-tenant-id <FA_TENANT_ID> \
  --api-key <FA_API_KEY> \
  --csv-us1 us1.csv \
  --csv-eu1 eu1.csv \
  --csv-ap1 ap1.csv \
  --output-dir ./sql
```

The `--fusionauth-tenant-id` flag scopes the FA user search to a single tenant, ensuring the email-to-FA-UUID mapping is unambiguous when the same email exists in multiple FA tenants.

This writes one file per satellite (e.g. `sql/us1-backfill-external-ids.sql`):

```sql
-- Satellite: us1
-- Generated: 2026-02-26T13:00:00Z
-- 12345 statements

UPDATE users SET external_id = 'fa-uuid-...' WHERE normalized_email = 'ALICE@EXAMPLE.COM' AND (tenant_id IS NULL OR tenant_id = '');
UPDATE users SET external_id = 'fa-uuid-...' WHERE normalized_email = 'BOB@EXAMPLE.COM' AND tenant_id = 'some-tenant';
...
```

The `AND tenant_id` condition is always included. When the CSV row has an empty or null `tenant_id`, the condition is `(tenant_id IS NULL OR tenant_id = '')` to match both representations. When a non-empty `tenant_id` is present, the condition is `AND tenant_id = '<value>'`. This ensures each statement targets exactly the right row in satellites where the same normalized email may appear under multiple tenants.

Hand the appropriate file to DevOps to run against each satellite's Spanner instance via `spanner-cli` or `gcloud spanner databases execute-sql`.

Use `--dry-run` to print match/missing statistics without writing any files.

> **Note:** `external_id` is also auto-populated on each user's first login — the satellite maps the FA `sub` claim to the local user by email. The backfill is only needed if you require `external_id` to be set before users log in.

### Flags

| Flag                         | Default | Description                                                        |
|------------------------------|---------|--------------------------------------------------------------------|
| `--fusionauth-url`           |         | FusionAuth base URL                                                |
| `--fusionauth-tenant-id`     |         | FusionAuth tenant ID (required; scopes user search to this tenant) |
| `--api-key`                  |         | FusionAuth API key                                                 |
| `--csv-{us1,eu1,ap1,qa,slc}` |         | Same CSVs used in the export step                                  |
| `--raw-csv`                  | `false` | Parse CSVs as direct satellite exports rather than Redash format   |
| `--output-dir`               | `.`     | Directory for generated `.sql` files                               |
| `--dry-run`                  | `false` | Print stats without writing files                                  |

## User data mapping

| Satellite field                               | FusionAuth field                                        | Notes                                                                                                                                                  |
|-----------------------------------------------|---------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `id`                                          | `data.storjUserId`                                      | Original satellite UUID                                                                                                                                |
| `email`                                       | `email`                                                 |                                                                                                                                                        |
| `password_hash`                               | `password` + `salt` + `factor`                          | bcrypt split; omitted for conflict users                                                                                                               |
| `status = 1`                                  | `verified: true`                                        |                                                                                                                                                        |
| `created_at`                                  | `insertInstant`                                         | Unix milliseconds; export fails fast if the value cannot be parsed                                                                                     |
| `mfa_secret_key` + `mfa_recovery_codes`       | `twoFactor`                                             | TOTP secret converted from base32 to base64                                                                                                            |
| `satellite name`                              | `data.sourceSatellite`, `registrations[].applicationId` |                                                                                                                                                        |
| `external_id`                                 | `data.previousExternalIds`                              | Map of `{ "us1": "<old-id>", ... }` for all satellites where the user had a non-empty `external_id`; omitted if none. Preserved for rollback purposes. |
| `external_id` (with `--identity-provider-id`) | `link.identityProviderUserId`                           | Parsed from `<prefix>:<UserID>` or `<UserID>`; linked via `POST /api/identity-provider/link` during import                                             |
| `tenant_id`                                   | _(not imported)_                                        | Used in backfill SQL `WHERE` clause to disambiguate rows with the same normalized email across tenants                                                 |
