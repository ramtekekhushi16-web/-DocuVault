# DocuVault API

DocuVault is a FastAPI document vault backed by PostgreSQL. It provides bearer-token authentication, rotating refresh tokens, owner/editor/viewer access, encrypted document bodies, version history, expiring read-only share links, title search, and append-only audit events.

## Requirements

- Python 3.12
- PostgreSQL 16 (or Docker Compose)
- An AES key encoded as URL-safe base64, exactly 32 decoded bytes

Create a local `.env` from `.env.example` and replace every placeholder. The API requires `DATABASE_URL`, a `JWT_SECRET_KEY` of at least 32 characters, and `DOCUVAULT_ENCRYPTION_KEY`; it does not fall back to a hard-coded JWT secret or database URL. `JWT_ALGORITHM`, access/refresh lifetimes, share lifetime, and the document size limit are configurable environment variables.

| Variable | Required | Purpose |
|---|---:|---|
| `DATABASE_URL` | Yes | SQLAlchemy PostgreSQL connection URL. |
| `JWT_SECRET_KEY` | Yes | Random signing secret, at least 32 characters; keep private. |
| `DOCUVAULT_ENCRYPTION_KEY` | Yes | URL-safe base64 key that decodes to exactly 32 bytes. Keep unchanged for existing data. |
| `JWT_ALGORITHM` | No | JWT signing algorithm; defaults to `HS256`. |
| `ACCESS_TOKEN_MINUTES` | No | Access-token lifetime; defaults to 15 minutes. |
| `REFRESH_TOKEN_DAYS` | No | Refresh-token lifetime; defaults to 30 days. |
| `SHARE_TOKEN_DAYS` | No | Default share-link lifetime; defaults to 7 days. |
| `MAX_DOCUMENT_BYTES` | No | Maximum UTF-8 document content size; defaults to 2,000,000 bytes. |

Generate a new encryption key only for a new deployment/database, using PowerShell:

```powershell
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Use the generated value for `DOCUVAULT_ENCRYPTION_KEY`; set `JWT_SECRET_KEY` to a separate random value at least 32 characters long. Never regenerate or rotate the existing encryption key: existing document bodies and versions cannot be decrypted without it. `.env` is ignored by Git; do not commit it or put secrets in container images.

## Run locally

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
alembic upgrade head
uvicorn app.main:app --reload
```

Or start the API and PostgreSQL with Docker Compose after creating `.env`:

```powershell
docker compose up --build -d
docker compose ps
docker compose logs -f api
```

Stop services without deleting the database volume with `docker compose down`. Do not use `docker compose down -v` unless you explicitly intend to delete the local PostgreSQL volume. Compose's `postgres/postgres` credentials are local-development defaults only; override `POSTGRES_PASSWORD` in `.env` for non-local use. Changing the password for a database with an existing volume also requires rotating the PostgreSQL role password consistently. Render uses its managed database connection string and does not use this Compose credential.

Interactive API documentation is available at `/docs` (OpenAPI JSON at `/openapi.json`). `/health` performs a database connectivity check and returns 503 if PostgreSQL is unavailable. Container startup runs Alembic migrations before starting Uvicorn.

## Authentication and API

1. `POST /auth/register` with `{ "email": "...", "password": "at least 12 characters" }`.
2. `POST /auth/login` as form data (`username`, `password`) to get access and refresh tokens. The account email may also be sent as the `email` form field.
3. Send `Authorization: Bearer <access_token>` for protected routes.
4. `POST /auth/refresh` with JSON `{ "refresh_token": "..." }` to rotate it. Store and use the newly returned refresh token; the old token is single-use and rejected. `POST /auth/logout` revokes the supplied refresh token.

Protected API groups:

- `/documents`: create, list, read, update, delete, and download documents; owners grant/revoke editor and viewer access.
- `/documents/{id}/versions`: list snapshots and restore an earlier version (restoration creates a new version).
- `/shares/{document_id}` and `/shares/public/{token}`: issue expiring read-only sharing links, optionally password-protect or make them one-time, and revoke them.
- `/search?q=...`: search accessible document titles.
- `/audit`: list events performed by you and events for documents you own.

Owners can read, edit, share, grant permissions, and delete. Editors can read, edit, and create/revoke share links. Viewers can only read. Unauthorized users receive a not-found response for document reads, preventing document ID discovery.

To grant document access, an owner sends `PUT /documents/{document_id}/permissions` with `{"user_email":"collaborator@example.com","role":"viewer"}` (the `email` property is also accepted). The collaborator must already be registered; roles are `viewer` or `editor`. Unknown users return 404, while invalid request fields or roles return 422.

Document content and version snapshots are encrypted using AES-256-GCM with a fresh 96-bit nonce for each encryption. Titles remain plaintext so PostgreSQL can perform indexed full-text search; body search is intentionally not offered because indexing decrypted bodies would expose plaintext at rest. The GIN index uses PostgreSQL's English text-search configuration.

Use `GET /documents/{document_id}/download` with a bearer access token to download the authorized document as UTF-8 text. The response is decrypted only after the access check and is marked `no-store`.

Create a protected share with `POST /shares/{document_id}` and JSON such as `{"expires_in_days":7,"password":"A strong share passphrase 123!","one_time":true}`. Send the password in the `X-Share-Password` header when reading `/shares/public/{token}`. A one-time link is consumed after successful authentication and decryption; a missing or incorrect password does not consume it.

Audit events include the actor, resource, timestamp, and client IP when available. They are append-only in application code and protected by a PostgreSQL trigger against updates/deletes. `/audit` returns only events for the current actor or their owned documents. Audit details never include document text, passwords, hashes, or share tokens.

## Migrations and tests

```powershell
alembic upgrade head
python -m pytest --cov=app --cov-report=term-missing --cov-fail-under=90
```

The standard API tests use in-memory SQLite and do not touch the configured PostgreSQL database. The PostgreSQL integration test creates a uniquely named temporary schema, applies migrations there, checks full-text search and the audit trigger, then drops only that test schema. To run it, set `DOCUVAULT_TEST_DATABASE_URL` to a dedicated PostgreSQL test database URL and run `python -m pytest tests/test_postgres_integration.py -q`. Never point this variable at a production database.

## Deployment

`render.yaml` provisions a Render web service and PostgreSQL database. To deploy manually:

1. Push the project to a Git provider connected to Render and create a Blueprint from `render.yaml`.
2. Review the web-service and database plans/region before confirming resource creation.
3. In the Render service environment, set `DOCUVAULT_ENCRYPTION_KEY` to the existing deployment key (URL-safe base64 for exactly 32 bytes). Do not generate a replacement for a database that already contains encrypted documents.
4. Confirm Render generated `JWT_SECRET_KEY` and supplied the managed `DATABASE_URL`; keep those values in Render's secret environment, not source control.
5. Deploy the web service. Its Docker startup applies Alembic migrations before Uvicorn starts. Verify `/health`, `/docs`, and deployment logs. No deployment is performed by these local checks.

Enable database backups and restrict production database access to the application. Do not copy production secrets into `.env.example`, Docker build arguments, or committed files.

The container applies additive Alembic migrations on startup and runs as an unprivileged user. To rebuild the local API after source changes, use `docker compose up --build -d api`; this does not remove the PostgreSQL volume. Keep the Render encryption key stable and back it up separately: losing it makes existing content unrecoverable.

The [Postman collection](./docs/DocuVault.postman_collection.json) and [Mermaid ER diagram](./docs/er_diagram.mmd) are in `docs/`.