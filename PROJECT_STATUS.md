# DocuVault implementation status

## Implemented

- Registration/login, bcrypt password hashing, JWT access/refresh tokens, refresh rotation/revocation, and OAuth2 form authorization.
- Owner/Editor/Viewer permission enforcement with separate test accounts.
- AES-256-GCM encrypted document storage, authenticated decryption, version creation/history/restore, and authorized UTF-8 downloads.
- Expiring/revocable share links, password-protected links, and single-use links.
- PostgreSQL title full-text search using the GIN/tsvector migration.
- Append-only audit records for auth, document/version, permission, and sharing actions; client IP where available; protected `/audit` listing.
- Additive Alembic migration `20261123_0002` for share password/one-time settings and audit IP addresses.
- Docker image runs as a non-root user and has a health check; Render blueprint, README, Postman collection, and Mermaid ER diagram are maintained.
- Production settings require `DATABASE_URL`, a 32-character minimum `JWT_SECRET_KEY`, and `DOCUVAULT_ENCRYPTION_KEY`; database/JWT secrets have no unsafe built-in defaults.
- `.dockerignore` excludes `.env` files and development artifacts from build context; local Compose PostgreSQL credentials are overridable.

## Verification results

- `python -m compileall -q app tests alembic`: passed.
- `python -m pytest -q --cov=app --cov-report=term-missing --cov-fail-under=90`: 26 passed, 1 skipped; 95.25% application coverage.
- PostgreSQL integration test: 1 passed against the Compose PostgreSQL service using a uniquely named temporary schema. Both migrations, real PostgreSQL FTS, and update/delete audit triggers were exercised; the schema was dropped afterward. No public-schema records were changed.
- The additive migration was applied to the local Compose database; Alembic reports `20261123_0002 (head)`. Existing user/document rows were not reset.
- Alembic offline SQL generation through `head`: passed.
- `docker compose config --quiet`: passed.
- `docker compose build api`: passed.
- The running Compose API's health, Swagger UI, and OpenAPI endpoints returned HTTP 200 before the current image build. The current Phase 10 image has not been deployed/recreated; its database-aware health route is covered by tests.
- Health now performs `SELECT 1` and reports 503 on database failure; this behavior is covered by API tests.
- Postman collection JSON parse: passed.
- Render deployment itself has not been run.

## Known scope limits

- Search is title-only; encrypted document bodies are not indexed.
- The current document API stores encrypted text content in PostgreSQL. Multipart upload of arbitrary binary files is not implemented.
- Swagger/OpenAPI and API endpoint behavior are verified with FastAPI tests; no external Render URL has been exercised.

## Operational safety

- Migration 0002 is additive and preserves existing rows. Run `alembic upgrade head` before deploying.
- The PostgreSQL integration fixture only creates and drops its generated temporary schema. Never point it at production.
- The configured AES key was not changed or regenerated.
