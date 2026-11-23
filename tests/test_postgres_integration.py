import os
import uuid

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError


@pytest.fixture(scope="module")
def migrated_postgres_schema():
    database_url = os.getenv("DOCUVAULT_TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("Set DOCUVAULT_TEST_DATABASE_URL to run isolated PostgreSQL integration tests")

    schema = f"docuvault_test_{uuid.uuid4().hex}"
    admin_engine = create_engine(database_url, pool_pre_ping=True)
    with admin_engine.begin() as connection:
        connection.execute(text(f'CREATE SCHEMA "{schema}"'))

    test_engine = create_engine(
        database_url,
        pool_pre_ping=True,
        connect_args={"options": f"-csearch_path={schema}"},
    )
    try:
        with test_engine.connect() as connection:
            config = Config("alembic.ini")
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        yield test_engine, schema
    finally:
        test_engine.dispose()
        with admin_engine.begin() as connection:
            connection.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin_engine.dispose()


def test_postgres_migrations_full_text_index_and_audit_trigger(migrated_postgres_schema):
    engine, schema = migrated_postgres_schema
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO users (email, password_hash, created_at) "
            "VALUES ('pg-test@example.com', 'not-used', now())"
        ))
        user_id = connection.execute(text(
            "SELECT id FROM users WHERE email = 'pg-test@example.com'"
        )).scalar_one()
        connection.execute(text(
            "INSERT INTO documents (owner_id, title, encrypted_content, created_at, updated_at) "
            "VALUES (:owner_id, 'Quarterly security review', decode('00', 'hex'), now(), now())"
        ), {"owner_id": user_id})
        document_id = connection.execute(text(
            "SELECT id FROM documents WHERE owner_id = :owner_id"
        ), {"owner_id": user_id}).scalar_one()
        matches = connection.execute(text(
            "SELECT id FROM documents WHERE "
            "to_tsvector('english', title) @@ websearch_to_tsquery('english', 'security review')"
        )).scalars().all()
        assert document_id in matches
        connection.execute(text(
            "INSERT INTO audit_logs (actor_id, action, resource_type, resource_id, details, created_at) "
            "VALUES (:actor_id, 'test', 'document', :resource_id, '{}', now())"
        ), {"actor_id": user_id, "resource_id": str(document_id)})
        audit_id = connection.execute(text(
            "SELECT id FROM audit_logs WHERE action = 'test'"
        )).scalar_one()

    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.execute(text(
                "UPDATE audit_logs SET action = 'mutated' WHERE id = :audit_id"
            ), {"audit_id": audit_id})
    with pytest.raises(DBAPIError):
        with engine.begin() as connection:
            connection.execute(text(
                "DELETE FROM audit_logs WHERE id = :audit_id"
            ), {"audit_id": audit_id})

    with engine.connect() as connection:
        trigger_exists = connection.execute(text(
            "SELECT 1 FROM pg_trigger "
            "WHERE tgname = 'audit_logs_immutable' AND tgrelid = 'audit_logs'::regclass"
        )).scalar_one_or_none()
        assert trigger_exists == 1
