import json
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from .domain import ConflictError, NotFoundError


def utcnow():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class SQLiteRepository:
    def __init__(self, path):
        self.path = str(path)
        self._initialize()

    def _connect(self):
        connection = sqlite3.connect(self.path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self):
        with self._connect() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS entities (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    status TEXT NOT NULL,
                    version INTEGER NOT NULL,
                    data TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_entities_kind_status
                    ON entities(kind, status);
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    actor_role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    from_status TEXT,
                    to_status TEXT NOT NULL,
                    detail TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_audit_entity
                    ON audit_log(entity_id, id);
                CREATE TABLE IF NOT EXISTS idempotency (
                    actor_id TEXT NOT NULL,
                    idem_key TEXT NOT NULL,
                    entity_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(actor_id, idem_key)
                );
                CREATE TABLE IF NOT EXISTS pending_items (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TEXT NOT NULL
                );
            """)

    @staticmethod
    def _entity_from_row(row):
        return {
            "id": row["id"],
            "kind": row["kind"],
            "status": row["status"],
            "version": int(row["version"]),
            "data": json.loads(row["data"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        }

    def create_entity(self, entity_id, kind, status, data, actor_id):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                (entity_id, kind, status, payload, actor_id, now, now),
            )
        return self.get_entity(entity_id)

    def get_entity(self, entity_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
        return self._entity_from_row(row) if row else None

    def list_entities(self, kind=None, status=None):
        clauses = []
        params = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM entities" + where + " ORDER BY created_at, id", params
            ).fetchall()
        return [self._entity_from_row(row) for row in rows]

    def find_entities(self, kind, field, value):
        return [
            entity
            for entity in self.list_entities(kind=kind)
            if (entity["id"] == value if field == "id" else entity["data"].get(field) == value)
        ]

    def update_entity(self, entity_id, expected_version, status, data):
        now = utcnow()
        payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
            if not row:
                raise NotFoundError("entity not found: " + entity_id)
            current_version = int(row["version"])
            if expected_version is not None and current_version != int(expected_version):
                raise ConflictError(
                    "version conflict: expected %s, found %s"
                    % (expected_version, current_version)
                )
            connection.execute(
                "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
                "WHERE id = ? AND version = ?",
                (status, payload, now, entity_id, current_version),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get_entity(entity_id)

    @staticmethod
    def _locked_lookup(connection):
        def lookup(kind, field, value):
            rows = connection.execute(
                "SELECT * FROM entities WHERE kind = ? ORDER BY created_at, id", (kind,)
            ).fetchall()
            result = []
            for row in rows:
                entity = SQLiteRepository._entity_from_row(row)
                if field == "id":
                    matched = entity["id"] == value
                else:
                    matched = entity["data"].get(field) == value
                if matched:
                    result.append(entity)
            return result

        return lookup

    def create_guarded(self, kind, status, plan, actor_id, entity_id):
        """在写事务内重新读取全部相关对象并执行跨对象校验。

        plan(locked_lookup) 返回 (status, data)；冲突由调用方转为领域异常。
        """
        now = utcnow()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            locked_lookup = self._locked_lookup(connection)
            final_status, data = plan(locked_lookup)
            if connection.execute(
                "SELECT 1 FROM entities WHERE id = ?", (entity_id,)
            ).fetchone():
                raise ConflictError("entity already exists: " + entity_id)
            payload = json.dumps(data, ensure_ascii=False, sort_keys=True)
            connection.execute(
                "INSERT INTO entities(id, kind, status, version, data, created_by, created_at, updated_at) "
                "VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                (entity_id, kind, final_status or status, payload, actor_id, now, now),
            )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get_entity(entity_id)

    def update_guarded(self, entity_id, expected_version, plan):
        """在写事务内重读实体并执行 plan；plan 可返回额外的同事务更新。

        plan(entity, locked_lookup) 返回 (next_status, data, extras)，
        extras 为 [(id, expected_version_or_None, next_status, data), ...]。
        校验在锁内使用最新数据完成，先到一方提交后，后到一方会读到最新限制。
        """
        now = utcnow()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM entities WHERE id = ?", (entity_id,)
            ).fetchone()
            if not row:
                raise NotFoundError("entity not found: " + entity_id)
            current_version = int(row["version"])
            if expected_version is not None and current_version != int(expected_version):
                raise ConflictError(
                    "version conflict: expected %s, found %s"
                    % (expected_version, current_version)
                )
            entity = self._entity_from_row(row)
            locked_lookup = self._locked_lookup(connection)
            next_status, data, extras = plan(entity, locked_lookup)
            updates = [(entity_id, current_version, next_status, data)]
            for extra_id, extra_expected, extra_status, extra_data in extras or []:
                extra_row = connection.execute(
                    "SELECT * FROM entities WHERE id = ?", (extra_id,)
                ).fetchone()
                if not extra_row:
                    raise NotFoundError("entity not found: " + extra_id)
                extra_version = int(extra_row["version"])
                if extra_expected is not None and extra_version != int(extra_expected):
                    raise ConflictError(
                        "version conflict: expected %s, found %s"
                        % (extra_expected, extra_version)
                    )
                updates.append((extra_id, extra_version, extra_status, extra_data))
            for target_id, target_version, target_status, target_data in updates:
                connection.execute(
                    "UPDATE entities SET status = ?, version = version + 1, data = ?, updated_at = ? "
                    "WHERE id = ? AND version = ?",
                    (
                        target_status,
                        json.dumps(target_data, ensure_ascii=False, sort_keys=True),
                        now,
                        target_id,
                        target_version,
                    ),
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()
        return self.get_entity(entity_id)

    def enqueue_pending(self, kind, payload, last_error=None, pending_id=None):
        pending_id = pending_id or uuid4().hex
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO pending_items(id, kind, payload, attempts, last_error, created_at) "
                "VALUES (?, ?, ?, 0, ?, ?)",
                (pending_id, kind, json.dumps(payload, ensure_ascii=False, sort_keys=True), last_error, utcnow()),
            )
        return pending_id

    def get_pending(self, pending_id):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM pending_items WHERE id = ?", (pending_id,)
            ).fetchone()
        return self._pending_from_row(row) if row else None

    def list_pending(self):
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM pending_items ORDER BY created_at, id"
            ).fetchall()
        return [self._pending_from_row(row) for row in rows]

    def mark_pending_attempt(self, pending_id, last_error):
        with self._connect() as connection:
            connection.execute(
                "UPDATE pending_items SET attempts = attempts + 1, last_error = ? WHERE id = ?",
                (last_error, pending_id),
            )

    def delete_pending(self, pending_id):
        with self._connect() as connection:
            connection.execute("DELETE FROM pending_items WHERE id = ?", (pending_id,))

    @staticmethod
    def _pending_from_row(row):
        return {
            "id": row["id"],
            "kind": row["kind"],
            "payload": json.loads(row["payload"]),
            "attempts": int(row["attempts"]),
            "last_error": row["last_error"],
            "created_at": row["created_at"],
        }

    def append_audit(self, entity_id, actor_id, actor_role, action, from_status, to_status, detail):
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO audit_log(entity_id, actor_id, actor_role, action, from_status, to_status, detail, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    entity_id,
                    actor_id,
                    actor_role,
                    action,
                    from_status,
                    to_status,
                    json.dumps(detail, ensure_ascii=False, sort_keys=True),
                    utcnow(),
                ),
            )

    def list_audit(self, entity_id=None):
        with self._connect() as connection:
            if entity_id:
                rows = connection.execute(
                    "SELECT * FROM audit_log WHERE entity_id = ? ORDER BY id", (entity_id,)
                ).fetchall()
            else:
                rows = connection.execute("SELECT * FROM audit_log ORDER BY id").fetchall()
        return [
            {
                "id": row["id"],
                "entity_id": row["entity_id"],
                "actor_id": row["actor_id"],
                "actor_role": row["actor_role"],
                "action": row["action"],
                "from_status": row["from_status"],
                "to_status": row["to_status"],
                "detail": json.loads(row["detail"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]

    def get_idempotency(self, actor_id, idem_key):
        with self._connect() as connection:
            row = connection.execute(
                "SELECT entity_id FROM idempotency WHERE actor_id = ? AND idem_key = ?",
                (actor_id, idem_key),
            ).fetchone()
        return row["entity_id"] if row else None

    def save_idempotency(self, actor_id, idem_key, entity_id):
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO idempotency(actor_id, idem_key, entity_id, created_at) "
                "VALUES (?, ?, ?, ?)",
                (actor_id, idem_key, entity_id, utcnow()),
            )

    def ping(self):
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()
        return True
