from uuid import uuid4

from .audit import AuditTrail
from .domain import ConflictError, NotFoundError
from .rules import RuleEngine


class DomainService:
    def __init__(self, repository, rules=None):
        self.repository = repository
        self.rules = rules or RuleEngine()
        self.audit = AuditTrail(repository)

    def _lookup(self, kind, field, value):
        return self.repository.find_entities(self.rules.normalize_kind(kind), field, value)

    def health(self):
        return {"status": "ok" if self.repository.ping() else "error"}

    def create(self, actor, kind, data, idempotency_key=None):
        kind = self.rules.normalize_kind(kind)
        payload = dict(data or {})
        if idempotency_key:
            existing = self.repository.get_idempotency(actor.user_id, idempotency_key)
            if existing:
                entity = self.repository.get_entity(existing)
                if entity:
                    return entity
        self.rules.validate_create(actor, kind, payload, self._lookup)
        # A destruction receipt is unique per grant: re-submitting must not
        # produce a second receipt.
        if kind == "receipt":
            grant_id = payload.get("grant_id")
            if grant_id:
                existing = self.repository.find_entities("receipt", "grant_id", grant_id)
                if existing:
                    return existing[0]
        entity_id = str(payload.pop("id", "") or uuid4())
        if self.repository.get_entity(entity_id):
            raise ConflictError("entity already exists: " + entity_id)
        status = self.rules.initial_status(kind)
        entity = self.repository.create_entity(entity_id, kind, status, payload, actor.user_id)
        self.audit.record(entity_id, actor, "create", None, status, {"kind": kind})
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        expected = int(expected_version) if expected_version is not None else entity["version"]
        next_status, patch = self.rules.validate_transition(
            actor, entity, action, dict(data or {}), self._lookup
        )
        merged = dict(entity["data"])
        merged.update(patch)

        def guard(connection):
            # Re-validate against the latest committed state inside the write
            # transaction so a concurrent verify/approve cannot bypass the
            # pending receipt; the later party always reads the newest limit.
            tx_lookup = lambda kind, field, value: self.repository.find_entities_tx(
                connection, self.rules.normalize_kind(kind), field, value
            )
            self.rules.validate_transition(actor, entity, action, dict(data or {}), tx_lookup)

        def after_update(connection):
            self._apply_side_effects(connection, actor, entity, action)

        updated = self.repository.update_entity(
            entity_id, expected, next_status, merged, guard=guard, after_update=after_update
        )
        self.audit.record(
            entity_id,
            actor,
            action,
            entity["status"],
            updated["status"],
            {"patch": patch},
        )
        return updated

    def _apply_side_effects(self, connection, actor, entity, action):
        kind = entity["kind"]
        if kind == "grant" and action in ("revoke", "expire"):
            self._suspend_org_for_grant(connection, entity)
            self._ensure_receipt(connection, actor, entity)
        elif kind == "receipt" and action == "verify":
            self._reactivate_org_if_resolved(connection, entity)
        elif kind == "application" and action in ("approve", "reject", "withdraw"):
            self._reactivate_org_if_resolved(connection, entity)

    def _suspend_org_for_grant(self, connection, grant):
        org_id = grant["data"].get("recipient")
        if not org_id:
            return
        orgs = self.repository.find_entities_tx(connection, "organization", "id", org_id)
        if not orgs:
            return
        org = orgs[0]
        if org["status"] != "suspended":
            self.repository.update_entity_tx(connection, org["id"], "suspended", org["data"])

    def _ensure_receipt(self, connection, actor, grant):
        grant_id = grant["id"]
        existing = self.repository.find_entities_tx(connection, "receipt", "grant_id", grant_id)
        if existing:
            return
        receipt_id = str(uuid4())
        data = {
            "organization_id": grant["data"].get("recipient"),
            "grant_id": grant_id,
            "dataset_id": grant["data"].get("dataset_id"),
        }
        self.repository.create_entity_tx(
            connection, receipt_id, "receipt", "pending", data, actor.user_id
        )

    def _reactivate_org_if_resolved(self, connection, entity):
        if entity["kind"] == "receipt":
            org_id = entity["data"].get("organization_id")
        else:
            org_id = entity["data"].get("organization_id")
        if not org_id:
            return
        orgs = self.repository.find_entities_tx(connection, "organization", "id", org_id)
        if not orgs:
            return
        org = orgs[0]
        pending = self.repository.find_entities_tx(connection, "receipt", "organization_id", org_id)
        pending = [r for r in pending if r["status"] == "pending"]
        if pending:
            return
        if org["status"] != "active":
            self.repository.update_entity_tx(connection, org["id"], "active", org["data"])

    def get(self, entity_id):
        entity = self.repository.get_entity(entity_id)
        if not entity:
            raise NotFoundError("entity not found: " + entity_id)
        return entity

    def list(self, kind=None, status=None):
        if kind:
            kind = self.rules.normalize_kind(kind)
        return self.repository.list_entities(kind=kind, status=status)

    def audit_log(self, entity_id=None):
        return self.repository.list_audit(entity_id=entity_id)
