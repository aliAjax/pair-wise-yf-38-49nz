from uuid import uuid4

from .audit import AuditTrail
from .domain import (
    ConflictError,
    NotFoundError,
)
from .rules import OPEN_APPLICATION_STATUSES, RuleEngine


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
        entity_id = str(payload.pop("id", "") or uuid4())
        # 跨对象校验（重复回执、凭证状态等）全部在写事务内用最新数据重跑。
        def plan(locked_lookup):
            checked = self.rules.validate_create(actor, kind, dict(payload), locked_lookup)
            return self.rules.initial_status(kind), checked

        entity = self.repository.create_guarded(
            kind, self.rules.initial_status(kind), plan, actor.user_id, entity_id
        )
        self._record_audits(
            [
                {
                    "entity_id": entity_id,
                    "actor_id": actor.user_id,
                    "actor_role": actor.role,
                    "action": "create",
                    "from_status": None,
                    "to_status": entity["status"],
                    "detail": {"kind": kind},
                }
            ]
        )
        if idempotency_key:
            self.repository.save_idempotency(actor.user_id, idempotency_key, entity_id)
        return entity

    def transition(self, actor, entity_id, action, data=None, expected_version=None):
        requested = dict(data or {})
        captured = {}

        def plan(entity, locked_lookup):
            next_status, patch = self.rules.validate_transition(
                actor, entity, action, dict(requested), locked_lookup
            )
            merged = dict(entity["data"])
            merged.update(patch)
            extras = []
            events = [
                {
                    "entity_id": entity_id,
                    "actor_id": actor.user_id,
                    "actor_role": actor.role,
                    "action": action,
                    "from_status": entity["status"],
                    "to_status": next_status,
                    "detail": {"patch": patch},
                }
            ]
            # 停用治理：回执核对通过后，对应已批准申请同步办结。
            if entity["kind"] == "destruction_receipt" and action == "verify":
                grant = self._locked_one(locked_lookup, "grant", "id", entity["data"].get("grant_id"))
                if grant:
                    application = self._locked_one(
                        locked_lookup, "application", "id", grant["data"].get("application_id")
                    )
                    if application and application["status"] == "approved":
                        app_merged = dict(application["data"])
                        reason = "destruction receipt %s verified" % entity_id
                        app_merged["closed_reason"] = reason
                        extras.append((application["id"], None, "closed", app_merged))
                        events.append(
                            {
                                "entity_id": application["id"],
                                "actor_id": actor.user_id,
                                "actor_role": actor.role,
                                "action": "close",
                                "from_status": "approved",
                                "to_status": "closed",
                                "detail": {"reason": reason, "receipt_id": entity_id},
                            }
                        )
            captured["events"] = events
            return next_status, merged, extras

        expected = int(expected_version) if expected_version is not None else None
        updated = self.repository.update_guarded(entity_id, expected, plan)
        self._record_audits(captured.get("events", []))
        return updated

    @staticmethod
    def _locked_one(locked_lookup, kind, field, value):
        if not value:
            return None
        rows = locked_lookup(kind, field, value) or []
        return rows[0] if rows else None

    def _record_audits(self, events):
        """写入审计；失败时把全部待写事件保留为待续项，后续可重试。"""
        for index, event in enumerate(events):
            try:
                self.repository.append_audit(
                    entity_id=event["entity_id"],
                    actor_id=event["actor_id"],
                    actor_role=event["actor_role"],
                    action=event["action"],
                    from_status=event["from_status"],
                    to_status=event["to_status"],
                    detail=event["detail"],
                )
            except Exception as exc:  # 写后失败：保留待续项，不丢治理记录
                self.repository.enqueue_pending(
                    "audit",
                    {"events": events[index:]},
                    last_error=str(exc),
                )
                raise ConflictError(
                    "audit write failed; remaining records queued as pending item"
                )

    def retry_pending(self, pending_id):
        item = self.repository.get_pending(pending_id)
        if not item:
            raise NotFoundError("pending item not found: " + pending_id)
        try:
            if item["kind"] == "audit":
                for event in item["payload"].get("events", []):
                    self.repository.append_audit(
                        entity_id=event["entity_id"],
                        actor_id=event["actor_id"],
                        actor_role=event["actor_role"],
                        action=event["action"],
                        from_status=event["from_status"],
                        to_status=event["to_status"],
                        detail=event["detail"],
                    )
            else:
                raise ConflictError("unknown pending item kind: " + item["kind"])
        except Exception as exc:
            self.repository.mark_pending_attempt(pending_id, str(exc))
            raise ConflictError("pending item retry failed: %s" % exc)
        self.repository.delete_pending(pending_id)
        return {"id": pending_id, "status": "completed"}

    def list_pending(self):
        return self.repository.list_pending()

    def governance_summary(self, recipient=None):
        applications = self.repository.list_entities(kind="application")
        receipts = self.repository.list_entities(kind="destruction_receipt")
        open_applications = [
            entity
            for entity in applications
            if entity["status"] in OPEN_APPLICATION_STATUSES
        ]
        pending_receipts = [
            entity for entity in receipts if entity["status"] == "pending"
        ]
        if recipient:
            open_applications = [
                entity
                for entity in open_applications
                if entity["data"].get("applicant_id") == recipient
            ]
            pending_receipts = [
                entity
                for entity in pending_receipts
                if entity["data"].get("recipient") == recipient
            ]
        return {
            "open_applications": open_applications,
            "pending_receipts": pending_receipts,
            "pending_items": self.repository.list_pending(),
        }

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
