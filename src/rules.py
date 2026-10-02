from datetime import datetime, timedelta

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


# 申请尚未办结的状态： rejected/withdrawn 从未放行，closed 是凭证到期或撤销、
# 销毁回执核对通过后的办结状态。
OPEN_APPLICATION_STATUSES = ("draft", "submitted", "under_review", "approved")
GRANT_CLOSED_STATUSES = ("revoked", "expired")


def _validate_dataset(actor, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")


def _validate_application(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")


def _validate_approve(actor, entity, data, lookup):
    approvals = data.get("approvals") or []
    if len(set(approvals)) < 3:
        raise ValidationError("at least three distinct committee approvals are required")
    if data.get("conflict_of_interest"):
        raise PermissionDenied("conflicted reviewer cannot approve access")
    # 停用治理：申请方存在待核销毁回执时，委员会不得继续放行新申请。
    applicant = data.get("applicant_id") or entity["data"].get("applicant_id")
    pending = _pending_receipts(lookup, applicant)
    if pending:
        raise ConflictError(
            "cannot approve while destruction receipts await verification: %s"
            % ", ".join(item["id"] for item in pending)
        )


def valid_grant_window(expires_at, as_of):
    return str(expires_at) >= str(as_of)


def _validate_grant_activate(actor, entity, data, lookup):
    if data.get("expires_at") < data.get("starts_at"):
        raise ValidationError("grant expiry must be after start")
    recipient = entity["data"].get("recipient")
    application_id = entity["data"].get("application_id")
    # 停用治理：待核销毁回执未核对，不能启用新凭证。
    pending = _pending_receipts(lookup, recipient)
    if pending:
        raise ConflictError(
            "cannot activate grant while destruction receipts await verification: %s"
            % ", ".join(item["id"] for item in pending)
        )
    # 停用治理：该机构仍有未结申请时，新凭证不能启用（本凭证对应的申请不算）。
    open_applications = _open_applications(lookup, recipient, exclude=application_id)
    if open_applications:
        raise ConflictError(
            "cannot activate grant while open applications exist: %s"
            % ", ".join(item["id"] for item in open_applications)
        )
    return {"activated_by": actor.user_id}


def _validate_receipt(actor, data, lookup):
    grant = _find_one(lookup, "grant", "id", data.get("grant_id"))
    if not grant:
        raise ValidationError("grant does not exist")
    if grant["status"] not in GRANT_CLOSED_STATUSES:
        raise InvalidTransition(
            "destruction receipt only accepted for revoked or expired grants"
        )
    recipient = data.get("recipient") or grant["data"].get("recipient")
    if not recipient:
        raise ValidationError("recipient is required")
    # 重复提交不生成第二份回执：同一凭证的待核/已核回执均阻断。
    existing = _find_one(lookup, "destruction_receipt", "grant_id", grant["id"])
    if existing:
        raise ConflictError("destruction receipt already submitted: " + existing["id"])
    data["recipient"] = recipient
    data["dataset_id"] = grant["data"].get("dataset_id")


def _validate_receipt_verify(actor, entity, data, lookup):
    if not data.get("confirmed"):
        raise ValidationError("confirmed is required to verify a destruction receipt")
    return {"verified_by": actor.user_id, "verified_note": data.get("note", "")}


def _pending_receipts(lookup, recipient):
    if lookup is None or not recipient:
        return []
    return [
        item
        for item in (lookup("destruction_receipt", "recipient", recipient) or [])
        if item["status"] == "pending"
    ]


def _open_applications(lookup, applicant, exclude=None):
    if lookup is None or not applicant:
        return []
    return [
        item
        for item in (lookup("application", "applicant_id", applicant) or [])
        if item["status"] in OPEN_APPLICATION_STATUSES and item["id"] != exclude
    ]


CUSTOM_CREATE = {'dataset': _validate_dataset, 'application': _validate_application, 'destruction_receipt': _validate_receipt}
CUSTOM_TRANSITIONS = {('application', 'approve'): _validate_approve, ('grant', 'activate'): _validate_grant_activate, ('destruction_receipt', 'verify'): _validate_receipt_verify}


class RuleEngine:
    ALIASES = {'datasets': 'dataset', 'applications': 'application', 'grants': 'grant', 'destruction_receipts': 'destruction_receipt', 'receipts': 'destruction_receipt'}
    INITIAL_STATUS = {'dataset': 'registered', 'application': 'draft', 'grant': 'issued', 'destruction_receipt': 'pending'}
    TRANSITIONS = {'dataset': {'restrict': (('registered',), 'restricted'), 'publish': (('restricted',), 'published')}, 'application': {'submit': (('draft',), 'submitted'), 'review': (('submitted',), 'under_review'), 'approve': (('under_review',), 'approved'), 'reject': (('under_review',), 'rejected'), 'withdraw': (('submitted', 'under_review'), 'withdrawn'), 'close': (('approved',), 'closed')}, 'grant': {'activate': (('issued',), 'active'), 'revoke': (('active',), 'revoked'), 'expire': (('active',), 'expired')}, 'destruction_receipt': {'verify': (('pending',), 'verified')}}
    CREATE_REQUIRED = {'dataset': ('name', 'access_policy'), 'application': ('dataset_id', 'applicant_id', 'purpose'), 'grant': ('application_id', 'dataset_id', 'recipient'), 'destruction_receipt': ('grant_id',)}
    ACTION_REQUIRED = {('dataset', 'restrict'): ('reason',), ('application', 'review'): ('committee_id',), ('application', 'approve'): ('approvals', 'terms', 'expires_at'), ('application', 'reject'): ('reason',), ('application', 'withdraw'): ('reason',), ('grant', 'activate'): ('starts_at', 'expires_at'), ('grant', 'revoke'): ('reason',), ('grant', 'expire'): ('expired_at',), ('destruction_receipt', 'verify'): ('confirmed',)}
    CREATE_ROLES = {'dataset': ('admin', 'committee'), 'application': ('admin', 'applicant'), 'grant': ('admin', 'committee'), 'destruction_receipt': ('admin', 'auditor', 'applicant')}
    ROLE_ACTIONS = {'restrict': ('admin', 'committee'), 'publish': ('admin', 'committee'), 'submit': ('admin', 'applicant'), 'review': ('admin', 'committee'), 'approve': ('admin', 'committee'), 'reject': ('admin', 'committee'), 'withdraw': ('admin', 'applicant'), 'close': ('admin', 'auditor'), 'activate': ('admin', 'committee'), 'revoke': ('admin', 'committee'), 'expire': ('admin', 'committee'), 'verify': ('admin', 'auditor')}

    def normalize_kind(self, kind):
        return self.ALIASES.get(kind, kind)

    def initial_status(self, kind):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        return self.INITIAL_STATUS[kind]

    @staticmethod
    def _ensure_role(actor, allowed):
        if "*" not in allowed and actor.role not in allowed:
            raise PermissionDenied("role %s is not allowed here" % actor.role)

    @staticmethod
    def _require(data, fields):
        for field in fields:
            value = data.get(field)
            if value is None or value == "" or value == [] or value == {}:
                raise ValidationError("missing required field: " + field)

    def validate_create(self, actor, kind, data, lookup=None):
        kind = self.normalize_kind(kind)
        if kind not in self.INITIAL_STATUS:
            raise ValidationError("unknown kind: " + str(kind))
        self._ensure_role(actor, self.CREATE_ROLES.get(kind, ("admin",)))
        self._require(data, self.CREATE_REQUIRED.get(kind, ()))
        custom = CUSTOM_CREATE.get(kind)
        if custom:
            custom(actor, data, lookup)
        return dict(data)

    def validate_transition(self, actor, entity, action, data, lookup=None):
        kind = self.normalize_kind(entity["kind"])
        transition = self.TRANSITIONS.get(kind, {}).get(action)
        if not transition:
            raise InvalidTransition("unknown action %s for %s" % (action, kind))
        allowed_statuses, next_status = transition
        if entity["status"] not in allowed_statuses:
            raise InvalidTransition(
                "cannot %s from status %s" % (action, entity["status"])
            )
        allowed_roles = self.ROLE_ACTIONS.get(
            (kind, action), self.ROLE_ACTIONS.get(action, ("admin",))
        )
        self._ensure_role(actor, allowed_roles)
        self._require(data, self.ACTION_REQUIRED.get((kind, action), ()))
        custom = CUSTOM_TRANSITIONS.get((kind, action))
        extra = custom(actor, entity, data, lookup) if custom else {}
        patch = dict(data)
        if extra:
            patch.update(extra)
        return next_status, patch


def _find_one(lookup, kind, field, value):
    if lookup is None:
        return None
    rows = lookup(kind, field, value) or []
    return rows[0] if rows else None


def _date_ordinal(value):
    return datetime.fromisoformat(str(value)[:10]).date().toordinal()
