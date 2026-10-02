from datetime import datetime, timedelta

from .domain import (
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)


# Applications that have not reached a terminal decision.
OPEN_APPLICATION_STATUSES = ("draft", "submitted", "under_review")


def _validate_dataset(actor, data, lookup):
    if len(data.get("access_policy", "")) < 3:
        raise ValidationError("access_policy is required")


def _validate_organization(actor, data, lookup):
    if not data.get("name", "").strip():
        raise ValidationError("name is required")


def _validate_application(actor, data, lookup):
    dataset = _find_one(lookup, "dataset", "id", data.get("dataset_id"))
    if not dataset:
        raise ValidationError("dataset does not exist")
    if not data.get("organization_id"):
        raise ValidationError("organization_id is required")
    org = _find_one(lookup, "organization", "id", data.get("organization_id"))
    if not org:
        raise ValidationError("organization does not exist")
    if not data.get("purpose", "").strip():
        raise ValidationError("purpose is required")


def _validate_approve(actor, entity, data, lookup):
    approvals = data.get("approvals") or []
    if len(set(approvals)) < 3:
        raise ValidationError("at least three distinct committee approvals are required")
    if data.get("conflict_of_interest"):
        raise PermissionDenied("conflicted reviewer cannot approve access")
    org = _find_one(lookup, "organization", "id", entity["data"].get("organization_id"))
    if org and org["status"] == "suspended":
        raise ValidationError(
            "cannot approve while organization is suspended; "
            "destruction receipt pending verification"
        )


def valid_grant_window(expires_at, as_of):
    return str(expires_at) >= str(as_of)


def _validate_grant_activate(actor, entity, data, lookup):
    if data.get("expires_at") < data.get("starts_at"):
        raise ValidationError("grant expiry must be after start")
    org = _find_one(lookup, "organization", "id", entity["data"].get("recipient"))
    if org and org["status"] == "suspended":
        raise ValidationError(
            "cannot activate grant while organization is suspended; "
            "destruction receipt pending verification"
        )
    if org:
        apps = lookup("application", "organization_id", org["id"]) or []
        open_apps = [a for a in apps if a["status"] in OPEN_APPLICATION_STATUSES]
        if open_apps:
            raise ValidationError("cannot activate grant while applications are open")
    return {"activated_by": actor.user_id}


def _validate_receipt_verify(actor, entity, data, lookup):
    return {"verified_by": actor.user_id}


CUSTOM_CREATE = {
    'dataset': _validate_dataset,
    'application': _validate_application,
    'organization': _validate_organization,
}
CUSTOM_TRANSITIONS = {
    ('application', 'approve'): _validate_approve,
    ('grant', 'activate'): _validate_grant_activate,
    ('receipt', 'verify'): _validate_receipt_verify,
}


class RuleEngine:
    OPEN_APPLICATION_STATUSES = OPEN_APPLICATION_STATUSES
    ALIASES = {
        'datasets': 'dataset',
        'applications': 'application',
        'grants': 'grant',
        'organizations': 'organization',
        'receipts': 'receipt',
    }
    INITIAL_STATUS = {
        'dataset': 'registered',
        'application': 'draft',
        'grant': 'issued',
        'organization': 'active',
        'receipt': 'pending',
    }
    TRANSITIONS = {
        'dataset': {
            'restrict': (('registered',), 'restricted'),
            'publish': (('restricted',), 'published'),
        },
        'application': {
            'submit': (('draft',), 'submitted'),
            'review': (('submitted',), 'under_review'),
            'approve': (('under_review',), 'approved'),
            'reject': (('under_review',), 'rejected'),
            'withdraw': (('submitted', 'under_review'), 'withdrawn'),
        },
        'grant': {
            'activate': (('issued',), 'active'),
            'revoke': (('active',), 'revoked'),
            'expire': (('active',), 'expired'),
        },
        'receipt': {
            'verify': (('pending',), 'verified'),
        },
    }
    CREATE_REQUIRED = {
        'dataset': ('name', 'access_policy'),
        'application': ('dataset_id', 'organization_id', 'applicant_id', 'purpose'),
        'grant': ('application_id', 'dataset_id', 'recipient'),
        'organization': ('name',),
        'receipt': ('organization_id', 'grant_id'),
    }
    ACTION_REQUIRED = {
        ('dataset', 'restrict'): ('reason',),
        ('application', 'review'): ('committee_id',),
        ('application', 'approve'): ('approvals', 'terms', 'expires_at'),
        ('application', 'reject'): ('reason',),
        ('application', 'withdraw'): ('reason',),
        ('grant', 'activate'): ('starts_at', 'expires_at'),
        ('grant', 'revoke'): ('reason',),
        ('grant', 'expire'): ('expired_at',),
    }
    CREATE_ROLES = {
        'dataset': ('admin', 'committee'),
        'application': ('admin', 'applicant'),
        'grant': ('admin', 'committee'),
        'organization': ('admin', 'committee'),
        'receipt': ('admin', 'committee'),
    }
    ROLE_ACTIONS = {
        'restrict': ('admin', 'committee'),
        'publish': ('admin', 'committee'),
        'submit': ('admin', 'applicant'),
        'review': ('admin', 'committee'),
        'approve': ('admin', 'committee'),
        'reject': ('admin', 'committee'),
        'withdraw': ('admin', 'applicant'),
        'activate': ('admin', 'committee'),
        'revoke': ('admin', 'committee'),
        'expire': ('admin', 'committee'),
        'verify': ('admin', 'auditor'),
    }

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
