import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from src.domain import Actor, PermissionDenied, ValidationError
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


def _setup(service):
    admin = Actor("admin", "admin")
    org = service.create(admin, "organization", {"name": "Rare Disease Consortium"})
    dataset = service.create(
        admin, "dataset", {"name": "Rare Disease Cohort", "access_policy": "controlled"}
    )
    return admin, org, dataset


def _approved_application(service, admin, org, dataset):
    app = service.create(
        admin,
        "application",
        {
            "dataset_id": dataset["id"],
            "organization_id": org["id"],
            "applicant_id": "APP-1",
            "purpose": "variant analysis",
        },
    )
    service.transition(admin, app["id"], "submit", {})
    service.transition(admin, app["id"], "review", {"committee_id": "committee-a"})
    service.transition(
        admin,
        app["id"],
        "approve",
        {"approvals": ["r1", "r2", "r3"], "terms": "noncommercial", "expires_at": "2099-01-01"},
    )
    return service.get(app["id"])


def _open_application(service, admin, org, dataset):
    app = service.create(
        admin,
        "application",
        {
            "dataset_id": dataset["id"],
            "organization_id": org["id"],
            "applicant_id": "APP-2",
            "purpose": "follow-up analysis",
        },
    )
    service.transition(admin, app["id"], "submit", {})
    service.transition(admin, app["id"], "review", {"committee_id": "committee-a"})
    return service.get(app["id"])


def _grant(service, admin, org, dataset, app):
    return service.create(
        admin,
        "grant",
        {
            "application_id": app["id"],
            "dataset_id": dataset["id"],
            "recipient": org["id"],
        },
    )


def _activate(service, admin, grant):
    return service.transition(
        admin,
        grant["id"],
        "activate",
        {"starts_at": "2026-09-24", "expires_at": "2099-01-01"},
    )


class GovernanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())

    def tearDown(self):
        self.tmp.cleanup()

    def test_revoke_suspends_org_and_creates_pending_receipt(self):
        admin, org, dataset = _setup(self.service)
        app = _approved_application(self.service, admin, org, dataset)
        grant = _grant(self.service, admin, org, dataset, app)
        _activate(self.service, admin, grant)
        self.service.transition(admin, grant["id"], "revoke", {"reason": "purpose changed"})

        org = self.service.get(org["id"])
        self.assertEqual(org["status"], "suspended")

        receipts = self.service.list("receipt")
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["status"], "pending")
        self.assertEqual(receipts[0]["data"]["grant_id"], grant["id"])
        self.assertEqual(receipts[0]["data"]["organization_id"], org["id"])

    def test_expire_suspends_org_and_creates_pending_receipt(self):
        admin, org, dataset = _setup(self.service)
        app = _approved_application(self.service, admin, org, dataset)
        grant = _grant(self.service, admin, org, dataset, app)
        _activate(self.service, admin, grant)
        self.service.transition(admin, grant["id"], "expire", {"expired_at": "2026-10-01"})

        org = self.service.get(org["id"])
        self.assertEqual(org["status"], "suspended")
        receipts = self.service.list("receipt")
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["status"], "pending")

    def test_verify_receipt_reactivates_org(self):
        admin, org, dataset = _setup(self.service)
        app = _approved_application(self.service, admin, org, dataset)
        grant = _grant(self.service, admin, org, dataset, app)
        _activate(self.service, admin, grant)
        self.service.transition(admin, grant["id"], "revoke", {"reason": "done"})
        receipt = self.service.list("receipt")[0]

        auditor = Actor("auditor", "auditor")
        verified = self.service.transition(auditor, receipt["id"], "verify", {})
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(verified["data"]["verified_by"], "auditor")

        org = self.service.get(org["id"])
        self.assertEqual(org["status"], "active")

    def test_verify_receipt_reactivates_org_even_with_open_apps(self):
        admin, org, dataset = _setup(self.service)
        app = _approved_application(self.service, admin, org, dataset)
        grant = _grant(self.service, admin, org, dataset, app)
        _activate(self.service, admin, grant)
        self.service.transition(admin, grant["id"], "revoke", {"reason": "done"})
        receipt = self.service.list("receipt")[0]

        # An open application exists; it blocks new grant activation but does
        # not block org reactivation once the receipt is verified.
        _open_application(self.service, admin, org, dataset)
        self.service.transition(admin, receipt["id"], "verify", {})
        org = self.service.get(org["id"])
        self.assertEqual(org["status"], "active")

    def test_verify_requires_admin_or_auditor(self):
        admin, org, dataset = _setup(self.service)
        app = _approved_application(self.service, admin, org, dataset)
        grant = _grant(self.service, admin, org, dataset, app)
        _activate(self.service, admin, grant)
        self.service.transition(admin, grant["id"], "revoke", {"reason": "done"})
        receipt = self.service.list("receipt")[0]

        for role in ("applicant", "viewer", "committee"):
            with self.assertRaises(PermissionDenied):
                self.service.transition(Actor(role, role), receipt["id"], "verify", {})

        auditor = Actor("auditor", "auditor")
        verified = self.service.transition(auditor, receipt["id"], "verify", {})
        self.assertEqual(verified["status"], "verified")

    def test_open_applications_block_new_grant_activation(self):
        admin, org, dataset = _setup(self.service)
        app = _approved_application(self.service, admin, org, dataset)
        grant = _grant(self.service, admin, org, dataset, app)
        _activate(self.service, admin, grant)

        # A second open application exists for the org.
        second = _open_application(self.service, admin, org, dataset)
        new_grant = _grant(self.service, admin, org, dataset, second)
        with self.assertRaises(ValidationError):
            _activate(self.service, admin, new_grant)

        # Resolving the open application allows activation.
        self.service.transition(admin, second["id"], "withdraw", {"reason": "no"})
        activated = _activate(self.service, admin, new_grant)
        self.assertEqual(activated["status"], "active")

    def test_pending_receipt_blocks_application_approval(self):
        admin, org, dataset = _setup(self.service)
        app = _approved_application(self.service, admin, org, dataset)
        grant = _grant(self.service, admin, org, dataset, app)
        _activate(self.service, admin, grant)
        self.service.transition(admin, grant["id"], "revoke", {"reason": "done"})

        # New application submitted while receipt is pending.
        second = _open_application(self.service, admin, org, dataset)
        with self.assertRaises(ValidationError):
            self.service.transition(
                admin,
                second["id"],
                "approve",
                {"approvals": ["r1", "r2", "r3"], "terms": "x", "expires_at": "2099-01-01"},
            )

        # After verification, approval reads the latest restriction and succeeds.
        receipt = self.service.list("receipt")[0]
        self.service.transition(admin, receipt["id"], "verify", {})
        approved = self.service.transition(
            admin,
            second["id"],
            "approve",
            {"approvals": ["r1", "r2", "r3"], "terms": "x", "expires_at": "2099-01-01"},
        )
        self.assertEqual(approved["status"], "approved")

    def test_duplicate_receipt_submission_does_not_create_second(self):
        admin, org, dataset = _setup(self.service)
        app = _approved_application(self.service, admin, org, dataset)
        grant = _grant(self.service, admin, org, dataset, app)
        _activate(self.service, admin, grant)
        self.service.transition(admin, grant["id"], "revoke", {"reason": "done"})

        receipts = self.service.list("receipt")
        self.assertEqual(len(receipts), 1)

        # Re-submitting a receipt for the same grant returns the existing one.
        again = self.service.create(
            admin,
            "receipt",
            {
                "organization_id": org["id"],
                "grant_id": grant["id"],
                "dataset_id": dataset["id"],
            },
        )
        self.assertEqual(again["id"], receipts[0]["id"])
        self.assertEqual(len(self.service.list("receipt")), 1)

    def test_concurrent_verify_and_approve_is_consistent(self):
        admin, org, dataset = _setup(self.service)
        app = _approved_application(self.service, admin, org, dataset)
        grant = _grant(self.service, admin, org, dataset, app)
        _activate(self.service, admin, grant)
        self.service.transition(admin, grant["id"], "revoke", {"reason": "done"})
        receipt = self.service.list("receipt")[0]
        second = _open_application(self.service, admin, org, dataset)

        results = {}
        barrier = threading.Barrier(2)

        def do_verify():
            barrier.wait()
            try:
                results["verify"] = self.service.transition(
                    admin, receipt["id"], "verify", {}
                )
            except Exception as exc:  # noqa: BLE001
                results["verify"] = exc

        def do_approve():
            barrier.wait()
            try:
                results["approve"] = self.service.transition(
                    admin,
                    second["id"],
                    "approve",
                    {"approvals": ["r1", "r2", "r3"], "terms": "x", "expires_at": "2099-01-01"},
                )
            except Exception as exc:  # noqa: BLE001
                results["approve"] = exc

        t1 = threading.Thread(target=do_verify)
        t2 = threading.Thread(target=do_approve)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # The approval cannot bypass the pending receipt: if it succeeded, the
        # receipt must have been verified first.
        receipt = self.service.get(receipt["id"])
        org = self.service.get(org["id"])
        second = self.service.get(second["id"])
        if isinstance(results.get("approve"), Exception):
            self.assertEqual(receipt["status"], "verified")
        else:
            self.assertEqual(second["status"], "approved")
            self.assertEqual(receipt["status"], "verified")
            self.assertEqual(org["status"], "active")

    def test_write_failure_keeps_pending_item_and_retries(self):
        admin, org, dataset = _setup(self.service)
        app = _approved_application(self.service, admin, org, dataset)
        grant = _grant(self.service, admin, org, dataset, app)
        _activate(self.service, admin, grant)

        class FailingRepository:
            def __init__(self, repo):
                self._repo = repo
                self._failed = False

            def __getattr__(self, name):
                return getattr(self._repo, name)

            def create_entity_tx(self, *args, **kwargs):
                if not self._failed:
                    self._failed = True
                    raise sqlite3.OperationalError("simulated write failure")
                return self._repo.create_entity_tx(*args, **kwargs)

        failing = FailingRepository(self.repo)
        service = DomainService(failing, RuleEngine())

        # First attempt fails when writing the receipt; the grant update rolls
        # back, so the grant stays active and no receipt is created.
        with self.assertRaises(sqlite3.OperationalError):
            service.transition(admin, grant["id"], "revoke", {"reason": "done"})
        grant = service.get(grant["id"])
        self.assertEqual(grant["status"], "active")
        self.assertEqual(len(service.list("receipt")), 0)

        # Retry succeeds: the pending receipt is created.
        service.transition(admin, grant["id"], "revoke", {"reason": "done"})
        grant = service.get(grant["id"])
        self.assertEqual(grant["status"], "revoked")
        receipts = service.list("receipt")
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["status"], "pending")


if __name__ == "__main__":
    unittest.main()
