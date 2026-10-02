import threading
import tempfile
import unittest
import urllib.request
import json
from pathlib import Path

from src.domain import (
    Actor,
    ConflictError,
    InvalidTransition,
    PermissionDenied,
    ValidationError,
)
from src.repository import SQLiteRepository
from src.rules import RuleEngine
from src.service import DomainService


ADMIN = Actor("admin-1", "admin")
AUDITOR = Actor("auditor-1", "auditor")
COMMITTEE = Actor("committee-1", "committee")
APPLICANT = Actor("applicant-1", "applicant")
VIEWER = Actor("viewer-1", "viewer")


class GovernanceTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())
        self.recipient = "org-1"

    def tearDown(self):
        self.tmp.cleanup()

    def _issue_closed_grant(self, recipient="org-1", revoke=True):
        """完整走完 dataset -> application -> grant -> revoke/expire。"""
        dataset = self.service.create(
            ADMIN, "dataset", {"name": "D", "access_policy": "controlled"}
        )
        application = self.service.create(
            APPLICANT,
            "application",
            {"dataset_id": dataset["id"], "applicant_id": recipient, "purpose": "analysis"},
        )
        self.service.transition(APPLICANT, application["id"], "submit", {})
        self.service.transition(COMMITTEE, application["id"], "review", {"committee_id": "c1"})
        self.service.transition(
            COMMITTEE,
            application["id"],
            "approve",
            {"approvals": ["r1", "r2", "r3"], "terms": "x", "expires_at": "2099-01-01"},
        )
        grant = self.service.create(
            COMMITTEE,
            "grant",
            {"application_id": application["id"], "dataset_id": dataset["id"], "recipient": recipient},
        )
        self.service.transition(
            ADMIN,
            grant["id"],
            "activate",
            {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
        )
        if revoke:
            self.service.transition(ADMIN, grant["id"], "revoke", {"reason": "project ended"})
        else:
            self.service.transition(ADMIN, grant["id"], "expire", {"expired_at": "2099-02-01"})
        return dataset, application, grant

    def _new_issued_grant(self, recipient="org-1", index=2, review=False):
        dataset = self.service.create(
            ADMIN, "dataset", {"name": "D%d" % index, "access_policy": "controlled"}
        )
        application = self.service.create(
            APPLICANT,
            "application",
            {"dataset_id": dataset["id"], "applicant_id": recipient, "purpose": "more"},
        )
        if review:
            self.service.transition(APPLICANT, application["id"], "submit", {})
            self.service.transition(COMMITTEE, application["id"], "review", {"committee_id": "c1"})
            self.service.transition(
                COMMITTEE,
                application["id"],
                "approve",
                {"approvals": ["r1", "r2", "r3"], "terms": "x", "expires_at": "2099-01-01"},
            )
        grant = self.service.create(
            COMMITTEE,
            "grant",
            {"application_id": application["id"], "dataset_id": dataset["id"], "recipient": recipient},
        )
        return dataset, application, grant

    # 1. 完整停用治理：凭证撤销 -> 提交回执 -> admin/auditor 核对 -> 申请办结
    def test_receipt_lifecycle_closes_application(self):
        _, application, grant = self._issue_closed_grant()
        receipt = self.service.create(ADMIN, "destruction_receipt", {"grant_id": grant["id"]})
        self.assertEqual(receipt["status"], "pending")
        self.assertEqual(receipt["data"]["recipient"], self.recipient)

        # 未核对时总览中有待核回执和未结申请
        summary = self.service.governance_summary()
        self.assertTrue(any(r["id"] == receipt["id"] for r in summary["pending_receipts"]))
        self.assertTrue(any(a["id"] == application["id"] for a in summary["open_applications"]))

        verified = self.service.transition(
            AUDITOR, receipt["id"], "verify", {"confirmed": True, "note": "checked on site"}
        )
        self.assertEqual(verified["status"], "verified")
        self.assertEqual(verified["data"]["verified_by"], "auditor-1")

        # 回执核对后对应 approved 申请在同一事务内办结
        closed = self.service.get(application["id"])
        self.assertEqual(closed["status"], "closed")

        summary = self.service.governance_summary()
        self.assertFalse(any(r["id"] == receipt["id"] for r in summary["pending_receipts"]))
        self.assertFalse(any(a["id"] == application["id"] for a in summary["open_applications"]))

    def test_receipt_requires_closed_grant(self):
        dataset = self.service.create(
            ADMIN, "dataset", {"name": "D", "access_policy": "controlled"}
        )
        application = self.service.create(
            APPLICANT,
            "application",
            {"dataset_id": dataset["id"], "applicant_id": "org-1", "purpose": "p"},
        )
        grant = self.service.create(
            COMMITTEE,
            "grant",
            {"application_id": application["id"], "dataset_id": dataset["id"], "recipient": "org-1"},
        )
        with self.assertRaises(InvalidTransition):
            self.service.create(ADMIN, "destruction_receipt", {"grant_id": grant["id"]})

    def test_expired_grant_also_accepts_receipt(self):
        _, _, grant = self._issue_closed_grant(revoke=False)
        receipt = self.service.create(AUDITOR, "destruction_receipt", {"grant_id": grant["id"]})
        self.assertEqual(receipt["status"], "pending")

    # 2. 待核回执存在时，新凭证不能启用，新申请审批也不能放行
    def test_pending_receipt_blocks_activation_and_approval(self):
        _, _, grant = self._issue_closed_grant()
        self.service.create(ADMIN, "destruction_receipt", {"grant_id": grant["id"]})

        _, _, new_grant = self._new_issued_grant(index=2)
        with self.assertRaises(ConflictError):
            self.service.transition(
                ADMIN,
                new_grant["id"],
                "activate",
                {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
            )

        # 新申请审批同样被阻断，委员会不能绕过待核回执继续放行
        dataset = self.service.create(
            ADMIN, "dataset", {"name": "D3", "access_policy": "controlled"}
        )
        app2 = self.service.create(
            APPLICANT,
            "application",
            {"dataset_id": dataset["id"], "applicant_id": self.recipient, "purpose": "again"},
        )
        self.service.transition(APPLICANT, app2["id"], "submit", {})
        self.service.transition(COMMITTEE, app2["id"], "review", {"committee_id": "c1"})
        with self.assertRaises(ConflictError):
            self.service.transition(
                COMMITTEE,
                app2["id"],
                "approve",
                {"approvals": ["r1", "r2", "r3"], "terms": "x", "expires_at": "2099-01-01"},
            )

        # 核对通过后两个限制都解除
        receipt = self.service.list("destruction_receipts", status="pending")[0]
        self.service.transition(ADMIN, receipt["id"], "verify", {"confirmed": True})
        # 此前被拦下的新申请先撤回办结，避免未结申请继续阻断激活
        self.service.transition(APPLICANT, app2["id"], "withdraw", {"reason": "will reapply"})
        activated = self.service.transition(
            ADMIN,
            new_grant["id"],
            "activate",
            {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
        )
        self.assertEqual(activated["status"], "active")

    # 3. 未结申请存在时新凭证不能启用（本凭证对应申请除外）
    def test_open_application_blocks_activation(self):
        _, _, new_grant = self._new_issued_grant(recipient="org-fresh", index=9)
        # org-fresh 另有一个 submitted 的未结申请
        dataset = self.service.create(
            ADMIN, "dataset", {"name": "DX", "access_policy": "controlled"}
        )
        other = self.service.create(
            APPLICANT,
            "application",
            {"dataset_id": dataset["id"], "applicant_id": "org-fresh", "purpose": "side"},
        )
        self.service.transition(APPLICANT, other["id"], "submit", {})
        with self.assertRaises(ConflictError):
            self.service.transition(
                ADMIN,
                new_grant["id"],
                "activate",
                {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
            )
        # 撤回后变为办结，激活放行
        self.service.transition(APPLICANT, other["id"], "withdraw", {"reason": "cancelled"})
        activated = self.service.transition(
            ADMIN,
            new_grant["id"],
            "activate",
            {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
        )
        self.assertEqual(activated["status"], "active")

    # 4. 越权提交要拒绝
    def test_unauthorized_submit_and_verify_rejected(self):
        _, _, grant = self._issue_closed_grant()
        with self.assertRaises(PermissionDenied):
            self.service.create(VIEWER, "destruction_receipt", {"grant_id": grant["id"]})
        receipt = self.service.create(ADMIN, "destruction_receipt", {"grant_id": grant["id"]})
        with self.assertRaises(PermissionDenied):
            self.service.transition(APPLICANT, receipt["id"], "verify", {"confirmed": True})
        with self.assertRaises(PermissionDenied):
            self.service.transition(VIEWER, receipt["id"], "verify", {"confirmed": True})

    def test_verify_requires_confirmation(self):
        _, _, grant = self._issue_closed_grant()
        receipt = self.service.create(ADMIN, "destruction_receipt", {"grant_id": grant["id"]})
        with self.assertRaises(ValidationError):
            self.service.transition(ADMIN, receipt["id"], "verify", {})

    # 5. 重复提交不生成第二份回执
    def test_duplicate_receipt_submission_rejected(self):
        _, _, grant = self._issue_closed_grant()
        first = self.service.create(ADMIN, "destruction_receipt", {"grant_id": grant["id"]})
        with self.assertRaises(ConflictError):
            self.service.create(AUDITOR, "destruction_receipt", {"grant_id": grant["id"]})
        receipts = self.service.list("destruction_receipts")
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["id"], first["id"])

    # 6. 写后失败保留待续项并可重试
    def test_audit_write_failure_queues_pending_and_retries(self):
        _, application, grant = self._issue_closed_grant()
        receipt = self.service.create(ADMIN, "destruction_receipt", {"grant_id": grant["id"]})

        original_append = self.repo.append_audit
        failing = {"on": True}

        def flaky_append(*args, **kwargs):
            if failing["on"]:
                raise RuntimeError("disk unavailable")
            return original_append(*args, **kwargs)

        self.repo.append_audit = flaky_append
        with self.assertRaises(ConflictError):
            self.service.transition(ADMIN, receipt["id"], "verify", {"confirmed": True})
        self.repo.append_audit = original_append

        # 状态变更已经落盘，但审计待续项保留下来
        pending = self.service.list_pending()
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["kind"], "audit")
        events = pending[0]["payload"]["events"]
        self.assertTrue(any(e["action"] == "verify" for e in events))
        self.assertTrue(any(e["action"] == "close" for e in events))

        # 恢复后重试成功
        result = self.service.retry_pending(pending[0]["id"])
        self.assertEqual(result["status"], "completed")
        self.assertEqual(self.service.list_pending(), [])
        actions = {row["action"] for row in self.service.audit_log(application["id"])}
        self.assertIn("close", actions)

    def test_retry_failure_keeps_item_and_records_attempt(self):
        pending_id = self.repo.enqueue_pending(
            "audit",
            {"events": [
                {
                    "entity_id": "x",
                    "actor_id": "u",
                    "actor_role": "admin",
                    "action": "create",
                    "from_status": None,
                    "to_status": "registered",
                    "detail": {},
                }
            ]},
        )
        original_append = self.repo.append_audit

        def flaky_append(*args, **kwargs):
            raise RuntimeError("still down")

        self.repo.append_audit = flaky_append
        with self.assertRaises(ConflictError):
            self.service.retry_pending(pending_id)
        self.repo.append_audit = original_append
        item = self.repo.get_pending(pending_id)
        self.assertIsNotNone(item)
        self.assertEqual(item["attempts"], 1)
        self.assertIn("still down", item["last_error"])

    # 7. 核对与审批并发：先核对者放行，后到一方读到最新限制（核对先到）
    def test_concurrent_verify_then_approve_blocks_or_succeeds_consistently(self):
        _, _, grant = self._issue_closed_grant()
        receipt = self.service.create(ADMIN, "destruction_receipt", {"grant_id": grant["id"]})
        dataset = self.service.create(
            ADMIN, "dataset", {"name": "DN", "access_policy": "controlled"}
        )
        app2 = self.service.create(
            APPLICANT,
            "application",
            {"dataset_id": dataset["id"], "applicant_id": self.recipient, "purpose": "new"},
        )
        self.service.transition(APPLICANT, app2["id"], "submit", {})
        self.service.transition(COMMITTEE, app2["id"], "review", {"committee_id": "c1"})
        approve_data = {"approvals": ["r1", "r2", "r3"], "terms": "x", "expires_at": "2099-01-01"}

        barrier = threading.Barrier(2)
        outcomes = {}

        def do_verify():
            barrier.wait()
            try:
                self.service.transition(ADMIN, receipt["id"], "verify", {"confirmed": True})
                outcomes["verify"] = "ok"
            except Exception as exc:
                outcomes["verify"] = type(exc).__name__

        def do_approve():
            barrier.wait()
            try:
                self.service.transition(COMMITTEE, app2["id"], "approve", approve_data)
                outcomes["approve"] = "ok"
            except Exception as exc:
                outcomes["approve"] = type(exc).__name__

        t1 = threading.Thread(target=do_verify)
        t2 = threading.Thread(target=do_approve)
        t1.start()
        t2.start()
        t1.join(10)
        t2.join(10)

        # 任一排序下都不允许“已批准 + 回执仍待核”
        self.assertEqual(outcomes["verify"], "ok")
        app_after = self.service.get(app2["id"])
        receipt_after = self.service.get(receipt["id"])
        self.assertFalse(
            app_after["status"] == "approved" and receipt_after["status"] == "pending"
        )
        if outcomes["approve"] == ConflictError.__name__:
            self.assertEqual(app_after["status"], "under_review")
        else:
            self.assertEqual(outcomes["approve"], "ok")
            self.assertEqual(receipt_after["status"], "verified")

    # 8. 审批先到并成功时，核对仍可完成；核对先到则审批被拒
    def test_concurrent_approve_then_verify_still_consistent(self):
        _, _, grant = self._issue_closed_grant()
        receipt = self.service.create(ADMIN, "destruction_receipt", {"grant_id": grant["id"]})
        dataset = self.service.create(
            ADMIN, "dataset", {"name": "DM", "access_policy": "controlled"}
        )
        app2 = self.service.create(
            APPLICANT,
            "application",
            {"dataset_id": dataset["id"], "applicant_id": self.recipient, "purpose": "new2"},
        )
        self.service.transition(APPLICANT, app2["id"], "submit", {})
        self.service.transition(COMMITTEE, app2["id"], "review", {"committee_id": "c1"})
        approve_data = {"approvals": ["r1", "r2", "r3"], "terms": "x", "expires_at": "2099-01-01"}

        # 审批先到：在回执还 pending 时必然被拒（同一线程顺序可复现限制）
        with self.assertRaises(ConflictError):
            self.service.transition(COMMITTEE, app2["id"], "approve", approve_data)
        # 后到核对：读到当前状态并完成
        self.service.transition(AUDITOR, receipt["id"], "verify", {"confirmed": True})
        # 重新审批此时放行
        approved = self.service.transition(COMMITTEE, app2["id"], "approve", approve_data)
        self.assertEqual(approved["status"], "approved")

    # 9. 并发激活与核对：核对先提交则激活被拒，激活先成功则其读到的是无 pending 的快照
    def test_concurrent_activate_vs_verify(self):
        _, _, grant = self._issue_closed_grant()
        receipt = self.service.create(ADMIN, "destruction_receipt", {"grant_id": grant["id"]})
        _, _, new_grant = self._new_issued_grant(index=5)
        barrier = threading.Barrier(2)
        outcomes = {}

        def do_verify():
            barrier.wait()
            try:
                self.service.transition(ADMIN, receipt["id"], "verify", {"confirmed": True})
                outcomes["verify"] = "ok"
            except Exception as exc:
                outcomes["verify"] = type(exc).__name__

        def do_activate():
            barrier.wait()
            try:
                self.service.transition(
                    ADMIN,
                    new_grant["id"],
                    "activate",
                    {"starts_at": "2026-01-01", "expires_at": "2099-01-01"},
                )
                outcomes["activate"] = "ok"
            except Exception as exc:
                outcomes["activate"] = type(exc).__name__

        t1 = threading.Thread(target=do_verify)
        t2 = threading.Thread(target=do_activate)
        t1.start()
        t2.start()
        t1.join(10)
        t2.join(10)

        grant_after = self.service.get(new_grant["id"])
        receipt_after = self.service.get(receipt["id"])
        self.assertFalse(
            grant_after["status"] == "active" and receipt_after["status"] == "pending"
        )


class GovernanceHttpTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = SQLiteRepository(Path(self.tmp.name) / "test.db")
        self.service = DomainService(self.repo, RuleEngine())
        from src.http_api import create_server

        self.server = create_server("127.0.0.1", 0, self.service, RuleEngine(), "static")
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        self.tmp.cleanup()

    def _request(self, method, path, payload=None, role="admin", user="u1"):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            "http://127.0.0.1:%s%s" % (self.port, path),
            data=data,
            method=method,
            headers={"Content-Type": "application/json", "X-User-Id": user, "X-Role": role},
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                return response.status, json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read().decode("utf-8"))

    def test_governance_endpoint_and_permissions(self):
        status, payload = self._request("GET", "/api/governance")
        self.assertEqual(status, 200)
        self.assertEqual(set(payload.keys()), {"open_applications", "pending_receipts", "pending_items"})

        status, _ = self._request("GET", "/api/pending", role="viewer")
        self.assertEqual(status, 403)
        status, _ = self._request("POST", "/api/pending/nope/retry", role="auditor")
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
