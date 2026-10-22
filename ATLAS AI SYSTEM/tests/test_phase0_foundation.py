"""Comprehensive Phase 0 Foundation, Security, Cost, Model Router, Audit & Registry Tests.

Compatible with both `pytest` and `python -m unittest discover -s tests -v`.
"""

from __future__ import annotations

import os
import time
import unittest
from typing import Any, Dict

from fastapi import HTTPException
from starlette.requests import Request

from api.routes import (
    create_task_endpoint,
    health_check,
    list_agents_endpoint,
    pause_agent_endpoint,
    process_next_task_endpoint,
    resolve_approval_endpoint,
    resume_agent_endpoint,
    run_agent_direct_endpoint,
    trigger_kill_switch,
    trigger_resume,
    update_charter_endpoint,
)
from api.schemas import (
    ApprovalActionRequest,
    CharterUpdateRequest,
    CreateTaskRequest,
    KillSwitchRequest,
    ResumeRequest,
)
from core.agent_contract import (
    AgentOperationalStatus,
    AutonomyLevel,
    BaseAgent,
    TaskInput,
    TaskResult,
)
from core.agent_registry import REGISTRY
from core.audit import AuditTamperError, append_audit_log, verify_audit_chain
from core.charter import ensure_active_charter, update_charter_by_chairman
from core.config import Settings, load_settings
from core.kill_switch import engage_kill_switch, ensure_system_state, resume_from_safe_mode
from core.legacy_adapter import LegacyAdapter
from core.model_router import (
    BudgetCapExceededError,
    ModelRouter,
    ProviderUnavailableError,
    RunawayTaskError,
    assert_can_execute_from_llm,
)
from core.security import (
    RATE_LIMITER,
    authenticate_bearer_token,
    encode_jwt,
    login_with_google_id_token,
    refresh_access_token,
    require_scope,
    revoke_refresh_token,
    set_google_id_token_verifier,
)
from core.task_queue import TASK_QUEUE
from db.database import get_session_factory, init_db


def _make_dummy_request(method: str = "POST", path: str = "/api/v1/test", token: str = "") -> Request:
    headers = []
    if token:
        headers.append((b"authorization", f"Bearer {token}".encode("latin-1")))
    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "scheme": "https",
        "server": ("localhost", 443),
        "query_string": b"",
    }
    return Request(scope)


class Phase0FoundationTestSuite(unittest.TestCase):
    """End-to-end verification of Phase 0 Foundation and Addendum A1–A5 security invariants."""

    def setUp(self) -> None:
        os.environ["ENV"] = "test"
        os.environ["DATABASE_URL"] = "sqlite:///:memory:"
        os.environ["OWNER_EMAIL"] = "abbass@example.com"
        os.environ["GOOGLE_CLIENT_ID"] = "atlas-client-id.apps.googleusercontent.com"
        os.environ["JWT_SIGNING_KEY"] = "test-jwt-signing-secret-key-32-bytes-minimum"
        os.environ["MACHINE_API_TOKEN"] = "machine-secret-token-xyz-987"
        os.environ["DEV_OWNER_TOKEN"] = "dev-bypass-token-local-only"
        os.environ["GEMINI_API_KEY"] = ""
        os.environ["GLOBAL_DAILY_BUDGET_USD"] = "5.0"
        os.environ["GLOBAL_MONTHLY_BUDGET_USD"] = "100.0"
        os.environ["PER_AGENT_DAILY_SHARE_CAP"] = "0.30"
        os.environ["BOARD_DAILY_BUDGET_USD"] = "1.0"

        RATE_LIMITER.reset()
        init_db("sqlite:///:memory:")
        self.session_factory = get_session_factory()
        self.session = self.session_factory()

        ensure_system_state(self.session)
        REGISTRY._load_default_catalog()
        REGISTRY.sync_to_db(self.session)
        ensure_active_charter(self.session)
        self.session.commit()

        def _fake_google_verifier(id_token_str: str, expected_aud: str) -> Dict[str, Any]:
            now = int(time.time())
            if id_token_str == "valid-owner-google-token":
                return {
                    "iss": "https://accounts.google.com",
                    "aud": expected_aud,
                    "email": "abbass@example.com",
                    "email_verified": True,
                    "exp": now + 3600,
                }
            if id_token_str == "intruder-google-token":
                return {
                    "iss": "https://accounts.google.com",
                    "aud": expected_aud,
                    "email": "attacker@evil.org",
                    "email_verified": True,
                    "exp": now + 3600,
                }
            raise ValueError("Invalid Google token signature")

        set_google_id_token_verifier(_fake_google_verifier)

    def tearDown(self) -> None:
        set_google_id_token_verifier(None)
        self.session.close()

    # --- 1. Authentication, Machine Scopes, Step-Up & Dev Bypass Tests (Addendum A2) ---

    def test_non_owner_google_account_rejected_and_audit_logged(self) -> None:
        with self.assertRaises(HTTPException) as ctx:
            login_with_google_id_token(
                self.session,
                id_token_str="intruder-google-token",
                client_ip="198.51.100.42",
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("not the authorized Chairman", ctx.exception.detail)

        chain = verify_audit_chain(self.session)
        self.assertTrue(chain["valid"])
        self.assertGreaterEqual(chain["checked_count"], 1)

    def test_owner_google_login_refresh_and_revocation_lifecycle(self) -> None:
        bundle = login_with_google_id_token(
            self.session,
            id_token_str="valid-owner-google-token",
            client_ip="127.0.0.1",
        )
        self.assertIn("access_token", bundle)
        self.assertIn("refresh_token", bundle)
        self.assertIsNotNone(bundle["step_up_verified_until"])

        principal = authenticate_bearer_token(bundle["access_token"], self.session)
        self.assertEqual(principal.principal_type, "owner")
        self.assertTrue(principal.has_fresh_step_up())

        # Refresh rotates token and issues an access token WITHOUT fresh step-up
        refreshed = refresh_access_token(
            self.session,
            raw_refresh_token=bundle["refresh_token"],
            client_ip="127.0.0.1",
        )
        refreshed_principal = authenticate_bearer_token(refreshed["access_token"], self.session)
        self.assertFalse(refreshed_principal.has_fresh_step_up())

        # Old refresh token is now revoked and cannot be reused
        with self.assertRaises(HTTPException) as reuse_ctx:
            refresh_access_token(
                self.session,
                raw_refresh_token=bundle["refresh_token"],
                client_ip="127.0.0.1",
            )
        self.assertEqual(reuse_ctx.exception.status_code, 401)

        # Explicit revocation of new refresh token
        revoke_refresh_token(
            self.session,
            raw_refresh_token=refreshed["refresh_token"],
            actor=principal.actor,
        )
        with self.assertRaises(HTTPException) as rev_ctx:
            refresh_access_token(
                self.session,
                raw_refresh_token=refreshed["refresh_token"],
                client_ip="127.0.0.1",
            )
        self.assertEqual(rev_ctx.exception.status_code, 401)

    def test_expired_jwt_rejected(self) -> None:
        cfg = load_settings()
        now_ts = int(time.time())
        expired_jwt = encode_jwt(
            {
                "sub": "owner:abbass@example.com",
                "email": "abbass@example.com",
                "iat": now_ts - 2000,
                "exp": now_ts - 10,
                "step_up_at": now_ts - 2000,
            },
            cfg.jwt_signing_key,
        )
        with self.assertRaises(HTTPException) as ctx:
            authenticate_bearer_token(expired_jwt, self.session, cfg)
        self.assertEqual(ctx.exception.status_code, 401)

    def test_machine_token_can_trigger_kill_switch_but_cannot_approve_resume_or_edit_charter(self) -> None:
        machine_token = os.environ["MACHINE_API_TOKEN"]
        machine_principal = authenticate_bearer_token(machine_token, self.session)
        self.assertEqual(machine_principal.principal_type, "machine")

        # 1. Machine token CAN trigger the kill switch
        ks_res = trigger_kill_switch(
            KillSwitchRequest(reason="Automated n8n anomaly halt"),
            principal=machine_principal,
            session=self.session,
        )
        self.assertEqual(ks_res["mode"], "SAFE")
        self.assertTrue(ks_res["kill_switch_engaged"])

        # 2. Machine token CANNOT resume from SAFE mode
        req_resume = _make_dummy_request("POST", "/api/v1/resume", machine_token)
        resume_dep = require_scope("execute:resume", require_step_up=True)
        with self.assertRaises(HTTPException) as res_ctx:
            resume_dep(req_resume, machine_principal, self.session)
        self.assertEqual(res_ctx.exception.status_code, 403)

        # 3. Machine token CANNOT edit the Charter
        req_charter = _make_dummy_request("PUT", "/api/v1/charter", machine_token)
        charter_dep = require_scope("write:charter", require_step_up=True)
        with self.assertRaises(HTTPException) as ch_ctx:
            charter_dep(req_charter, machine_principal, self.session)
        self.assertEqual(ch_ctx.exception.status_code, 403)

        # 4. Machine token CANNOT approve Tier 2 decisions
        req_approve = _make_dummy_request("POST", "/api/v1/approvals/apr_1/approve", machine_token)
        approve_dep = require_scope("write:approvals")
        with self.assertRaises(HTTPException) as ap_ctx:
            approve_dep(req_approve, machine_principal, self.session)
        self.assertEqual(ap_ctx.exception.status_code, 403)

    def test_step_up_required_for_charter_edits_and_safe_mode_resume(self) -> None:
        # Issue token via Google login then rotate via refresh (so step_up_at is None)
        bundle = login_with_google_id_token(self.session, id_token_str="valid-owner-google-token")
        refreshed = refresh_access_token(self.session, raw_refresh_token=bundle["refresh_token"])
        no_step_up_principal = authenticate_bearer_token(refreshed["access_token"], self.session)

        req_charter = _make_dummy_request("PUT", "/api/v1/charter", refreshed["access_token"])
        charter_dep = require_scope("write:charter", require_step_up=True)
        with self.assertRaises(HTTPException) as ctx:
            charter_dep(req_charter, no_step_up_principal, self.session)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("Step-up verification required", ctx.exception.detail)

        # Now perform fresh Google step-up authentication (<5 min)
        step_up_bundle = login_with_google_id_token(
            self.session,
            id_token_str="valid-owner-google-token",
            is_step_up_flow=True,
        )
        step_up_principal = authenticate_bearer_token(step_up_bundle["access_token"], self.session)
        verified_principal = charter_dep(req_charter, step_up_principal, self.session)
        self.assertEqual(verified_principal.principal_type, "owner")

        # Update Charter with valid step-up principal and verify optimistic concurrency check
        updated = update_charter_endpoint(
            CharterUpdateRequest(
                expected_version=1,
                rationale="Reviewed conservative budget parameters",
                updated_charter={"budgets_and_limits": {"global_daily_budget_usd": 5.0}},
                explicit_confirmation=True,
            ),
            principal=verified_principal,
            session=self.session,
        )
        self.assertEqual(updated["version"], 2)

        # Submitting stale expected_version=1 must fail with 409 Conflict
        with self.assertRaises(HTTPException) as conflict_ctx:
            update_charter_endpoint(
                CharterUpdateRequest(
                    expected_version=1,
                    rationale="Stale update attempt",
                    updated_charter={"budgets_and_limits": {"global_daily_budget_usd": 6.0}},
                    explicit_confirmation=True,
                ),
                principal=verified_principal,
                session=self.session,
            )
        self.assertEqual(conflict_ctx.exception.status_code, 409)

    def test_dev_bypass_blocked_in_production(self) -> None:
        with self.assertRaises(RuntimeError) as ctx:
            Settings(
                env="prod",
                owner_email="abbass@example.com",
                jwt_signing_key="strong-prod-jwt-signing-key-32-bytes-long",
                dev_owner_token="any-dev-bypass-token",
            )
        self.assertIn("DEV_OWNER_TOKEN", str(ctx.exception))

    # --- 2. Model Router & Cost Agent Cap Enforcement Tests (Addendum A3 & A4) ---

    def test_model_router_respects_per_agent_yaml_config(self) -> None:
        router = ModelRouter()
        atlas_cfg = router.get_assignment("atlas")
        self.assertEqual(atlas_cfg.model, "gemini-3.8-flash")
        self.assertAlmostEqual(atlas_cfg.temperature, 0.2)

        esc_cfg = router.get_assignment("atlas_escalation")
        self.assertEqual(esc_cfg.model, "gemini-4-argon")
        self.assertAlmostEqual(esc_cfg.temperature, 0.2)

        cap_dir = router.get_assignment("director_capital")
        self.assertEqual(cap_dir.model, "gemini-3.8-flash")
        self.assertAlmostEqual(cap_dir.temperature, 0.4)

        da_dir = router.get_assignment("director_devils_advocate")
        self.assertEqual(da_dir.model, "gemini-4-argon")
        self.assertAlmostEqual(da_dir.temperature, 0.6)

        content_cfg = router.get_assignment("content")
        self.assertEqual(content_cfg.model, "gemini-3.8-flash")
        self.assertAlmostEqual(content_cfg.temperature, 0.7)

    def test_production_without_gemini_api_key_fails_closed(self) -> None:
        prod_settings = Settings(
            env="prod",
            owner_email="abbass@atlas.ai",
            jwt_signing_key="strong-prod-jwt-signing-key-32-bytes-long",
            dev_owner_token="",
            gemini_api_key="",
        )
        router = ModelRouter(settings=prod_settings)
        with self.assertRaises(ProviderUnavailableError):
            router.generate(
                self.session,
                agent_name="atlas",
                prompt="Evaluate routine task",
            )

    def test_mock_output_tagged_and_never_executes_action(self) -> None:
        router = ModelRouter()
        resp = router.generate(
            self.session,
            agent_name="atlas",
            prompt="Analyze system status in dev/test mode",
        )
        self.assertTrue(resp.mock)
        self.assertFalse(resp.can_trigger_execution)
        with self.assertRaises(PermissionError):
            assert_can_execute_from_llm(resp)

    def test_cost_cap_blocks_call_before_it_is_made_and_pauses_agent(self) -> None:
        # Configure a tight global daily budget ($0.0001) so the pre-call check triggers hard stop
        tight_settings = Settings(
            env="test",
            global_daily_budget_usd=0.00001,
            global_monthly_budget_usd=100.0,
            per_agent_daily_share_cap=0.30,
        )
        router = ModelRouter(settings=tight_settings)
        with self.assertRaises(BudgetCapExceededError):
            router.generate(
                self.session,
                agent_name="health",
                prompt="Run diagnostic analysis exceeding micro-cap",
            )

        # Verify agent 'health' was automatically paused by Cost Agent hard stop
        agents = {a["name"]: a for a in REGISTRY.get_agent_views(self.session)}
        self.assertEqual(agents["health"]["status"], "PAUSED")

    # --- 3. Audit Log Tamper Resistance & Chain Integrity Tests ---

    def test_audit_log_hash_chain_and_tamper_rejection(self) -> None:
        entry1 = append_audit_log(
            self.session,
            actor="owner:abbass@example.com",
            action="test.event_one",
            target="system",
            outcome="SUCCESS",
            why="First test audit entry",
            details={"api_key": "super-secret-value", "normal_field": "ok"},
        )
        self.session.commit()

        # Verify secret redaction
        self.assertIn("[REDACTED]", entry1.details_json)
        self.assertNotIn("super-secret-value", entry1.details_json)

        # Verify hash chain integrity
        verification = verify_audit_chain(self.session)
        self.assertTrue(verification["valid"])

        # Attempting to modify an existing AuditLog row must raise AuditTamperError
        with self.assertRaises(AuditTamperError):
            entry1.why = "Tampered reason"
            self.session.flush()
        self.session.rollback()

        # Attempting to delete an existing AuditLog row must raise AuditTamperError
        entry_ref = self.session.get(type(entry1), entry1.id)
        with self.assertRaises(AuditTamperError):
            self.session.delete(entry_ref)
            self.session.flush()
        self.session.rollback()

    # --- 4. Agent Registry, Planned Agents, LegacyAdapter & Task Queue Tests (Addendum A5) ---

    def test_planned_catalog_agents_registered_and_raise_not_implemented(self) -> None:
        views = {a["name"]: a for a in REGISTRY.get_agent_views(self.session)}
        self.assertEqual(len(views), 49)

        for legacy_name, expected_phase in (
            ("crypto_trading", 4),
            ("gold_trading", 4),
            ("learning_engine", 2),
            ("linkedin", 3),
        ):
            self.assertIn(legacy_name, views)
            self.assertEqual(views[legacy_name]["status"], "PLANNED")
            self.assertEqual(views[legacy_name]["autonomy_level"], "L0")
            self.assertEqual(views[legacy_name]["phase"], expected_phase)

            with self.assertRaises(NotImplementedError):
                REGISTRY.execute_agent_task(
                    self.session,
                    legacy_name,
                    TaskInput(task_id="tsk_test", action=views[legacy_name]["capabilities"][0]),
                )

    def test_task_queue_idempotency_execution_and_kill_switch_cancellation(self) -> None:
        # 1. Enqueue with idempotency_key
        t1 = TASK_QUEUE.enqueue_task(
            self.session,
            agent_name="health",
            action="check_system_health",
            priority=2,
            tier="0",
            created_by="owner:abbass@example.com",
            idempotency_key="idem-health-1",
        )
        t1_dup = TASK_QUEUE.enqueue_task(
            self.session,
            agent_name="health",
            action="check_system_health",
            priority=2,
            tier="0",
            created_by="owner:abbass@example.com",
            idempotency_key="idem-health-1",
        )
        self.assertEqual(t1["id"], t1_dup["id"])

        # 2. Execute queued task
        executed = TASK_QUEUE.execute_next_queued_task(self.session)
        self.assertIsNotNone(executed)
        assert executed is not None
        self.assertEqual(executed["status"], "COMPLETED")
        self.assertEqual(executed["result"]["output"]["system"], "healthy")

        # 3. Enqueue another task and engage Kill Switch -> task is cancelled and system enters SAFE mode
        t2 = TASK_QUEUE.enqueue_task(
            self.session,
            agent_name="audit",
            action="verify_chain",
            priority=3,
            tier="0",
            created_by="owner:abbass@example.com",
        )
        ks_report = engage_kill_switch(
            self.session,
            actor="owner:abbass@example.com",
            reason="Testing emergency halt",
        )
        self.assertEqual(ks_report["mode"], "SAFE")
        self.assertEqual(ks_report["cancelled_tasks_count"], 1)

        tasks_after = {t["id"]: t for t in TASK_QUEUE.list_tasks(self.session)}
        self.assertEqual(tasks_after[t2["id"]]["status"], "CANCELLED")

        # 4. Resume from SAFE mode restores active agents
        resume_report = resume_from_safe_mode(
            self.session,
            actor="owner:abbass@example.com",
            reason="Test completed",
        )
        self.assertEqual(resume_report["mode"], "NORMAL")
        self.assertGreaterEqual(resume_report["restored_agents_count"], 2)

    def test_legacy_adapter_secret_isolation_and_forbidden_permissions(self) -> None:
        class DummyLegacyWrapper(LegacyAdapter):
            def estimate_cost(self, task: TaskInput) -> float:
                return 0.0

            def invoke_legacy_callable(self, validated_input, sanitized_env, timeout_seconds):
                return {"env_keys": sorted(sanitized_env.keys()), "confidence": 0.9}

        # Declaring forbidden direct permissions must fail immediately
        with self.assertRaises(PermissionError):
            DummyLegacyWrapper(
                name="bad_legacy",
                display_name="Bad Legacy",
                layer="Trading",
                description="Test",
                capabilities=["run_script"],
                permissions=["trade:live_direct"],
            )

        wrapper = DummyLegacyWrapper(
            name="safe_legacy",
            display_name="Safe Legacy",
            layer="Trading",
            description="Test",
            capabilities=["run_script"],
            permissions=["read:exchange", "trade:paper"],
            allowed_env_keys=["OWNER_EMAIL"],
            is_trading_adapter=True,
            status=AgentOperationalStatus.ACTIVE,
        )
        env = wrapper.build_sanitized_env()
        self.assertEqual(env.get("ATLAS_TRADING_MODE"), "PAPER")
        self.assertEqual(env.get("OWNER_EMAIL"), "abbass@example.com")
        self.assertNotIn("JWT_SIGNING_KEY", env)
        self.assertNotIn("MACHINE_API_TOKEN", env)

        # Attempting to execute in LIVE mode without Tier 2 approval permission is blocked
        with self.assertRaises(PermissionError):
            wrapper.run_with_audit(
                self.session,
                TaskInput(task_id="tsk_leg", action="run_script"),
                current_trading_mode="LIVE",
            )

    def test_login_lockout_engages_after_repeated_failures(self) -> None:
        for _ in range(5):
            with self.assertRaises(HTTPException) as ctx:
                login_with_google_id_token(
                    self.session,
                    id_token_str="bad-signature-token",
                    client_ip="203.0.113.99",
                )
            self.assertEqual(ctx.exception.status_code, 401)

        # 6th attempt from same IP must be locked out with HTTP 429
        with self.assertRaises(HTTPException) as lock_ctx:
            login_with_google_id_token(
                self.session,
                id_token_str="valid-owner-google-token",
                client_ip="203.0.113.99",
            )
        self.assertEqual(lock_ctx.exception.status_code, 429)


if __name__ == "__main__":
    unittest.main()
