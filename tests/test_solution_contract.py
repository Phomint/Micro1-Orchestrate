import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "code"))

from main import (
    DeletionAuditAgent,
    authorize_deletion_request,
    classify,
    order_and_number_steps,
    validate_output_rows,
)


class RequestAuthorizationTests(unittest.TestCase):
    def test_explicit_account_erasure_authorizes_deletion(self):
        self.assertTrue(authorize_deletion_request("Please erase my account and personal data."))

    def test_portuguese_personal_data_erasure_authorizes_deletion(self):
        self.assertTrue(authorize_deletion_request("Solicito a exclusão permanente da minha conta e dos meus dados pessoais."))

    def test_marketing_opt_out_is_not_a_deletion_request(self):
        self.assertFalse(authorize_deletion_request("Please opt me out of marketing emails; do not delete my account."))

    def test_access_request_is_not_a_deletion_request(self):
        self.assertFalse(authorize_deletion_request("Please send me a copy of all personal data you hold."))

    def test_japanese_account_erasure_is_authorized(self):
        self.assertTrue(authorize_deletion_request("このメールアドレスに関連するアカウントの完全な削除を依頼します。"))


class OutputContractTests(unittest.TestCase):
    def test_steps_are_ordered_by_phase_operation_then_system_resource(self):
        steps = [
            {"phase": "VERIFICATION", "system_id": "z", "resource_id": "2", "operation": "VERIFY_RECORD_ABSENT", "state": "ABSENT", "evidence_id": "e2"},
            {"phase": "FINDING", "system_id": "b", "resource_id": "2", "operation": "REPORT_REMAINING_RECORD", "state": "PRESENT", "evidence_id": "e1"},
            {"phase": "FINDING", "system_id": "a", "resource_id": "1", "operation": "REPORT_ACTIVE_DATA_FLOW", "state": "ACTIVE", "evidence_id": "e3"},
        ]
        ordered = order_and_number_steps(steps)
        self.assertEqual([s["step_no"] for s in ordered], [1, 2, 3])
        self.assertEqual([s["system_id"] for s in ordered], ["b", "a", "z"])

    def test_agent_audits_a_sample_request_as_a_structured_case(self):
        agent = DeletionAuditAgent(ROOT / "dataset")
        request = agent.requests[0]
        result = agent.audit_case(request)
        self.assertEqual(set(result), {"case_id", "deletion_status", "steps_json"})
        self.assertEqual(result["case_id"], request["case_id"])
        self.assertIn(result["deletion_status"], {"COMPLETE", "INCOMPLETE", "NOT_APPLICABLE"})

    def test_all_public_sample_cases_match_published_answers(self):
        import json

        from main import create_case_output, read_csv
        dataset = ROOT / "dataset"
        requests = read_csv(dataset / "sample_deletion_requests.csv")
        expected = {row["case_id"]: row for row in read_csv(dataset / "sample_output.csv")}
        identities = read_csv(dataset / "user_identities.csv")
        audits = read_csv(dataset / "user_audit_log.csv")
        manifest = read_csv(dataset / "evidence_files.csv")
        rules = read_csv(dataset / "deletion_rules.csv")
        for request in requests:
            with self.subTest(case_id=request["case_id"]):
                actual = create_case_output(request, dataset, identities, audits, manifest, rules)
                target = expected[request["case_id"]]
                self.assertEqual(actual["deletion_status"], target["deletion_status"])
                self.assertEqual(json.loads(actual["steps_json"]), json.loads(target["steps_json"]))

    def test_output_validation_rejects_missing_or_duplicate_case_rows(self):
        rows = [
            {"case_id": "case_1", "deletion_status": "NOT_APPLICABLE", "steps_json": "[]"},
            {"case_id": "case_2", "deletion_status": "COMPLETE", "steps_json": "[]"},
        ]
        self.assertEqual(validate_output_rows(rows, ["case_1", "case_2"]), [])
        errors = validate_output_rows(rows[:1] + rows[:1], ["case_1", "case_2"])
        self.assertTrue(errors)

    def test_image_ocr_extracts_email_and_resource_identifier(self):
        from main import extract_image_text
        image = ROOT / "dataset" / "evidence" / "images" / "account_admin_console_20260926.png"
        text = extract_image_text(image)
        self.assertIn("haruka.s1838@zoho.com", text.casefold())
        self.assertIn("account_5762", text.casefold())

    def test_identity_match_does_not_treat_lookup_marker_as_subject_link(self):
        from main import identity_match
        unrelated = {
            "resource_id": "account_6440",
            "status_code": 200,
            "_explicit_lookup_match": True,
            "profile": {"email": "someone-else@example.test"},
        }
        self.assertFalse(identity_match(unrelated, {"subject@example.test", "user_1"}, "user_1"))

    def test_sql_snapshot_present_profile_generates_complete_remediation_plan(self):
        import json

        from main import DeletionAuditAgent, read_csv
        dataset = ROOT / "dataset"
        agent = DeletionAuditAgent(dataset)
        request = next(row for row in read_csv(dataset / "sample_deletion_requests.csv") if row["case_id"] == "case_05")
        expected = next(row for row in read_csv(dataset / "sample_output.csv") if row["case_id"] == "case_05")
        actual = agent.audit_case(request)
        self.assertEqual(actual["deletion_status"], expected["deletion_status"])
        self.assertEqual(json.loads(actual["steps_json"]), json.loads(expected["steps_json"]))

    def test_retained_record_does_not_mask_other_incomplete_observations(self):
        from main import create_case_output, read_csv
        dataset = ROOT / "dataset"
        request = next(row for row in read_csv(dataset / "sample_deletion_requests.csv") if row["case_id"] == "case_11")
        actual = create_case_output(request, dataset, read_csv(dataset / "user_identities.csv"),
                                    read_csv(dataset / "user_audit_log.csv"), read_csv(dataset / "evidence_files.csv"),
                                    read_csv(dataset / "deletion_rules.csv"))
        self.assertEqual(actual["deletion_status"], "INCOMPLETE")

    def test_json_not_found_without_subject_link_is_not_assigned(self):
        from main import identity_match
        row = {"resource_id": "account_6440", "profile": None, "status_code": 404,
               "_explicit_lookup_match": True}
        self.assertFalse(identity_match(row, {"amara-okeke@proton.me", "user_21"}, "user_21"))

    def test_sql_snapshot_keeps_present_profile_rows_as_policy_violations(self):
        from main import collect_evidence, dt, read_csv, resolve_identity
        dataset = ROOT / "dataset"
        request = next(row for row in read_csv(dataset / "sample_deletion_requests.csv") if row["case_id"] == "case_05")
        user, identifiers = resolve_identity(request, read_csv(dataset / "user_identities.csv"),
                                             read_csv(dataset / "user_audit_log.csv"), dt(request["audit_at"]))
        observations = collect_evidence(dataset, read_csv(dataset / "evidence_files.csv"), identifiers,
                                        user, dt(request["audit_at"]))
        self.assertTrue(any(item["resource_id"] == "account_005" and item["action"] == "DELETE"
                            and item["evidence_id"] == "evidence_54" for item in observations), observations)

    def test_security_audit_resource_remains_retained_in_service_export(self):
        self.assertEqual(
            classify({"resource_id": "audit_record_3737", "event_code": "IDENTITY_CHANGE_RECORDED"},
                     "json_service_export", "security_service", "service_resource_export.json"),
            ("SECURITY_AUDIT_LOG", "RETAIN"),
        )

    def test_unknown_evidence_classification_returns_explicit_unknown_pair(self):
        self.assertEqual(classify({"resource_id": "resource_1"}, "unmapped_table", "unmapped_system"), ("UNKNOWN", "UNKNOWN"))

    def test_sample_database_absence_requires_candidate_account_and_full_inventory(self):
        from main import classify, dt
        snapshot = ROOT / "dataset" / "evidence" / "databases" / "customer_accounts_failover_replica_20260902.sql"
        self.assertLessEqual(dt("2026-09-02T23:00:00Z"), dt("2026-09-03T11:30:00Z"))
        import sqlite3
        connection = sqlite3.connect(":memory:")
        try:
            connection.executescript(snapshot.read_text())
            rows = connection.execute("SELECT COUNT(*) FROM customer_profiles_failover_replica WHERE resource_id = ?", ("account_001",)).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(rows, 0)
        self.assertNotEqual(classify({"resource_id": "account_001", "status_code": 404}, "profile_lookups", "account_service"), ("USER_PROFILE", "ABSENT"))

    def test_not_found_profile_is_compliant_state_not_a_violation(self):
        self.assertEqual(classify({"resource_id": "account_1", "result": "NOT_FOUND"}, "account_profiles", "account_service"), ("USER_PROFILE", "ABSENT"))

    def test_service_export_rows_use_the_record_system_not_the_export_container(self):
        cases = [
            ({"resource_id": "search_9001", "email": "subject@example.test"}, "search_service", ("SEARCH_INDEX_ENTRY", "DELETE")),
            ({"resource_id": "analytics_9001", "email": "subject@example.test"}, "analytics_platform", ("ANALYTICS_PROFILE", "ANONYMIZE")),
            ({"resource_id": "support_9001", "email": "subject@example.test"}, "support_platform", ("SUPPORT_MESSAGE", "REDACT")),
            ({"resource_id": "export_9001", "email": "subject@example.test"}, "export_service", ("USER_EXPORT", "DELETE")),
        ]
        for row, system, expected in cases:
            with self.subTest(system=system):
                self.assertEqual(classify(row, "json_service_export", system), expected)

    def test_handover_line_parser_reads_dash_prefixed_snapshot_timestamp(self):
        from main import DeletionAuditAgent, read_csv
        agent = DeletionAuditAgent(ROOT / "dataset")
        request = next(row for row in read_csv(ROOT / "dataset" / "sample_deletion_requests.csv") if row["case_id"] == "case_11")
        result = agent.audit_case(request)
        self.assertIn("VERIFY_RECORD_ABSENT", [step["operation"] for step in __import__("json").loads(result["steps_json"])])

    def test_split_log_readback_is_linked_to_its_started_subject_only(self):
        import json

        from main import DeletionAuditAgent, read_csv
        agent = DeletionAuditAgent(ROOT / "dataset")
        request = next(row for row in read_csv(ROOT / "dataset" / "sample_deletion_requests.csv") if row["case_id"] == "case_15")
        result = agent.audit_case(request)
        steps = json.loads(result["steps_json"])
        self.assertTrue(any(step["resource_id"] == "data_flow_9846" and step["operation"] == "REPORT_ACTIVE_DATA_FLOW" for step in steps))
        self.assertFalse(any(step["resource_id"] == "data_flow_1121" for step in steps))

    def test_case_03_complete_plan_includes_anonymous_analytics_readback(self):
        import json

        from main import DeletionAuditAgent, read_csv
        agent = DeletionAuditAgent(ROOT / "dataset")
        request = next(row for row in read_csv(ROOT / "dataset" / "sample_deletion_requests.csv") if row["case_id"] == "case_03")
        actual = agent.audit_case(request)
        steps = json.loads(actual["steps_json"])
        self.assertTrue(any(step["resource_id"] == "analytics_9406" and step["operation"] == "VERIFY_RECORD_ANONYMIZED" for step in steps))

        import json

        from main import DeletionAuditAgent, read_csv
        agent = DeletionAuditAgent(ROOT / "dataset")
        request = next(row for row in read_csv(ROOT / "dataset" / "sample_deletion_requests.csv") if row["case_id"] == "case_08")
        result = agent.audit_case(request)
        steps = json.loads(result["steps_json"])
        self.assertEqual(result["deletion_status"], "INCOMPLETE")
        self.assertTrue(any(step["resource_id"] == "export_001" and step["operation"] == "REPORT_REMAINING_RECORD" for step in steps))

    def test_case_31_complete_output_includes_redacted_tombstone_verification(self):
        import json

        from main import DeletionAuditAgent, read_csv
        agent = DeletionAuditAgent(ROOT / "dataset")
        request = next(row for row in read_csv(ROOT / "dataset" / "sample_deletion_requests.csv") if row["case_id"] == "case_31")
        actual = agent.audit_case(request)
        steps = json.loads(actual["steps_json"])
        self.assertEqual(actual["deletion_status"], "COMPLETE")
        self.assertTrue(any(step["resource_id"] == "tombstone_440" and step["operation"] == "VERIFY_RECORD_REDACTED" and step["evidence_id"] == "evidence_51" for step in steps))

    def test_case_26_complete_output_verifies_every_policy_compliant_resource(self):
        import json

        from main import DeletionAuditAgent, read_csv
        dataset = ROOT / "dataset"
        agent = DeletionAuditAgent(dataset)
        request = next(row for row in read_csv(dataset / "sample_deletion_requests.csv") if row["case_id"] == "case_26")
        expected = next(row for row in read_csv(dataset / "sample_output.csv") if row["case_id"] == "case_26")
        actual = agent.audit_case(request)
        self.assertEqual(actual["deletion_status"], "COMPLETE")
        self.assertEqual(json.loads(actual["steps_json"]), json.loads(expected["steps_json"]))

    def test_tombstone_resource_is_classified_by_its_record_type_across_json_sources(self):
        row = {
            "resource_id": "tombstone_9178", "subject_reference": "user_542",
            "name": "Kofi Addo", "email": "addo.kofi@gmail.com",
            "phone": "+233 24 991 1328", "email_hash": "hash-value",
        }
        self.assertEqual(classify(row, "json", "identity_service"), ("ACCOUNT_TOMBSTONE", "REDACT"))

    def test_identity_match_finds_subject_inside_snapshot_records_container(self):
        from main import identity_match
        snapshot = {"data_store": "identity_service", "collection": "deleted_customer_references", "records": [
            {"resource_id": "tombstone_1", "subject_reference": "user_1", "name": None},
            {"resource_id": "tombstone_2", "subject_reference": "user_2", "name": "Unrelated"},
        ]}
        self.assertTrue(identity_match(snapshot, {"subject@example.test", "user_1"}, "user_1"))
        self.assertFalse(identity_match(snapshot, {"other@example.test", "user_3"}, "user_3"))

    def test_identity_match_rejects_snapshot_context_with_two_matching_records(self):
        from main import identity_match
        snapshot = {"data_store": "export_service", "records": [
            {"resource_id": "export_1", "owner_email": "subject@example.test"},
            {"resource_id": "export_2", "owner_email": "subject@example.test"},
        ]}
        self.assertFalse(identity_match(snapshot, {"subject@example.test", "user_1"}, "user_1"))

    def test_completed_profile_lookup_404_is_classified_as_absence_in_service_export(self):
        row = {"event": "profile_lookup_completed", "resource_id": "account_1", "rows": "0", "http_status": "404"}
        self.assertEqual(classify(row, "json_service_export", "account_service"), ("USER_PROFILE", "ABSENT"))

    def test_false_boolean_is_preserved_for_disabled_data_flow(self):
        from main import norm
        self.assertEqual(norm(False), "false")
        self.assertEqual(norm(0), "0")
        self.assertEqual(
            classify({"resource_id": "data_flow_9001", "enabled": False}, "connector_subscriptions", "integration_service"),
            ("DATA_FLOW", "FLOW_DISABLED"),
        )

    def test_completed_readback_event_uses_explicit_observed_state(self):
        cases = [
            ({"event": "index_query_completed", "result": "hit", "resource_id": "search_1"}, ("SEARCH_INDEX_ENTRY", "DELETE")),
            ({"event": "analytics_profile_read_completed", "email": "subject@example.test", "resource_id": "analytics_1"}, ("ANALYTICS_PROFILE", "ANONYMIZE")),
            ({"event": "support_ticket_read_completed", "requester_email": "subject@example.test", "resource_id": "support_1"}, ("SUPPORT_MESSAGE", "REDACT")),
            ({"event": "connector_config_read_completed", "enabled": False, "resource_id": "data_flow_1"}, ("DATA_FLOW", "FLOW_DISABLED")),
            ({"event": "restore_policy_read_completed", "restore_allowed": False, "resource_id": "backup_1"}, ("BACKUP_ARCHIVE", "RESTORE_BLOCKED")),
        ]
        for row, expected in cases:
            with self.subTest(event=row["event"]):
                self.assertEqual(classify(row, "json_service_export", ""), expected)

    def test_started_readback_event_is_not_state_evidence(self):
        self.assertEqual(
            classify({"event": "index_query_started", "resource_id": "search_1"}, "json_service_export", ""),
            ("UNKNOWN", "UNKNOWN"),
        )

    def test_log_start_and_completion_are_correlated_by_trace_before_identity_matching(self):
        from main import extract_correlated_log_records
        text = (
            '2026-09-17T22:00:04Z level=DEBUG service=support_replica trace_id=tr-1 event=contact_query_started lookup_key=nadia.ionescu@yahoo.com\n'
            '2026-09-17T22:00:05Z level=INFO service=support_replica trace_id=tr-1 event=contact_query_completed resource_id=support_002 rows=1\n'
            '2026-09-17T22:00:06Z level=INFO service=support_replica trace_id=tr-2 event=contact_query_completed resource_id=support_003 rows=1'
        )
        records = extract_correlated_log_records(text)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["resource_id"], "support_002")
        self.assertEqual(records[0]["lookup_key"], "nadia.ionescu@yahoo.com")
        self.assertEqual(records[0]["event"], "contact_query_completed")

    def test_trace_correlation_preserves_start_key_on_resource_completion(self):
        from main import extract_correlated_log_records
        log_path = ROOT / "dataset" / "evidence" / "logs" / "service_events_ap_south_20260915.log"
        records = extract_correlated_log_records(log_path.read_text())
        matched = next(row for row in records if row.get("resource_id") == "account_4092")
        self.assertEqual(matched["lookup_key"], "leonie.g9352@outlook.com")
        self.assertEqual(matched["http_status"], "404")
        self.assertEqual(matched["_correlated_trace"], "tr-4708586")

    def test_404_from_unrelated_evidence_is_not_classified_as_profile_absence(self):
        self.assertEqual(
            classify({"resource_id": "record_1", "status_code": 404}, "unmapped_events", "unmapped_system"),
            ("UNKNOWN", "UNKNOWN"),
        )


if __name__ == "__main__":
    unittest.main()
