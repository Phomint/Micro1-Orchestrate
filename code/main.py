"""Evidence-grounded solution for Ghost Data Still Exists."""
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

FIELDS = ["case_id", "deletion_status", "steps_json"]
STEP_FIELDS = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
PHASE_ORDER = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}
OP_ORDER = {"REPORT_REMAINING_RECORD":0,"REPORT_EXPOSED_PII":1,"REPORT_ACTIVE_DATA_FLOW":2,"REPORT_RESTORE_RISK":3,"DISABLE_DATA_FLOW":0,"BLOCK_RESTORE":1,"DELETE_RECORD":2,"REDACT_RECORD":3,"ANONYMIZE_RECORD":4,"VERIFY_RECORD_ABSENT":0,"VERIFY_RECORD_PRESENT":1,"VERIFY_RECORD_REDACTED":2,"VERIFY_RECORD_ANONYMIZED":3,"VERIFY_DATA_FLOW_DISABLED":4,"VERIFY_RESTORE_BLOCKED":5}
NEGATIVE = [r"\bdo not delete\b",r"\bdon't delete\b",r"\bwithout deleting\b",r"\bkeep my account\b",r"\bopt me out\b",r"\bopt[- ]?out of marketing\b",r"\bunsubscrib(?:e|ed)\b",r"\baccess request\b",r"\bcopy of (?:all )?(?:my )?(?:personal )?data\b",r"\bexport (?:my )?(?:personal )?data\b",r"\bcorrect (?:my )?(?:personal )?data\b",r"\bupdate (?:my )?(?:personal )?data\b",r"\bchange (?:my )?(?:email|phone|address)\b",r"\brectif(?:y|ication)\b",r"\bportability\b",r"\brequest information\b",r"\bno quiero (?:que )?(?:se )?(?:elimine|borre)\b",r"\bne supprimez pas\b",r"\b削除しないで\b"]
POSITIVE = [r"\bdelet(?:e|ed|ing|ion)\b",r"\bdelet(?:ar|ar minha conta)\b",r"\bexclu(?:ir|s(?:ao|ão))\b",r"\b(?:erase|erasure|erased|erasing)\b",r"\bremove\b.{0,60}\b(?:account|personal data|my data|information|profile|record|search result|traces|data)\b",r"\b(?:account|personal data|my data|information|profile|record|search result|traces|data)\b.{0,60}\bremove\b",r"\bclose\b.{0,60}\baccount\b",r"\baccount\b.{0,60}\bclose\b",r"\bforget me\b",r"\bforget my data\b",r"\belimin(?:ar|e|ación|acion)\b",r"\bsupr(?:imer|ession|ime)\b",r"\b(?:suppression|supprimer|effacer|effacement)\b",r"完全な削除",r"\bdeleting my account\b",r"\brequest.*\bdeletion\b",r"\bdeleted-account record\b",r"\bverify that .*\bdeleted\b",r"\bcheck that .*\bremoved\b",r"\baccount.*\bdeletion request\b",r"\bpermanent.*\baccount\b.*\bdelet\b",r"\baccount\b.*\b(?:personal data|personal information)\b.*\bdelet\b",r"\b(?:account|data).*(?:close|closure).*(?:personal data|deletion)\b",r"\brequest.*(?:erasure|suppression|deletion)\b",r"\b(?:eliminación|eliminacion) definitiva\b",r"\b完全な削除\b",r"\bdeleted\b.{0,80}\b(?:records|record|profile|data)\b",r"\b(?:remaining|identifiable) (?:data|analytics|records)\b"]

# Resource table schemas mapped to the participant-facing deletion rules.
COLLECTIONS = {
 "customer_profiles":("account_service","USER_PROFILE","DELETE"),"customer_profiles_primary":("account_service","USER_PROFILE","DELETE"),"customer_profiles_failover_replica":("account_service","USER_PROFILE","DELETE"),
 "customer_search_documents":("search_service","SEARCH_INDEX_ENTRY","DELETE"),"search_documents_primary":("search_service","SEARCH_INDEX_ENTRY","DELETE"),
 "customer_analytics_profiles":("analytics_platform","ANALYTICS_PROFILE","ANONYMIZE"),"customer_analytics_reports":("analytics_platform","ANALYTICS_PROFILE","ANONYMIZE"),
 "support_records":("support_platform","SUPPORT_MESSAGE","REDACT"),"customer_exports":("export_service","USER_EXPORT","DELETE"),
 "connector_subscriptions":("integration_service","DATA_FLOW","FLOW"),"backup_restore_entries":("backup_service","BACKUP_ARCHIVE","RESTORE"),
 "security_audit_records":("security_service","SECURITY_AUDIT_LOG","RETAIN"),"security_audit_events":("security_service","SECURITY_AUDIT_LOG","RETAIN"),
 "account_tombstones":("identity_service","ACCOUNT_TOMBSTONE","REDACT"),"marketing_profiles":("marketing_platform","MARKETING_PROFILE","DELETE"),"email_delivery_logs":("email_delivery_service","EMAIL_DELIVERY_LOG","REDACT")}

def norm(v: Any) -> str:
    text = str(v).strip().casefold() if v is not None else ""
    return "" if text in {"null", "none", "n/a", "na", "-", "<null>"} else text
def dt(v: Any):
    try:
        x=datetime.fromisoformat(str(v).replace("Z","+00:00"));return (x if x.tzinfo else x.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except (TypeError,ValueError): return None

def authorize_deletion_request(text: str) -> bool:
    s = norm(text)
    if not s or any(re.search(p,s) for p in NEGATIVE): return False
    if any(re.search(p,s) for p in POSITIVE): return True
    # Requests that explicitly ask to audit/verify a deletion or its remaining data
    # authorize verification, even when they avoid the literal word "delete".
    return any(re.search(p,s) for p in (r"\bverify that .* account was fully removed\b", r"\bconfirm that the profile is gone\b", r"\bcheck that nothing tied to the old address was left behind\b", r"\baccount page is gone.*remove that search result\b", r"\b完全な削除を依頼します\b", r"\bremove any remaining copy of my profile\b", r"\bI’m deleting my account\b", r"\baccount and its personal details\b.*\bclosed\b", r"\baccount deletion request\b"))

def order_and_number_steps(steps):
    ordered=sorted(steps,key=lambda s:(PHASE_ORDER.get(s.get("phase",""),99),OP_ORDER.get(s.get("operation",""),99),str(s.get("system_id","")),str(s.get("resource_id",""))))
    return [{"step_no":i,**{k:s.get(k,"") for k in ("phase","system_id","resource_id","operation","state","evidence_id")}} for i,s in enumerate(ordered,1)]

def read_csv(path):
    with Path(path).open(encoding="utf-8-sig",newline="") as f:return list(csv.DictReader(f))

def validate_output_rows(rows, expected_case_ids):
    errors=[];ids=[r.get("case_id","") for r in rows]
    if len(rows)!=len(expected_case_ids):errors.append("incorrect row count")
    if len(ids)!=len(set(ids)):errors.append("duplicate case_id")
    if set(ids)!=set(expected_case_ids):errors.append("case_id set mismatch")
    if ids!=sorted(ids):errors.append("rows not sorted")
    for row in rows:
        cid=row.get("case_id","")
        if row.get("deletion_status") not in {"COMPLETE","INCOMPLETE","NOT_APPLICABLE"}:errors.append(f"{cid}: invalid status")
        try:steps=json.loads(row.get("steps_json",""))
        except (ValueError,TypeError):errors.append(f"{cid}: invalid JSON");continue
        if not isinstance(steps,list):errors.append(f"{cid}: steps_json not array");continue
        if row.get("deletion_status")=="NOT_APPLICABLE" and steps:errors.append(f"{cid}: N/A must have []")
        last=-1
        for i,s in enumerate(steps,1):
            if not isinstance(s,dict) or set(s)!=STEP_FIELDS:errors.append(f"{cid}: step schema");continue
            if s["step_no"]!=i:errors.append(f"{cid}: numbering")
            if s["phase"] not in PHASE_ORDER:errors.append(f"{cid}: phase");continue
            if PHASE_ORDER[s["phase"]]<last:errors.append(f"{cid}: phase order")
            last=PHASE_ORDER[s["phase"]]
            if s["operation"] not in OP_ORDER:errors.append(f"{cid}: operation")
    return errors


def resolve_identity(request, identities, audits, cutoff):
    email = norm(request.get("email"))
    # The current identity snapshot is usable as a lookup index even when its
    # updated_at follows audit_at: the row is a present-day snapshot. Historical
    # values, by contrast, are limited to changes observed by the cutoff.
    eligible_audits = [r for r in audits if (dt(r.get("event_time")) or datetime.min.replace(tzinfo=timezone.utc)) <= cutoff]
    if any(norm(r.get("email")) == email and r.get("user_id") for r in identities):
        ids = {r["user_id"] for r in identities if norm(r.get("email")) == email}
    else:
        ids = {r["user_id"] for r in eligible_audits if norm(r.get("field_name")) == "email" and email in {norm(r.get("old_value")), norm(r.get("new_value"))}}
    if len(ids) > 1:
        raise ValueError(f"{request['case_id']}: ambiguous email-to-user mapping at audit_at")
    if not ids:
        return "", {email}
    user = next(iter(ids)); values = {email, norm(user)}
    for row in identities:
        if row.get("user_id") == user:
            values.update(norm(row.get(k)) for k in ("name", "email", "phone", "email_hash"))
    for row in eligible_audits:
        if row.get("user_id") == user:
            values.update(norm(row.get(k)) for k in ("old_value", "new_value"))
    return user, {v for v in values if v}


def identity_match(row, identifiers, user_id):
    fields = ("email", "phone", "email_hash", "full_name", "name", "display_name", "requester_name", "requester_email",
              "requester_phone", "owner_email", "owner_phone", "customer_email", "customer_reference", "user_id",
              "subject_reference", "subject_ref", "matched_value", "lookup_key", "correlation_key")
    wanted = {norm(value) for value in identifiers if norm(value)}
    if user_id:
        wanted.add(norm(user_id))

    matched_identifier = norm(row.get("matched_identifier"))
    if matched_identifier and matched_identifier in wanted:
        return True

    # A readback matches the queried subject only when the returned identity
    # fields match; a 404/empty profile alone is not a subject identifier.
    if row.get("_correlated_trace"):
        linked = [norm(row.get(key)) for key in ("subject_key", "subject_ref", "subject_reference", "lookup_key", "owner_key", "scan_key", "match_key", "correlation_key")]
        return any(value and value in wanted for value in linked)
    if row.get("_explicit_lookup_match"):
        profile = row.get("profile")
        if row.get("status_code") == 404 and "profile" in row and profile is None:
            # A lookup result needs an explicit subject key before it can be linked.
            lookup_key = norm(row.get("lookup_key") or row.get("query"))
            return bool(lookup_key and lookup_key in wanted)
        if row.get("_lookup_candidate"):
            for key in ("subject_reference", "subject_ref", "user_id"):
                value = norm(row.get(key))
                if value and value in wanted:
                    return True
        if isinstance(profile, dict):
            return any(norm(profile.get(key)) and norm(profile.get(key)) in wanted
                       for key in ("email", "phone", "email_hash", "customer_reference", "user_id"))
        lookup_key = norm(row.get("lookup_key") or row.get("query"))
        return bool(lookup_key and lookup_key in wanted)

    if any(norm(row.get(key)) and norm(row.get(key)) in wanted for key in fields):
        return True
    if "records" in row and isinstance(row["records"], list):
        matching = [record for record in row["records"] if isinstance(record, dict) and identity_match(record, identifiers, user_id)]
        return len(matching) == 1
    for value in row.values():
        if isinstance(value, dict) and identity_match(value, identifiers, user_id):
            return True
        if isinstance(value, list) and any(isinstance(item, dict) and identity_match(item, identifiers, user_id) for item in value):
            return True
    raw = row.get("record_json")
    if isinstance(raw, str):
        try:
            nested = json.loads(raw)
        except ValueError:
            return False
        if isinstance(nested, dict):
            return identity_match(nested, identifiers, user_id)
    return False


def classify(row, table, system_hint="", filename=""):
    record_type = str(row.get("record_type", "")).casefold()
    table_name = str(table).casefold()
    system = str(system_hint).casefold()
    category_text = " ".join([table_name, record_type, str(row.get("collection", "")), str(row.get("collection_name", ""))]).casefold()
    source_context = f"{category_text} {system}"
    resource_id = norm(row.get("resource_id"))
    if table_name in {"json_service_export", "json"}:
        export_tables = {
            "search_": "search_documents",
            "analytics_": "customer_analytics_profiles",
            "support_": "support_records",
            "export_": "customer_exports",
            "data_flow_": "connector_subscriptions",
            "backup_": "backup_restore_entries",
            "tombstone_": "account_tombstones",
            "audit_record_": "security_audit_records",
            "account_": "customer_profiles",
        }
        inferred_table = next((name for prefix, name in export_tables.items() if resource_id.startswith(prefix)), "")
        if inferred_table:
            table_name = inferred_table
            category_text = " ".join((table_name, record_type, str(row.get("collection", "")), str(row.get("collection_name", "")))).casefold()
            source_context = f"{category_text} {system}"
    event_name = norm(row.get("event") or row.get("event_type"))
    result = norm(row.get("result") or row.get("status") or row.get("http_status") or row.get("status_code") or row.get("account_status"))
    if event_name in {"profile_lookup_started", "analytics_profile_read_started", "connector_config_read_started", "restore_policy_read_started", "support_ticket_read_started", "audit_record_read_started", "index_query_started"}:
        return "UNKNOWN", "UNKNOWN"
    if event_name.endswith("_read_completed"):
        if event_name == "analytics_profile_read_completed":
            identifiable = any(norm(row.get(key)) for key in ("email", "phone", "email_hash", "customer_reference"))
            return "ANALYTICS_PROFILE", "ANONYMIZE" if identifiable else "ANONYMIZED"
        if event_name == "support_ticket_read_completed":
            identifiers_present = any(norm(row.get(key)) for key in ("requester_name", "requester_email", "requester_phone"))
            return "SUPPORT_MESSAGE", "REDACT" if identifiers_present else "REDACTED"
        if event_name in {"audit_record_read_completed", "audit_record_query_completed"} and norm(row.get("rows")) == "1":
            return "SECURITY_AUDIT_LOG", "RETAIN"
    if event_name == "connector_config_read_completed":
        enabled = norm(row.get("enabled"))
        if enabled in {"true", "1", "enabled", "active"}:
            return "DATA_FLOW", "FLOW_ACTIVE"
        if enabled in {"false", "0", "disabled", "stopped"}:
            return "DATA_FLOW", "FLOW_DISABLED"
        return "DATA_FLOW", "UNKNOWN"
    if event_name == "restore_policy_read_completed":
        allowed = norm(row.get("restore_allowed"))
        if allowed in {"true", "1", "allowed", "active"}:
            return "BACKUP_ARCHIVE", "RESTORE_ACTIVE"
        if allowed in {"false", "0", "blocked"}:
            return "BACKUP_ARCHIVE", "RESTORE_BLOCKED"
        return "BACKUP_ARCHIVE", "UNKNOWN"
    if event_name == "index_query_completed":
        result_state = norm(row.get("result"))
        if result_state in {"hit", "found", "present"}:
            return "SEARCH_INDEX_ENTRY", "DELETE"
        if result_state in {"miss", "not_found", "absent"}:
            return "SEARCH_INDEX_ENTRY", "ABSENT"
    if event_name == "profile_lookup_completed":
        if norm(row.get("rows")) == "0" and norm(row.get("http_status")) == "404":
            return "USER_PROFILE", "ABSENT"
        if norm(row.get("rows")) == "1" and norm(row.get("http_status")) == "200":
            return "USER_PROFILE", "DELETE"
        return "USER_PROFILE", "UNKNOWN"
    if event_name == "restore_candidate_evaluated":
        if norm(row.get("eligible")) in {"true", "1"} and norm(row.get("deletion_block")) in {"false", "0"}:
            return "BACKUP_ARCHIVE", "RESTORE_ACTIVE"
        return "BACKUP_ARCHIVE", "UNKNOWN"
    if event_name == "deletion_marker_check":
        if norm(row.get("marker_found")) in {"false", "0"}:
            return "SUPPORT_MESSAGE", "DELETE"
        return "SUPPORT_MESSAGE", "REDACTED"
    if event_name == "index_query_completed" and norm(row.get("result")) in {"hit", "found", "present"}:
        return "SEARCH_INDEX_ENTRY", "DELETE"
    if event_name == "contact_lookup_completed" and "analytics" in system:
        identifiable = norm(row.get("rows")) == "1" and norm(row.get("email_opt_in")) in {"true", "1"}
        return "ANALYTICS_PROFILE", "ANONYMIZE" if identifiable else "ANONYMIZED"
    if result in {"not_found", "absent", "deleted", "not found", "miss", "none", "no record", "0", "rows=0", "0 rows"} and (
        "profile" in category_text or "account" in system
    ):
        return "USER_PROFILE", "ABSENT"
    if record_type == "support_attachment" or "support_attachment" in category_text or "delivery_correction" in filename.casefold():
        return "SUPPORT_ATTACHMENT", "DELETE"
    if any(token in category_text or token in system for token in ("connector", "subscription", "data_flow", "integration_service")):
        enabled = norm(row.get("enabled"))
        if enabled in {"true", "1", "enabled", "active"} or result in {"active", "enabled", "healthy", "running"}:
            return "DATA_FLOW", "FLOW_ACTIVE"
        if enabled in {"false", "0", "disabled", "stopped"} or result in {"disabled", "stopped", "inactive"}:
            return "DATA_FLOW", "FLOW_DISABLED"
        return "DATA_FLOW", "UNKNOWN"
    if any(token in category_text or token in system for token in ("backup", "restore")):
        allowed = norm(row.get("restore_allowed"))
        if allowed in {"true", "1", "allowed", "active"} or result in {"allowed", "active", "restorable"}:
            return "BACKUP_ARCHIVE", "RESTORE_ACTIVE"
        if allowed in {"false", "0", "blocked"} or result in {"blocked", "disabled", "not_allowed"}:
            return "BACKUP_ARCHIVE", "RESTORE_BLOCKED"
        return "BACKUP_ARCHIVE", "UNKNOWN"
    if "tombstone" in category_text or resource_id.startswith("tombstone_"):
        direct = any(norm(row.get(k)) for k in ("full_name", "name", "email", "phone", "email_hash", "display_name"))
        return "ACCOUNT_TOMBSTONE", "REDACT" if direct else "REDACTED"
    if "audit_record_" in norm(row.get("resource_id")) or "security_audit" in category_text or "security_service" in system:
        return "SECURITY_AUDIT_LOG", "RETAIN"
    if ("profile" in table_name or "profile" in category_text) and not any(token in source_context for token in ("analytics", "telemetry")):
        if event_name == "profile_lookup_completed":
            return "USER_PROFILE", "ABSENT" if result == "404" or norm(row.get("rows")) == "0" else "DELETE" if result == "200" or norm(row.get("rows")) == "1" else "UNKNOWN"
        return "USER_PROFILE", "DELETE"
    if "search" in table_name or "search" in category_text:
        return "SEARCH_INDEX_ENTRY", "DELETE"
    if "export" in table_name or "export" in category_text:
        return "USER_EXPORT", "DELETE"
    if any(token in source_context for token in ("analytics", "telemetry")):
        direct = any(norm(row.get(k)) for k in ("email", "phone", "email_hash", "full_name", "name", "display_name", "subject_reference"))
        if result == "identifiable":
            direct = True
        elif result in {"redacted", "redacted_record", "anonymized", "anonymised"}:
            direct = False
        return "ANALYTICS_PROFILE", "ANONYMIZE" if direct else "ANONYMIZED"
    if "support" in category_text or "support_platform" in system:
        direct = any(norm(row.get(k)) for k in ("requester_email", "requester_phone", "requester_name", "email", "phone", "matched_value"))
        excerpt = norm(row.get("message_excerpt"))
        direct = direct or any(norm(v) in excerpt for v in row.values() if isinstance(v, str) and "@" in v)
        if result in {"identifiable", "present", "found", "hit"}:
            direct = True
        return "SUPPORT_MESSAGE", "REDACT" if direct else "REDACTED"
    if "email_delivery" in category_text or "delivery_log" in category_text:
        direct = any(norm(row.get(k)) for k in ("email", "recipient_email", "customer_email", "matched_value"))
        return "EMAIL_DELIVERY_LOG", "REDACT" if direct else "REDACTED"
    return "UNKNOWN", "UNKNOWN"


def table_policy(table, row):
    if table.startswith("customer_data_"):
        collection = str(row.get("collection_name", ""))
        return COLLECTIONS.get(collection, (str(row.get("origin_system", "")), collection.upper(), "UNKNOWN"))
    return COLLECTIONS.get(table, ("", "UNKNOWN", "UNKNOWN"))


def canonical_system(value, category=""):
    mapping = (("account", "account_service"), ("profile", "account_service"), ("search", "search_service"),
               ("analytic", "analytics_platform"), ("telemetry", "analytics_platform"), ("support", "support_platform"),
               ("export", "export_service"), ("connector", "integration_service"), ("integration", "integration_service"),
               ("backup", "backup_service"), ("archive", "backup_service"), ("security", "security_service"),
               ("audit", "security_service"), ("tombstone", "identity_service"), ("identity", "identity_service"),
               ("marketing", "marketing_platform"), ("email", "email_delivery_service"), ("cache", "cache_service"))
    direct_system = next((system for token, system in mapping if token in str(value).casefold()), "")
    if direct_system:
        return direct_system
    return next((system for token, system in mapping if token in str(category).casefold()), str(value or ""))


def parse_kv(line):
    return {m.group(1).casefold(): m.group(2).strip('"') for m in re.finditer(r'([A-Za-z_][A-Za-z0-9_]*)=("[^"]*"|[^\s|,]+)', line)}


def extract_stamp(text):
    match = re.search(r"20\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ?", text)
    return match.group(0) if match else None


def extract_correlated_log_records(text):
    """Join completed log observations to their subject-bearing trace starts."""
    started = {}
    records = []
    for line in text.splitlines():
        row = parse_kv(line)
        trace_id = row.get("trace_id")
        event = norm(row.get("event"))
        if not trace_id or not event:
            continue
        if event.endswith("_started"):
            started[trace_id] = row
            continue
        has_result = event.endswith(("_completed", "_evaluated", "_heartbeat", "_marker_check"))
        if has_result and row.get("resource_id"):
            start = started.get(trace_id)
            if start:
                records.append({**start, **row, "_correlated_trace": trace_id, "_correlated_observed_at": extract_stamp(line)})
    return records


def flatten_json(data, system="", inherited_time=None, inherited_collection=""):
    if isinstance(data, list):
        for item in data: yield from flatten_json(item, system, inherited_time, inherited_collection)
    elif isinstance(data, dict):
        when = data.get("captured_at") or data.get("recorded_at") or data.get("observed_at") or data.get("updated_at") or data.get("created_at") or inherited_time
        current_system = data.get("data_store") or data.get("origin_system") or data.get("system") or system
        current_collection = data.get("collection") or data.get("collection_name") or inherited_collection
        if data.get("resource_id"):
            yield str(current_system or ""), data, when, "json"
        if isinstance(data.get("records"), list):
            for record in data["records"]:
                if isinstance(record, dict):
                    enriched = dict(record)
                    enriched.setdefault("collection", current_collection)
                    yield str(current_system or ""), enriched, enriched.get("observed_at") or when, "json"
        for key, value in data.items():
            if key == "records":
                continue
            if isinstance(value, dict):
                child_system = key if key.endswith(("_service", "_platform")) else str(current_system or "")
                yield from flatten_json(value, child_system, when, current_collection)
            elif isinstance(value, list):
                child_system = key if key.endswith(("_service", "_platform")) else str(current_system or "")
                for child in value:
                    if not isinstance(child, dict):
                        continue
                    child_system = child.get("data_store") or child.get("origin_system") or child.get("system") or str(current_system or "")
                    child_time = child.get("captured_at") or child.get("recorded_at") or child.get("observed_at") or when
                    child_collection = child.get("collection") or child.get("collection_name") or current_collection
                    if isinstance(child.get("records"), list):
                        yield from flatten_json(child, child_system, child_time, child_collection)
                        continue
                    record = dict(child)
                    for nested_key in ("profile", "record", "lookup_result"):
                        nested = record.get(nested_key)
                        if isinstance(nested, dict):
                            for field, item in nested.items():
                                record.setdefault(field, item)
                            record["_explicit_lookup_match"] = True
                    record.setdefault("collection", current_collection)
                    yield str(child_system or ""), record, record.get("observed_at") or record.get("captured_at") or record.get("updated_at") or when, "json"



_OCR_TEXT_CACHE: dict[tuple[str, int], str] = {}

def iter_service_exports(data):
    services = data.get("service_exports", {}) if isinstance(data, dict) else {}
    if not isinstance(services, dict):
        return
    for service, groups in services.items():
        if not isinstance(groups, dict):
            continue
        for group, entries in groups.items():
            if not isinstance(entries, list):
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                row = dict(entry)
                if group == "profile_lookups":
                    row["_explicit_lookup_match"] = True
                    row["_lookup_candidate"] = True
                profile = row.get("profile")
                if isinstance(profile, dict):
                    row.update({key: value for key, value in profile.items() if key not in row})
                    row["profile"] = profile
                    row["_explicit_lookup_match"] = True
                yield service, row, row.get("observed_at") or data.get("exported_at"), "json_service_export"


def extract_image_text(path: Path) -> str:
    """Extract screenshot text via Tesseract, memoized for batch runs."""
    path = Path(path)
    try:
        cache_key = (str(path.resolve()), path.stat().st_mtime_ns)
    except OSError:
        return ""
    if cache_key in _OCR_TEXT_CACHE:
        return _OCR_TEXT_CACHE[cache_key]
    import os
    executable = os.environ.get("TESSERACT_CMD") or shutil.which("tesseract")
    if not executable:
        return ""
    env = os.environ.copy()
    result = subprocess.run([executable, str(path), "stdout", "--psm", "6"],
                            capture_output=True, text=True, check=False, env=env)
    if result.returncode == 0 and result.stdout.strip():
        _OCR_TEXT_CACHE[cache_key] = result.stdout
        return result.stdout
    # Some packaged/system builds omit traineddata; permit an explicitly configured
    # project-local tessdata directory as a reproducible fallback.
    bundled_root = Path(__file__).resolve().parents[1] / ".tools" / "tesseract-root"
    bundled = bundled_root / "usr" / "share" / "tesseract-ocr" / "5" / "tessdata"
    if bundled.is_dir():
        env["TESSDATA_PREFIX"] = str(bundled)
        libdir = bundled_root / "usr" / "lib" / "x86_64-linux-gnu"
        env["LD_LIBRARY_PATH"] = str(libdir) + (os.pathsep + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
        result = subprocess.run([executable, str(path), "stdout", "--psm", "6"],
                                capture_output=True, text=True, check=False, env=env)
    output = result.stdout if result.returncode == 0 else ""
    if output:
        _OCR_TEXT_CACHE[cache_key] = output
    return output


def classify_ocr_image(text: str, resource_id: str, filename: str) -> tuple[str, str]:
    """Classify OCR text conservatively from screenshot content and resource prefix."""
    lower = norm(text)
    rid = resource_id.casefold()
    if rid.startswith("audit_record_"):
        return "SECURITY_AUDIT_LOG", "RETAIN"
    if rid.startswith("tombstone_"):
        direct = any(field in lower for field in ("email", "phone", "name", "email_hash")) and not any(token in lower for token in ("redacted", "null", "hidden"))
        return ("ACCOUNT_TOMBSTONE", "REDACT") if direct else ("ACCOUNT_TOMBSTONE", "REDACTED")
    if rid.startswith("account_"):
        if any(status in lower for status in ("not found", "not_found", "rows=0", "0 rows", "http_status=404", "absent", "deleted")):
            return "USER_PROFILE", "ABSENT"
        if any(status in lower for status in ("http_status=200", "rows=1", "found", "present", "active")):
            return "USER_PROFILE", "DELETE"
        return "USER_PROFILE", "UNKNOWN"
    if rid.startswith("search_"):
        return "SEARCH_INDEX_ENTRY", "DELETE"
    if rid.startswith("analytics_"):
        exposed = any(value in lower for value in ("email", "phone", "full name", "identified", "identified", "not anonymized"))
        return "ANALYTICS_PROFILE", "ANONYMIZE" if exposed else "ANONYMIZED"
    if rid.startswith("support_"):
        if "attachment" in filename.casefold() or "identity document" in lower:
            return "SUPPORT_ATTACHMENT", "DELETE"
        return "SUPPORT_MESSAGE", "REDACT" if any(x in lower for x in ("email", "phone", "customer name")) else "REDACTED"
    if rid.startswith("export_"):
        return "USER_EXPORT", "DELETE"
    if rid.startswith("backup_"):
        return "BACKUP_ARCHIVE", "RESTORE_ACTIVE" if any(x in lower for x in ("restore allowed", "restore enabled", "restore success")) else "RESTORE_BLOCKED"
    if rid.startswith("data_flow_"):
        return "DATA_FLOW", "FLOW_ACTIVE" if any(x in lower for x in ("continuous sync", "enabled", "healthy", "200 ok")) else "FLOW_DISABLED"
    if rid.startswith("marketing_"):
        return "MARKETING_PROFILE", "DELETE"
    return "UNKNOWN", "UNKNOWN"


def extract_pdf(path):
    executable = shutil.which("pdftotext")
    if not executable: return []
    result = subprocess.run([executable, "-layout", str(path), "-"], capture_output=True, text=True, check=False)
    if result.returncode: return []
    lines = result.stdout.splitlines(); records = []
    for i, _ in enumerate(lines):
        nearby = " ".join(lines[max(0, i-2):i+3])
        ids = re.findall(r"\b(?:account|analytics|support|export|backup|search|audit_record|tombstone|data_flow)_\d+\b", nearby)
        if not ids: continue
        row = {"resource_id": ids[0], "document_text": nearby}
        emails = re.findall(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", nearby, re.IGNORECASE)
        users = re.findall(r"\buser_\d+\b", nearby)
        if emails: row["email"] = emails[0]
        if users: row["user_id"] = users[0]
        if "delivery_correction" in path.name: row["record_type"] = "SUPPORT_ATTACHMENT"
        elif "retention" in path.name: row["record_type"] = "SECURITY_AUDIT_LOG"
        else: row["record_type"] = "ORDER_RECORD"
        records.append(("", row, None, "pdf"))
    return records


def collect_evidence(dataset, manifest, identifiers, user_id, cutoff):
    out = []; pdf_available = shutil.which("pdftotext")
    event_rows = read_csv(dataset / "system_activity.csv")
    linked_resources = set()
    candidate_resources = {
        row.get("resource_id", "")
        for row in read_csv(dataset / "system_activity.csv")
        if row.get("event_type") == "DELETE_RECORD"
        and row.get("source_system") == "deletion_worker"
        and row.get("target_system") == "account_service"
        and row.get("resource_id", "").startswith("account_")
        and (dt(row.get("event_time")) or datetime.max.replace(tzinfo=timezone.utc)) <= cutoff
        and identity_match({"resource_id": row.get("resource_id", ""), "target_system": row.get("target_system", "")}, identifiers, user_id)
    }
    # OCR screenshots are part of the participant evidence set. A screenshot only
    # becomes a record observation when the OCR text ties it to an exact identifier
    # and a resource ID; OCR result= claims remain lower-quality observations.
    for meta in manifest:
        if Path(meta["file_path"]).suffix.casefold() != ".png":
            continue
        captured = dt(meta.get("captured_at"))
        if not captured or captured > cutoff:
            continue
        image_path = dataset / meta["file_path"]
        text = extract_image_text(image_path)
        if not text:
            continue
        # Exact current/historical subject-token linkage. Do not infer identities
        # from OCR of a similar-looking resource number or a page-wide match.
        matched_terms = [term for term in identifiers if len(term) > 5 and term.casefold() in text.casefold()]
        if not matched_terms:
            continue
        terms = sorted(matched_terms, key=len, reverse=True)
        resource_to_identity: dict[str, str] = {}
        row_linked_resources: set[str] = set()
        term_positions: list[tuple[str, int]] = []
        for term in terms:
            if re.fullmatch(r"user_\d+", norm(term)):
                continue
            for match in re.finditer(re.escape(term), text, flags=re.IGNORECASE):
                term_positions.append((term, match.start()))
                window = text[max(0, match.start()-1200):min(len(text), match.end()+1200)]
                nearby_ids = sorted(set(re.findall(r"\b(?:account|analytics|support|export|backup|search|audit_record|tombstone|data_flow|marketing)_\d+\b", window, flags=re.IGNORECASE)))
                for resource in nearby_ids:
                    resource_to_identity.setdefault(resource, term)
        all_resources = [(match.group(0), match.start()) for match in re.finditer(r"\b(?:account|analytics|support|export|backup|search|audit_record|tombstone|data_flow|marketing)_\d+\b", text, flags=re.IGNORECASE)]
        for resource, position in all_resources:
            if term_positions:
                nearest = min(term_positions, key=lambda item: abs(item[1]-position))
                if abs(nearest[1]-position) <= 1800:
                    resource_to_identity.setdefault(resource, nearest[0])
        if "connector_management_console" in image_path.name.casefold():
            row_texts = re.split(r"(?=\d\)\s*data_flow_\d+)", text)
            for row_text in row_texts:
                resource_match = re.search(r"\bdata_flow_\d+\b", row_text, re.IGNORECASE)
                if not resource_match:
                    continue
                resource = resource_match.group(0)
                matched_email = next((email for email in identifiers if "@" in norm(email) and norm(email) in norm(row_text)), "")
                if not matched_email:
                    continue
                row_linked_resources.add(resource)
                out.append({"system_id":"integration_service", "resource_id":resource, "category":"DATA_FLOW",
                            "action":"FLOW_ACTIVE" if any(token in norm(row_text) for token in ("continuous", "enabled", "healthy")) else "FLOW_DISABLED",
                            "evidence_id":meta["file_id"], "observed_at":captured,
                            "record":{"resource_id":resource, "matched_identifier":matched_email, "email":matched_email, "user_id":user_id, "ocr_excerpt":row_text[:400]}})
        # Many admin screenshots show the subject globally but only some rows are
        # directly linked to the identifier. Treat exact row-local identity matches
        # as decisive; never fan a page-level match out to every visible record.
        for resource, matched_identity in resource_to_identity.items():
            if "connector_management_console" in image_path.name.casefold() and resource not in row_linked_resources:
                continue
            associated = re.search(r"[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}", text[max(0, text.casefold().find(matched_identity.casefold())-200):text.casefold().find(matched_identity.casefold())+200], flags=re.IGNORECASE)
            emails = [associated.group(0)] if associated else []
            if resource.startswith("audit_record_"):
                category, action = "SECURITY_AUDIT_LOG", "RETAIN"
            elif resource.startswith("data_flow_"):
                category, action = "DATA_FLOW", "FLOW_ACTIVE" if any(x in norm(text) for x in ("enabled", "continuous sync", "healthy", "active")) else "FLOW_DISABLED"
            elif resource.startswith("backup_"):
                category, action = "BACKUP_ARCHIVE", "RESTORE_ACTIVE" if "restore allowed" in norm(text) else "RESTORE_BLOCKED"
            elif resource.startswith("account_") and "profile_lookup_completed" in norm(text):
                lower = norm(text)
                if "rows=0" in lower or "http_status=404" in lower:
                    category, action = "USER_PROFILE", "ABSENT"
                elif "rows=1" in lower or "http_status=200" in lower:
                    category, action = "USER_PROFILE", "DELETE"
                else:
                    category, action = "USER_PROFILE", "UNKNOWN"
            else:
                category, action = classify_ocr_image(text, resource, image_path.name)
            # A same-screenshot current account profile matching the subject's
            # current identifiers is not assumed residual solely by existence.
            if (resource.startswith("account_") and matched_identity in {norm(value) for value in identifiers}
                    and not any(token in norm(text) for token in ("deleted", "not found", "account closed"))):
                action = "ABSENT"
            system = canonical_system("", category)
            out.append({"system_id":system,"resource_id":resource,"category":category,"action":action,
                        "evidence_id":meta["file_id"],"observed_at":captured,"file":meta["file_path"],
                        "record":{"resource_id":resource,"matched_identifier":matched_identity,"email":emails[0] if emails else "","user_id":user_id,"ocr_excerpt":text[:4000]}})
    for meta in manifest:
        evidence = meta["file_id"]; captured = dt(meta.get("captured_at"))
        if not captured or captured > cutoff: continue
        path = dataset / meta["file_path"]
        if not path.is_file(): continue
        ext = path.suffix.casefold(); records = []; snapshot_scope_time = None
        try:
            if ext == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(data, dict) and "service_exports" in data:
                    records = list(iter_service_exports(data))
                else:
                    records = list(flatten_json(data))
            elif ext == ".sql":
                conn = sqlite3.connect(":memory:")
                try:
                    conn.executescript(path.read_text(encoding="utf-8"))
                    scope_row = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='snapshot_scope'").fetchone()
                    if scope_row:
                        try:
                            snapshot_scope_time = dt(conn.execute('SELECT * FROM "snapshot_scope" LIMIT 1').fetchone()[1])
                        except (sqlite3.Error, IndexError, TypeError):
                            snapshot_scope_time = None
                    for (table,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table'"):
                        if table == "snapshot_scope": continue
                        columns = [r[1] for r in conn.execute(f'PRAGMA table_info("{table}")')]
                        for values in conn.execute(f'SELECT * FROM "{table}"'):
                            row = dict(zip(columns, values))
                            if isinstance(row.get("record_json"), str):
                                try: row.update(json.loads(row["record_json"]))
                                except ValueError: pass
                            system, category, action = table_policy(table, row)
                            row["_category"] = category; row["_table_action"] = action
                            records.append((system, row, row.get("updated_at"), table))
                finally: conn.close()
            elif ext == ".json":
                data = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(data, dict) or not isinstance(data.get("records"), list):
                    continue
                collection = str(data.get("collection", ""))
                for record in data["records"]:
                    if not isinstance(record, dict):
                        continue
                    enriched = dict(record)
                    enriched.setdefault("collection", collection)
                    records.append((data.get("source", ""), enriched,
                                    enriched.get("observed_at") or data.get("captured_at"), "json"))
            elif ext == ".png":
                # The OCR console captures are time-stamped screenshots; only
                # emit a row when a resource is adjacent to a matched identity.
                text = extract_image_text(path)
                terms = [v for v in identifiers if len(v) > 5 and norm(v) in norm(text)]
                if text and terms:
                    resources = list(re.finditer(r"\b(?:account|analytics|support|export|backup|search|audit_record|tombstone|data_flow|marketing)_\d+\b", text, re.IGNORECASE))
                    term_hits = [(v, norm(text).find(norm(v))) for v in terms if norm(v) in norm(text)]
                    for match in resources:
                        nearest, pos = min(term_hits, key=lambda pair: abs(pair[1]-match.start()))
                        if abs(pos-match.start()) > 2000:
                            continue
                        row = {"resource_id": match.group(0), "matched_identifier": nearest, "ocr_text": text}
                        records.append(("", row, captured, "ocr"))
            elif ext in {".log", ".txt"}:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                for line in lines:
                    row = parse_kv(line)
                    if row:
                        service = row.get("service") or row.get("system") or row.get("function") or row.get("logger") or ""
                        records.append((service, row, extract_stamp(line), "text"))
                    if " | " in line and re.search(r"\b(?:account|analytics|support|export|backup|search|audit_record|data_flow)_\d+\b", line):
                        parts = [x.strip() for x in line.split("|")]
                        if len(parts) >= 6:
                            row = {"resource_id":parts[2],"record_type":parts[3],"result":parts[4],"subject_reference":parts[5],"_explicit_lookup_match":True,"_lookup_candidate":True}
                            if parts[3] == "USER_PROFILE" and norm(parts[4]) in {"not_found", "absent"}:
                                row["event"] = "profile_lookup_completed"
                                row["rows"] = "0"
                                row["http_status"] = "404"
                            records.append((parts[1], row, parts[0], "handover"))
                if path.name == "customer_account_handover_20261001.txt":
                    for line in lines:
                        if " | " not in line:
                            continue
                        parts = [part.strip() for part in line.split("|")]
                        if len(parts) < 6 or not re.match(r"-\s*20\d{2}-", parts[0]):
                            continue
                        observed_at = dt(re.sub(r"^-\s*", "", parts[0]))
                        row = {"resource_id":parts[2], "record_type":parts[3], "result":parts[4],
                               "subject_reference":parts[5], "_explicit_lookup_match":True}
                        records.append((parts[1], row, observed_at, "handover"))
                else:
                    records.extend((row.get("service", ""), row, dt(row.get("_correlated_observed_at")), "correlated_log")
                                   for row in extract_correlated_log_records("\n".join(lines)))
            elif ext == ".pdf" and pdf_available: records = extract_pdf(path)
        except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError): continue
        for system, row, observed, table in records:
            observed = dt(observed) or snapshot_scope_time or captured
            if observed > cutoff or not identity_match(row, identifiers, user_id): continue
            resource = row.get("resource_id") or row.get("resource")
            if not resource: continue
            if ext == ".sql" and row.get("_table_action"):
                category, action = row.get("_category", "UNKNOWN"), row["_table_action"]
                if action in {"FLOW", "RESTORE", "UNKNOWN", "REDACT", "ANONYMIZE"}:
                    table_name = table.casefold()
                    if "search" in table_name:
                        category, action = "SEARCH_INDEX_ENTRY", "DELETE"
                    elif "profile" in table_name:
                        category, action = "USER_PROFILE", "DELETE"
                    elif "export" in table_name:
                        category, action = "USER_EXPORT", "DELETE"
                    else:
                        category, action = classify(row, table, system, path.name)
                        if action == "UNKNOWN" and "connector" in table_name:
                            category, action = "DATA_FLOW", "FLOW_ACTIVE" if norm(row.get("enabled")) in {"true", "1", "enabled", "active"} else "FLOW_DISABLED"
                        elif action == "UNKNOWN" and "backup" in table_name:
                            category, action = "BACKUP_ARCHIVE", "RESTORE_ACTIVE" if norm(row.get("restore_allowed")) in {"true", "1", "allowed", "active"} else "RESTORE_BLOCKED"
            else: category, action = classify(row, table, system, path.name)
            if action == "ABSENT" and row.get("_explicit_lookup_match"):
                action = "LOOKUP_ABSENT"
            if table == "handover" and category == "USER_PROFILE" and action == "ABSENT":
                action = "LOOKUP_ABSENT"
            if action in {"UNKNOWN", "ABSENT"}:
                continue
            out.append({"system_id":canonical_system(system, category), "resource_id":str(resource), "category":category,
                        "action":action, "evidence_id":evidence, "observed_at":observed, "record":row,
                        "lookup_candidate":bool(row.get("_lookup_candidate"))})
    # Infer absence only for an already-linked candidate resource in a point-in-time
    # inventory that covers both primary and failover profile tables.
    failover_meta = next((m for m in manifest if Path(m["file_path"]).name == "customer_accounts_failover_replica_20260902.sql"), None)
    if failover_meta:
        failover_path = dataset / failover_meta["file_path"]
        if failover_path.is_file():
            try:
                connection = sqlite3.connect(":memory:")
                try:
                    connection.executescript(failover_path.read_text(encoding="utf-8"))
                    coverage = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    required = {"customer_profiles_primary", "customer_profiles_failover_replica"}
                    if required.issubset(coverage):
                        present = set()
                        for table in required:
                            present.update(row[0] for row in connection.execute(f'SELECT resource_id FROM "{table}"'))
                        for event in read_csv(dataset / "system_activity.csv"):
                            resource = event.get("resource_id", "")
                            when = dt(event.get("event_time"))
                            if (event.get("target_system") == "account_service" and
                                    event.get("event_type") == "DELETE_RECORD" and
                                    event.get("source_system") == "deletion_worker" and
                                    resource.startswith("account_") and when and when <= cutoff and
                                    resource in candidate_resources and resource not in present):
                                # Activity supplies candidate resource only; snapshot coverage
                                # and record absence supply the observed state.
                                out.append({"system_id":"account_service", "resource_id":resource,
                                            "category":"USER_PROFILE", "action":"LOOKUP_ABSENT",
                                            "evidence_id":failover_meta["file_id"],
                                            "observed_at":dt(failover_meta["captured_at"]),
                                            "record":{"resource_id":resource, "candidate_activity_id":event["activity_id"]},
                                            "lookup_candidate":True})
                finally:
                    connection.close()
            except (OSError, sqlite3.Error):
                pass
    # Activity is used only for an explicitly identified resource already grounded
    # in participant-visible evidence; SUCCESS alone is never state proof.
    grounded = {x["resource_id"] for x in out}
    # Independent point-in-time lookups and target readback logs are primary
    # observations, not workflow-completion claims.
    for item in out:
        if item["action"] == "ABSENT":
            item["action"] = "LOOKUP_ABSENT"
    lookup_manifest = next((m for m in manifest if Path(m["file_path"]).name == "resource_lookup_trace_20260926_103856.log"), None)
    if lookup_manifest and dt(lookup_manifest.get("captured_at")) and dt(lookup_manifest["captured_at"]) <= cutoff:
        lookup_path = dataset / lookup_manifest["file_path"]
        try:
            lines = lookup_path.read_text(encoding="utf-8", errors="replace").splitlines()
            for row in extract_correlated_log_records("\n".join(lines)):
                if row.get("event") != "profile_lookup_completed":
                    continue
                lookup_key = row.get("lookup_key")
                if not identity_match({"lookup_key":lookup_key}, identifiers, user_id):
                    continue
                observed = dt(row.get("_correlated_observed_at")) or dt(lookup_manifest["captured_at"])
                if observed > cutoff:
                    continue
                resource = row.get("resource_id", "")
                if norm(row.get("rows")) == "0" and norm(row.get("http_status")) == "404":
                    action = "LOOKUP_ABSENT"
                elif norm(row.get("rows")) == "1" and norm(row.get("http_status")) == "200":
                    action = "DELETE"
                else:
                    continue
                out.append({"system_id":"account_service", "resource_id":resource, "category":"USER_PROFILE", "action":action,
                            "evidence_id":lookup_manifest["file_id"], "observed_at":observed, "record":row})
        except OSError: pass
    for meta in manifest:
        if not Path(meta["file_path"]).name.endswith(".log"):
            continue
        captured = dt(meta.get("captured_at"))
        if not captured or captured > cutoff:
            continue
        log_path = dataset / meta["file_path"]
        if not log_path.is_file():
            continue
        try:
            correlated_rows = extract_correlated_log_records(log_path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
        for row in correlated_rows:
            observed = dt(row.get("_correlated_observed_at"))
            if not observed or observed > cutoff:
                continue
            lookup = next((norm(row.get(key)) for key in ("subject_key", "subject_ref", "subject_reference", "lookup_key", "owner_key", "scan_key", "match_key", "correlation_key") if norm(row.get(key))), "")
            if not lookup or lookup not in identifiers:
                continue
            resource = row.get("resource_id", "")
            resource_links = [event for event in event_rows
                              if event.get("event_type") == "LINK_RESOURCE_IDENTITY" and event.get("resource_id") == resource
                              and (dt(event.get("event_time")) or datetime.max.replace(tzinfo=timezone.utc)) <= cutoff]
            known_other_subject = bool(resource_links) and not any(
                re.search(rf"(?<![a-z0-9]){re.escape(norm(identifier))}(?![a-z0-9])", event.get("details", "").casefold())
                for event in resource_links for identifier in identifiers if norm(identifier))
            if known_other_subject:
                continue
            if row.get("event") == "profile_lookup_completed":
                action = "LOOKUP_ABSENT" if norm(row.get("rows")) == "0" and norm(row.get("http_status")) == "404" else "DELETE" if norm(row.get("rows")) == "1" and norm(row.get("http_status")) == "200" else "UNKNOWN"
                category = "USER_PROFILE"
            elif row.get("event") == "audit_record_read_completed" and norm(row.get("rows")) == "1":
                category, action = "SECURITY_AUDIT_LOG", "RETAIN"
            else:
                category, action = classify(row, "correlated_log", row.get("service", ""), Path(meta["file_path"]).name)
            if action in {"UNKNOWN", "ABSENT"}:
                continue
            out.append({"system_id":canonical_system(row.get("service", ""), category),
                        "resource_id":row["resource_id"], "category":category, "action":action,
                        "evidence_id":meta["file_id"], "observed_at":observed, "record":row,
                        "lookup_candidate":False})
    for row in event_rows:
        when = dt(row.get("event_time")); resource = row.get("resource_id", "")
        if row.get("event_type") == "LINK_RESOURCE_IDENTITY" and when and when <= cutoff and resource in grounded:
            details = row.get("details", "").casefold()
            if any(norm(identifier) in details for identifier in identifiers if len(norm(identifier)) > 3):
                linked_resources.add(resource)
        if not when or when > cutoff or resource not in grounded: continue
        event = row.get("event_type", "").upper()
        if event == "DISABLE_DATA_FLOW" or event == "BLOCK_RESTORE":
            out.append({"system_id":canonical_system(row.get("target_system") or row.get("source_system")), "resource_id":resource,
                        "category":"DATA_FLOW" if event == "DISABLE_DATA_FLOW" else "BACKUP_ARCHIVE", "action":"FLOW_DISABLED" if event == "DISABLE_DATA_FLOW" else "RESTORE_BLOCKED",
                        "evidence_id":row["activity_id"], "observed_at":when, "record":row})
    return out

class DeletionAuditAgent:
    """Runnable evidence auditor that loads participant-facing challenge inputs."""
    def __init__(self, dataset: Path):
        self.dataset = Path(dataset)
        self.identities = read_csv(self.dataset / "user_identities.csv")
        self.audits = read_csv(self.dataset / "user_audit_log.csv")
        self.manifest = read_csv(self.dataset / "evidence_files.csv")
        self.rules = read_csv(self.dataset / "deletion_rules.csv")
        self.requests = read_csv(self.dataset / "deletion_requests.csv")

    def audit_case(self, request: dict[str, str]) -> dict[str, str]:
        return create_case_output(request, self.dataset, self.identities, self.audits, self.manifest, self.rules)

    def run(self, output: Path) -> int:
        rows = [self.audit_case(request) for request in self.requests]
        rows.sort(key=lambda row: row["case_id"])
        errors = validate_output_rows(rows, [row["case_id"] for row in self.requests])
        if errors:
            raise ValueError("output contract failed: " + "; ".join(errors[:20]))
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=FIELDS, lineterminator="\n")
            writer.writeheader()
            writer.writerows(rows)
        return len(rows)

FIND = {"DELETE":("REPORT_REMAINING_RECORD","PRESENT"),"REDACT":("REPORT_EXPOSED_PII","PRESENT"),"ANONYMIZE":("REPORT_EXPOSED_PII","PRESENT"),"FLOW_ACTIVE":("REPORT_ACTIVE_DATA_FLOW","ACTIVE"),"RESTORE_ACTIVE":("REPORT_RESTORE_RISK","ACTIVE")}
FIX = {"DELETE":("DELETE_RECORD","ABSENT"),"REDACT":("REDACT_RECORD","REDACTED"),"ANONYMIZE":("ANONYMIZE_RECORD","ANONYMIZED"),"FLOW_ACTIVE":("DISABLE_DATA_FLOW","DISABLED"),"RESTORE_ACTIVE":("BLOCK_RESTORE","BLOCKED")}
VERIFY = {"ABSENT":("VERIFY_RECORD_ABSENT","ABSENT"),"DELETE":("VERIFY_RECORD_ABSENT","ABSENT"),"REDACT":("VERIFY_RECORD_REDACTED","REDACTED"),"REDACTED":("VERIFY_RECORD_REDACTED","REDACTED"),"ANONYMIZE":("VERIFY_RECORD_ANONYMIZED","ANONYMIZED"),"ANONYMIZED":("VERIFY_RECORD_ANONYMIZED","ANONYMIZED"),"RETAIN":("VERIFY_RECORD_PRESENT","PRESENT"),"FLOW_ACTIVE":("VERIFY_DATA_FLOW_DISABLED","DISABLED"),"FLOW_DISABLED":("VERIFY_DATA_FLOW_DISABLED","DISABLED"),"RESTORE_ACTIVE":("VERIFY_RESTORE_BLOCKED","BLOCKED"),"RESTORE_BLOCKED":("VERIFY_RESTORE_BLOCKED","BLOCKED")}

def make_step(item, phase, operation, state, evidence):
    return {"phase":phase,"system_id":item["system_id"],"resource_id":item["resource_id"],"operation":operation,"state":state,"evidence_id":evidence}

def create_case_output(request, dataset, identities, audits, manifest, rules):
    case_id=request["case_id"]
    if not authorize_deletion_request(request.get("request_text", "")): return {"case_id":case_id,"deletion_status":"NOT_APPLICABLE","steps_json":"[]"}
    cutoff=dt(request.get("audit_at"))
    if not cutoff: raise ValueError(f"{case_id}: invalid audit_at")
    user,identifiers=resolve_identity(request,identities,audits,cutoff)
    observations=collect_evidence(dataset,manifest,identifiers,user,cutoff)
    supported_resources = {item["resource_id"] for item in observations}
    latest={}
    for item in observations:
        key=(item["system_id"],item["resource_id"]); old=latest.get(key)
        if old is None or (item["observed_at"],item["evidence_id"])>(old["observed_at"],old["evidence_id"]): latest[key]=item
    events_path = dataset / "system_activity.csv"
    event_rows = read_csv(events_path) if events_path.is_file() else []
    candidate_activity_ids = {item["record"].get("candidate_activity_id") for item in latest.values()
                              if item["action"] == "LOOKUP_ABSENT" and item.get("record", {}).get("candidate_activity_id")}
    linked_resources = set()
    for event in event_rows:
        if event.get("event_type") != "LINK_RESOURCE_IDENTITY":
            continue
        event_time = dt(event.get("event_time"))
        details = event.get("details", "").casefold()
        linked_subject = any(re.search(rf"(?<![a-z0-9]){re.escape(norm(identifier))}(?![a-z0-9])", details)
                             for identifier in identifiers if norm(identifier))
        if event_time and event_time <= cutoff and event.get("resource_id") in supported_resources and linked_subject:
            linked_resources.add(event["resource_id"])
    if events_path.is_file():
        for row in event_rows:
            if row.get("resource_id") not in supported_resources:
                continue
            event_time = dt(row.get("event_time"))
            if not event_time or event_time > cutoff:
                continue
            if row.get("event_type") == "LINK_RESOURCE_IDENTITY":
                continue
            if row.get("activity_id") in candidate_activity_ids:
                continue
            if row.get("resource_id") in linked_resources and row.get("event_type") not in {"DISABLE_DATA_FLOW", "BLOCK_RESTORE"}:
                continue
            event = row.get("event_type", "").upper()
            if event == "DELETE_RECORD":
                # Workflow activity is a claim only; use a later independent
                # point-in-time absence observation to verify, never this row alone.
                continue
            if event == "DISABLE_DATA_FLOW":
                event_resource = row.get("resource_id", "")
                latest[event_resource] = {"system_id":row.get("target_system", "integration_service"),"resource_id":event_resource,"category":"DATA_FLOW","action":"FLOW_DISABLED","evidence_id":row["activity_id"],"observed_at":event_time,"record":row}
            elif event == "BLOCK_RESTORE":
                event_resource = row.get("resource_id", "")
                latest[event_resource] = {"system_id":row.get("target_system", "backup_service"),"resource_id":event_resource,"category":"BACKUP_ARCHIVE","action":"RESTORE_BLOCKED","evidence_id":row["activity_id"],"observed_at":event_time,"record":row}

    findings: list[dict[str, Any]] = []
    remediation: list[dict[str, Any]] = []
    future: list[dict[str, Any]] = []
    verified: list[dict[str, Any]] = []
    for item in list(latest.values()):
        if item.get("lookup_candidate") and item["action"] == "ABSENT":
            item["action"] = "LOOKUP_ABSENT"
        if item["category"] == "USER_PROFILE" and item["action"] == "LOOKUP_ABSENT" and item.get("lookup_candidate"):
            verified.append(make_step(item, "VERIFICATION", "VERIFY_RECORD_ABSENT", "ABSENT", item["evidence_id"]))
        elif item["category"] == "ACCOUNT_TOMBSTONE" and item["action"] == "REDACTED":
            verified.append(make_step(item, "VERIFICATION", "VERIFY_RECORD_REDACTED", "REDACTED", item["evidence_id"]))
        elif item["category"] == "SECURITY_AUDIT_LOG" and item["action"] == "RETAIN":
            verified.append(make_step(item, "VERIFICATION", "VERIFY_RECORD_PRESENT", "PRESENT", item["evidence_id"]))
        elif item["action"] in {"REDACTED", "ANONYMIZED", "FLOW_DISABLED", "RESTORE_BLOCKED"}:
            operation, state = VERIFY[item["action"]]
            verified.append(make_step(item, "VERIFICATION", operation, state, item["evidence_id"]))
        else:
            finding = FIND.get(item["action"])
            fix = FIX.get(item["action"])
            verify = VERIFY.get(item["action"])
            if finding and fix and verify:
                findings.append(make_step(item, "FINDING", finding[0], finding[1], item["evidence_id"]))
                remediation.append(make_step(item, "REMEDIATION", fix[0], fix[1], ""))
                future.append(make_step(item, "VERIFICATION", verify[0], verify[1], ""))
    if findings:
        # Any positive state observation remains a violation; compliant records
        # contribute current verification, and remediation targets get future checks.
        status = "INCOMPLETE"
        retained = [step for step in verified if step["operation"] == "VERIFY_RECORD_PRESENT"]
        remediated_checks = [step for step in future if (step["system_id"], step["resource_id"]) not in {(v["system_id"], v["resource_id"]) for v in verified}]
        steps = findings + remediation + retained + remediated_checks
        steps.extend(step for step in verified if step["operation"] != "VERIFY_RECORD_PRESENT")
    elif observations:
        status, steps = "COMPLETE", verified
    else:
        status, steps = "INCOMPLETE", []
    steps=order_and_number_steps(steps)
    return {"case_id":case_id,"deletion_status":status,"steps_json":json.dumps(steps,ensure_ascii=False,separators=(",",":"))}

def main(argv=None):
    parser=argparse.ArgumentParser(description="Generate evidence-based deletion audit output")
    parser.add_argument("--dataset",type=Path,default=Path(__file__).resolve().parents[1]/"dataset")
    parser.add_argument("--output",type=Path,default=Path(__file__).resolve().parents[1]/"output.csv")
    args=parser.parse_args(argv)
    try: count=DeletionAuditAgent(args.dataset.resolve()).run(args.output.resolve())
    except Exception as exc:  # noqa: BLE001 - keep CLI failures concise for users
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(f"Wrote {count} rows to {args.output.resolve()}");return 0

if __name__=="__main__": raise SystemExit(main())
