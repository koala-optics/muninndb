#!/usr/bin/env python3
"""Create and validate a private, non-executing Stage B readiness packet.

This module is intentionally local-only. It does not inspect the environment,
contact Fly, launch child processes, collect evidence, authorize a change, or
mutate a production resource.
"""
from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

SCHEMA_VERSION = "koala-stage-b-packet-v1"
NOT_READY = "NOT_READY"
READY = "READY_FOR_AUTHORIZATION"
NOT_AUTHORIZED = "NOT_AUTHORIZED"
PUBLIC_CHANGE_LABEL = "MuninnDB RC2 Stage B readiness"
PUBLIC_WINDOW_LABEL = "SCHEDULED"
MAX_PACKET_BYTES = 1_048_576

QUALIFICATION = {
    "source_commit": "acef6bedbbd839f9616415e6a7559ad149dc8bc8",
    "source_tag": "koala-v0.9.0-rc.2",
    "candidate_image": (
        "ghcr.io/koala-optics/muninndb@sha256:"
        "5cc1546b854e6b173181ceed139ade783751c1e58bea504bc57cb0a7fa4019df"
    ),
    "rollback_rescue_image": (
        "ghcr.io/koala-optics/muninndb@sha256:"
        "52cad8cce1a0dca7b6e64f5bffafe1a0c677667c49112513cc3ad463a953594b"
    ),
    "baseline_image": (
        "registry.fly.io/koala-muninndb:"
        "deployment-01KSWRX9GKW5M94MQQCBZSJZHS"
    ),
    "baseline_digest": (
        "sha256:"
        "c06842e1452f2aab4c1f01207adf9406bfe757b4984da516568006f1f5c8ad86"
    ),
    "harness_target_merge": "880b692832ea3947b95b679839161d514f0cf883",
    "stage_a_workflow_run": "30347311896",
    "stage_a_receipt_sha256": (
        "dffdfbf015a4b17ef073bb09fb8568fe4333c31ec4b4e713c18ba6f029c0f2ed"
    ),
    "stage_a_cleanup_sha256": (
        "46ac8f52022679f2bbcf74687a3d6b21bd79ff2827bc5d08a792834c3df32541"
    ),
    "accepted_records": 502_385,
    "passed_gates": 16,
}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SECRET_SUMMARY_RE = re.compile(
    r"(?i)(?:https?://|fly://|-----BEGIN|\bbearer\s+|\bflyv1\b|\bfm2_[a-z0-9_-]+|"
    r"(?:api[ _-]?key|secret|password|token)\s*[:=])"
)


def _evidence_template() -> dict[str, Any]:
    return {
        "status": "UNKNOWN",
        "sha256": None,
        "observed_at": None,
        "expires_at": None,
        "coverage": "UNKNOWN",
        "source": "NONE",
    }


def build_template() -> dict[str, Any]:
    """Return an unfilled packet carrying the immutable qualification manifest."""
    return {
        "schema_version": SCHEMA_VERSION,
        "readiness_status": NOT_READY,
        "qualification": dict(QUALIFICATION),
        "public_summary": {
            "change_label": PUBLIC_CHANGE_LABEL,
            "window_label": "UNSCHEDULED",
        },
        "target_binding": {
            "evidence": _evidence_template(),
            "target_fingerprint_sha256": None,
            "maintenance_window_start": None,
            "maintenance_window_end": None,
            "topology_complete": False,
            "baseline_identity_matches": False,
            "machine_config_recorded": False,
            "no_unknown_resources": False,
        },
        "preflight": {
            "evidence": _evidence_template(),
            "credential_presence_recorded": False,
            "endpoint_presence_recorded": False,
            "region_guest_recorded": False,
            "restart_policy_recorded": False,
            "services_health_recorded": False,
            "mount_volume_recorded": False,
            "disk_headroom_verified": False,
            "muninn_status_counts_verified": False,
            "writer_ingress_inventory_complete": False,
            "rollback_capacity_verified": False,
        },
        "writer_control": {
            "evidence": _evidence_template(),
            "writer_inventory_complete": False,
            "freeze_tested": False,
            "queue_tested": False,
            "replay_tested": False,
            "write_boundary_proved": False,
        },
        "backup_restore": {
            "evidence": _evidence_template(),
            "writers_frozen_during_checkpoint": False,
            "application_checkpoint_verified": False,
            "checkpoint_scan_verified": False,
            "auxiliary_state_inventory_complete": False,
            "required_auxiliary_state_captured": False,
            "authentication_continuity_verified": False,
            "independent_restore_query_verified": False,
            "auxiliary_restore_verified": False,
            "fly_snapshot_supplemental_only": False,
        },
        "routing_acceptance": {
            "evidence": _evidence_template(),
            "service_health_check_configured": False,
            "fresh_health_observed": False,
            "candidate_isolation_planned": False,
            "acceptance_probes_defined": False,
            "read_only_soak_minutes": 30,
            "post_write_observation_hours": 24,
        },
        "rollback": {
            "evidence": _evidence_template(),
            "original_volume_untouched_plan": False,
            "retained_machine_plan": False,
            "rescue_digest_pinned": False,
            "pre_write_lossless_rollback": False,
            "image_only_data_reversal": False,
            "post_write_freeze_first": False,
            "post_write_restore_or_replay_verified": False,
        },
        "observation": {
            "evidence": _evidence_template(),
            "hard_triggers_defined": False,
            "cleanup_plan_defined": False,
            "observed_live_required": False,
            "rollback_window_closure_defined": False,
        },
        "authorization": {
            "status": NOT_AUTHORIZED,
            "authorization_receipt_sha256": None,
        },
    }


def packet_bytes(packet: Mapping[str, Any]) -> bytes:
    """Serialize a packet deterministically without exposing its contents."""
    return (json.dumps(packet, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_template(path: Path) -> str:
    """Atomically create a mode-0600 template without replacing any path."""
    destination = path.expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() or destination.is_symlink():
        raise FileExistsError("refusing to overwrite an existing packet")

    payload = packet_bytes(build_template())
    fd, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=destination.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # Linking is the no-replace atomic publish step. The temporary inode is
        # already 0600, so avoid a path-based chmod after publication.
        try:
            os.link(temporary, destination)
        except OSError as error:
            if error.errno == errno.EEXIST:
                raise FileExistsError(
                    "refusing to overwrite an existing packet"
                ) from error
            raise
        directory_fd = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)

    return hashlib.sha256(payload).hexdigest()


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.endswith("Z"):
        return None
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _check_exact_keys(
    value: Any,
    expected: set[str],
    path: str,
    errors: list[str],
) -> Mapping[str, Any] | None:
    if not isinstance(value, dict):
        errors.append(path)
        return None
    actual = set(value)
    for key in sorted(expected - actual):
        errors.append(f"{path}.{key}")
    for key in sorted(actual - expected):
        errors.append(f"{path}.{key}")
    return value


def _check_true_fields(
    group: Mapping[str, Any],
    fields: Sequence[str],
    path: str,
    errors: list[str],
) -> None:
    for field in fields:
        if group.get(field) is not True:
            errors.append(f"{path}.{field}")


def _check_evidence(
    value: Any,
    path: str,
    now: datetime,
    errors: list[str],
) -> None:
    expected = {
        "status",
        "sha256",
        "observed_at",
        "expires_at",
        "coverage",
        "source",
    }
    evidence = _check_exact_keys(value, expected, path, errors)
    if evidence is None:
        return
    if evidence.get("status") != "PASSED":
        errors.append(f"{path}.status")
    digest = evidence.get("sha256")
    if not isinstance(digest, str) or not _SHA256_RE.fullmatch(digest):
        errors.append(f"{path}.sha256")
    observed = _parse_timestamp(evidence.get("observed_at"))
    expires = _parse_timestamp(evidence.get("expires_at"))
    if observed is None:
        errors.append(f"{path}.observed_at")
    if expires is None:
        errors.append(f"{path}.expires_at")
    if observed is not None and observed > now:
        errors.append(f"{path}.observed_at")
    if expires is not None and expires <= now:
        errors.append(f"{path}.expires_at")
    if observed is not None and expires is not None and expires <= observed:
        errors.append(f"{path}.expires_at")
    if evidence.get("coverage") != "COMPLETE":
        errors.append(f"{path}.coverage")
    if evidence.get("source") != "PRIMARY_RECEIPT":
        errors.append(f"{path}.source")


def _check_group(
    packet: Mapping[str, Any],
    name: str,
    boolean_fields: Sequence[str],
    now: datetime,
    errors: list[str],
    extra_fields: Sequence[str] = (),
) -> Mapping[str, Any] | None:
    expected = {"evidence", *boolean_fields, *extra_fields}
    group = _check_exact_keys(packet.get(name), expected, name, errors)
    if group is None:
        return None
    _check_evidence(group.get("evidence"), f"{name}.evidence", now, errors)
    _check_true_fields(group, boolean_fields, name, errors)
    return group


def validate_packet(
    packet: Any,
    *,
    now: datetime | None = None,
) -> tuple[str, list[str]]:
    """Validate readiness locally; never grant or infer authorization."""
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    errors: list[str] = []
    top_level = {
        "schema_version",
        "readiness_status",
        "qualification",
        "public_summary",
        "target_binding",
        "preflight",
        "writer_control",
        "backup_restore",
        "routing_acceptance",
        "rollback",
        "observation",
        "authorization",
    }
    root = _check_exact_keys(packet, top_level, "$", errors)
    if root is None:
        return NOT_READY, errors

    if root.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version")
    if root.get("readiness_status") != READY:
        errors.append("readiness_status")

    qualification = _check_exact_keys(
        root.get("qualification"),
        set(QUALIFICATION),
        "qualification",
        errors,
    )
    if qualification is not None:
        for key, expected in QUALIFICATION.items():
            if qualification.get(key) != expected:
                errors.append(f"qualification.{key}")

    summary = _check_exact_keys(
        root.get("public_summary"),
        {"change_label", "window_label"},
        "public_summary",
        errors,
    )
    if summary is not None:
        expected_summaries = {
            "change_label": PUBLIC_CHANGE_LABEL,
            "window_label": PUBLIC_WINDOW_LABEL,
        }
        for field, expected in expected_summaries.items():
            value = summary.get(field)
            if value != expected or (
                isinstance(value, str) and _SECRET_SUMMARY_RE.search(value)
            ):
                errors.append(f"public_summary.{field}")

    target = _check_group(
        root,
        "target_binding",
        (
            "topology_complete",
            "baseline_identity_matches",
            "machine_config_recorded",
            "no_unknown_resources",
        ),
        current,
        errors,
        (
            "target_fingerprint_sha256",
            "maintenance_window_start",
            "maintenance_window_end",
        ),
    )
    if target is not None:
        fingerprint = target.get("target_fingerprint_sha256")
        if not isinstance(fingerprint, str) or not _SHA256_RE.fullmatch(fingerprint):
            errors.append("target_binding.target_fingerprint_sha256")
        start = _parse_timestamp(target.get("maintenance_window_start"))
        end = _parse_timestamp(target.get("maintenance_window_end"))
        if start is None:
            errors.append("target_binding.maintenance_window_start")
        if end is None:
            errors.append("target_binding.maintenance_window_end")
        if start is not None and end is not None and end <= start:
            errors.append("target_binding.maintenance_window_end")
        if end is not None and end <= current:
            errors.append("target_binding.maintenance_window_end")

    _check_group(
        root,
        "preflight",
        (
            "credential_presence_recorded",
            "endpoint_presence_recorded",
            "region_guest_recorded",
            "restart_policy_recorded",
            "services_health_recorded",
            "mount_volume_recorded",
            "disk_headroom_verified",
            "muninn_status_counts_verified",
            "writer_ingress_inventory_complete",
            "rollback_capacity_verified",
        ),
        current,
        errors,
    )
    _check_group(
        root,
        "writer_control",
        (
            "writer_inventory_complete",
            "freeze_tested",
            "queue_tested",
            "replay_tested",
            "write_boundary_proved",
        ),
        current,
        errors,
    )
    _check_group(
        root,
        "backup_restore",
        (
            "writers_frozen_during_checkpoint",
            "application_checkpoint_verified",
            "checkpoint_scan_verified",
            "auxiliary_state_inventory_complete",
            "required_auxiliary_state_captured",
            "authentication_continuity_verified",
            "independent_restore_query_verified",
            "auxiliary_restore_verified",
            "fly_snapshot_supplemental_only",
        ),
        current,
        errors,
    )
    routing = _check_group(
        root,
        "routing_acceptance",
        (
            "service_health_check_configured",
            "fresh_health_observed",
            "candidate_isolation_planned",
            "acceptance_probes_defined",
        ),
        current,
        errors,
        ("read_only_soak_minutes", "post_write_observation_hours"),
    )
    if routing is not None:
        if routing.get("read_only_soak_minutes") != 30:
            errors.append("routing_acceptance.read_only_soak_minutes")
        if routing.get("post_write_observation_hours") != 24:
            errors.append("routing_acceptance.post_write_observation_hours")

    rollback = _check_group(
        root,
        "rollback",
        (
            "original_volume_untouched_plan",
            "retained_machine_plan",
            "rescue_digest_pinned",
            "pre_write_lossless_rollback",
            "post_write_freeze_first",
            "post_write_restore_or_replay_verified",
        ),
        current,
        errors,
        ("image_only_data_reversal",),
    )
    if rollback is not None and rollback.get("image_only_data_reversal") is not False:
        errors.append("rollback.image_only_data_reversal")

    _check_group(
        root,
        "observation",
        (
            "hard_triggers_defined",
            "cleanup_plan_defined",
            "observed_live_required",
            "rollback_window_closure_defined",
        ),
        current,
        errors,
    )

    authorization = _check_exact_keys(
        root.get("authorization"),
        {"status", "authorization_receipt_sha256"},
        "authorization",
        errors,
    )
    if authorization is not None:
        if authorization.get("status") != NOT_AUTHORIZED:
            errors.append("authorization.status")
        if authorization.get("authorization_receipt_sha256") is not None:
            errors.append("authorization.authorization_receipt_sha256")

    return (READY if not errors else NOT_READY), sorted(set(errors))


def validate_path(path: Path) -> tuple[str, str, list[str]]:
    """Read and validate one private packet, returning only safe metadata."""
    packet_path = path.expanduser()
    if packet_path.is_symlink():
        return NOT_READY, "0" * 64, ["packet.symlink"]
    try:
        metadata = packet_path.stat()
    except OSError:
        return NOT_READY, "0" * 64, ["packet.unreadable"]
    if not stat.S_ISREG(metadata.st_mode):
        return NOT_READY, "0" * 64, ["packet.type"]
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        mode_errors = ["packet.mode"]
    else:
        mode_errors = []
    if metadata.st_size > MAX_PACKET_BYTES:
        return NOT_READY, "0" * 64, sorted({*mode_errors, "packet.size"})

    try:
        payload = packet_path.read_bytes()
    except OSError:
        return NOT_READY, "0" * 64, sorted({*mode_errors, "packet.unreadable"})
    digest = hashlib.sha256(payload).hexdigest()
    try:
        packet = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return NOT_READY, digest, sorted({*mode_errors, "packet.json"})
    status, errors = validate_packet(packet)
    return (NOT_READY if mode_errors else status), digest, sorted({*mode_errors, *errors})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create or locally validate a non-authorizing Stage B packet."
    )
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--template", type=Path, metavar="PATH")
    actions.add_argument("--validate", type=Path, metavar="PATH")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.template is not None:
        try:
            write_template(args.template)
        except (FileExistsError, OSError):
            print("TEMPLATE_NOT_WRITTEN", file=sys.stderr)
            return 2
        print("TEMPLATE_WRITTEN")
        return 0

    status, digest, errors = validate_path(args.validate)
    if errors:
        print(f"{status} sha256={digest} errors={','.join(errors)}")
        return 1
    print(f"{status} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
