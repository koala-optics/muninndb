#!/usr/bin/env python3
"""Production-scale synthetic rehearsal for Koala's MuninnDB v0.9 candidate.

Dry-run is the default. Live execution creates only run-owned disposable Fly
resources and requires a run-specific confirmation string.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import math
from functools import lru_cache
import os
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator, Sequence

SCHEMA_VERSION = 1
CORPUS_SCHEMA_VERSION = 2
CORPUS_SHAPE_VERSION = "lean-bulk-probes-v1"
DEFAULT_RECORD_COUNT = MIN_RECORD_COUNT = 502_385
DEFAULT_BATCH_SIZE = MAX_BATCH_SIZE = 50
DEFAULT_PAYLOAD_BYTES = 4_000
DEFAULT_PAYLOAD_SHAPE = "lexical"
MIN_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES = 1_000, 32_000
CALIBRATION_SAMPLE_COUNT = 25_000
CALIBRATION_LOW_PAYLOAD_BYTES, CALIBRATION_HIGH_PAYLOAD_BYTES = MIN_PAYLOAD_BYTES, 4_000
TAIL_PROBE_SAMPLE_COUNT = 2_000
FALSIFICATION_RUN_ID = "30108034677"
FALSIFICATION_RECEIPT_SHA256 = "b89c4daf7d4b6b55d92f1754d65606b9406cfdd60156bc450ab00d5048de6d68"
ABLATION_COHORTS = (
    ("opaque-1k", "opaque", CALIBRATION_LOW_PAYLOAD_BYTES),
    ("opaque-4k", "opaque", CALIBRATION_HIGH_PAYLOAD_BYTES),
    ("lexical-1k", "lexical", CALIBRATION_LOW_PAYLOAD_BYTES),
    ("lexical-4k", "lexical", CALIBRATION_HIGH_PAYLOAD_BYTES),
)
STORAGE_QUIET_TIMEOUT_S = 20 * 60
STORAGE_QUIET_INTERVAL_S = 10.0
STORAGE_QUIET_SAMPLES = 3
STORAGE_QUIET_TOLERANCE_BYTES = 1024 * 1024
PROGRESS_BATCH_INTERVAL = 100
MAX_STORE_BYTES = 13 * 1024**3 // 2
TARGET_STORE_BYTES = 6 * 1024**3
VOLUME_SIZE_GB = 20
MAX_PEAK_BYTES, MIN_FREE_PERCENT = 14 * 1024**3, 30.0
MIGRATION_LIMIT_S, READINESS_LIMIT_S = 45 * 60, 5 * 60
EXEC_CANARY_TOKEN = "42"
PROCESS_INVENTORY_CHARS = 600
STALL_DIAGNOSTIC_LINES = 20
SAFE_DETAIL_CHARS, RECEIPT_DETAIL_CHARS = 400, 1600
TRUNCATION_MARKER = " ...[truncated]... "
# A JSON-RPC error object is server-controlled and arbitrarily large, so each of its three
# fields is capped independently before it can reach the receipt. Three fields at 200 leaves
# the composed detail well inside RECEIPT_DETAIL_CHARS even with the method and vault prefix,
# so a verbose server error can never crowd out the part that names the call.
JSON_RPC_DETAIL_CHARS = 200
# JSON-RPC 2.0 reserves -32000..-32099 for implementation-defined SERVER errors, which is the
# band a tool raising "engram not found" lands in. Outside that band the reserved protocol codes
# live (-32700 parse, -32600 invalid request, -32601 method not found, -32602 invalid params,
# -32603 internal). The distinction is not cosmetic: one means the server answered at tool level,
# the other means the request never reached tool semantics, and the hard-delete check's PASS
# condition depends on telling them apart.
JSON_RPC_SERVER_ERROR_MIN, JSON_RPC_SERVER_ERROR_MAX = -32099, -32000
# Mirrors the [:10] slice run_query_probes reads, so the baseline witness and the fork probe
# ask about the SAME records. If those two ever disagree the comparison is worthless, which is
# the entire value of the witness.
BASELINE_READ_WITNESS_IDS = 10
# The backup archive lives beside the store because a Fly machine mounts one volume, so
# the helper that writes it cannot also mount a separate backup volume.
BACKUP_ARCHIVE_DIR = "/data"
# Sums CPU percent and RSS KiB over MuninnDB processes. Reads /proc/uptime as the first
# input file so no command substitution is needed for uptime. Deliberately contains no
# quote character of either kind and no backslash: single quotes delimit it for /bin/sh,
# double quotes would terminate the shell_command wrapper's own quoting, and a backslash
# does not survive the transport (see shell_command). The parenthesis literals are written
# as bracket expressions for that last reason: /[(].*[)]/ needs no escape and is exactly
# equivalent to /\(.*\)/ under mawk, gawk, and busybox awk alike.
PROCFS_RESOURCE_AWK = (
    "NR==1{up=$1;next} "
    "FNR==1{if(match($0,/[(].*[)]/)==0)next;"
    "comm=substr($0,RSTART+1,RLENGTH-2);"
    "n=split(substr($0,RSTART+RLENGTH+1),f);if(n<22)next;"
    "if(comm ~ /muninndb/){el=up-(f[20]/hz);"
    "if(el>0)cpu+=100*((f[12]+f[13])/hz)/el;rss+=f[22]*pg/1024}} "
    "END{print cpu+0,int(rss)}"
)
QUERY_P95_LIMIT_MS, STATUS_LIMIT_S = 250.0, 30.0
# The gated figure is the fuzzy p95 NET of the tunnel, not the raw client-observed p95.
# Every measured query crosses a `flyctl proxy` WireGuard tunnel from the GitHub runner to
# the ewr guest, so a raw reading is WAN round-trip PLUS server time. Across runs 13-16, on
# an identical 502,385-record corpus and identical performance-16x guests, the
# transport-dominated `exact` p50 swung 3.83x (43.581 -> 167.165 ms) while fuzzy's marginal
# cost over that floor held within 1.35x (77.7 -> 105.0 ms). A guest starved by factor k
# scales both terms by k, so the term that varies is additive and per-request: the tunnel,
# not MuninnDB. Run 16 failed at a raw 257.278 and would have passed on run 15's tunnel
# (43.6 + 90.1 = 133.7); run 15 passed at 121.256 and would have nearly failed on run 16's
# (167.2 + 77.7 = 244.9). The raw gate was grading runner placement.
# The net limit is 150.0 against four observed net readings - 117.5 / 82.5 / 77.8 / 90.1
# under the min-baseline below - i.e. about 28% headroom over the worst. Four points is a
# THIN basis and is disclosed as a receipt limitation. This is a bound chosen above the
# observed spread, not a constant fitted to make run 16 pass: it is STRICTER than the old
# gate on a fast tunnel (250 raw on run 15's floor permitted a net 206.4) and looser on a
# slow one (run 16's floor permitted only 82.8). Removing that dependence is the point.
QUERY_NET_P95_LIMIT_MS = 150.0
# Every entity and group name that exists on a primary-vault probe record, with its match
# count, derived from record_for rather than assumed: Entity 00 (2), 01 (2), 07 (1),
# 42 (503), 43 (1), Group 0 (504), 1 (4), 2 (1). An absent name would return nothing and
# contribute an unrepresentatively fast sample, so the set is exactly the non-empty ones.
FUZZY_CONTEXTS = (("Stage A Entity 00",), ("Stage A Entity 01",), ("Stage A Entity 07",),
                  ("Stage A Entity 42",), ("Stage A Entity 43",), ("Stage A Group 0",),
                  ("Stage A Group 1",), ("Stage A Group 2",))
FUZZY_PASSES = 3
RESTORE_LIMIT_S, ROLLBACK_LIMIT_S = 45 * 60, 30 * 60
# A cold store's DATA queries are what exceed a 60-second socket timeout. Its metadata calls
# do not, and #72 mistook one for the other.
#
# #72 reasoned that a store on a freshly created volume answers its FIRST query slowly, and
# waited on `muninn_status`. Run 30270851093 falsified that outright: restore_first_query_s
# came back at 0.077s and rollback_first_query_s at 0.159s. `muninn_status` is a metadata
# call that never faults a data block in, so waiting on it warmed nothing. Worse, it is
# EXACTLY the call query_count issues (see query_count below), so #72's wait warmed the one
# call that was already fast and left the expensive surface immediately after it untouched.
# It re-proved what initialize() and wait_ready already establish - the server is up - and
# bought no coverage at all.
#
# What that run did buy is a pinned historical failure window. rollback_first_query_s was
# recorded and rollback_counts was not, and query_counts provably issues the muninn_status
# that had just answered in 0.159s, so the old snapshot-fork path timed out inside
# run_query_probes: find_by_concept, find_by_entity, read, or the 24-sample fuzzy sweep.
# Those touch indexes and data blocks. The corrected topology no longer uses that fork for
# operational rollback: archive restore rebuilds candidate data on a clone, while rollback
# remounts the untouched original volume with the qualified rollback-rescue reader.
#
# The budget below covers a DATA query after each fresh machine launch and is applied per
# probe rather than only to a single warm-up call - warming one concept lookup cannot warm
# the entity index, the read path, or the fuzzy path, and guessing which one faults first is
# how #72 went wrong. This stays a WAIT, not a gate: RESTORE_LIMIT_S and ROLLBACK_LIMIT_S are
# unchanged and still judge their phases, so the per-probe budget can never let a phase run
# past the limit that governs it. The measurements now distinguish separately qualified
# disaster recovery from retained-original operational rollback.
COLD_QUERY_LIMIT_S, COLD_QUERY_POLL_INTERVAL_S = 15 * 60, 5.0
SNAPSHOT_LIMIT_S, SNAPSHOT_POLL_INTERVAL_S = 10 * 60, 5.0
VOLUME_READY_LIMIT_S, VOLUME_READY_POLL_INTERVAL_S = 15 * 60, 5.0
VOLUME_READY_STATE, VOLUME_HYDRATING_STATES = "created", {"restoring", "pending", "creating"}
HELPER_POLL_INTERVAL_S, HELPER_STATUS_RETRIES = 5.0, 5
DESTROY_ATTEMPTS, DESTROY_RETRY_DELAY_S = 3, 5.0
FLY_REGION, FLY_ORG, MCP_PORT = "ewr", "personal", 8750
BASELINE_IMAGE = "registry.fly.io/koala-muninndb:deployment-01KSWRX9GKW5M94MQQCBZSJZHS"
BASELINE_DIGEST = "sha256:c06842e1452f2aab4c1f01207adf9406bfe757b4984da516568006f1f5c8ad86"
CANDIDATE_IMAGE = "ghcr.io/koala-optics/muninndb@sha256:5cc1546b854e6b173181ceed139ade783751c1e58bea504bc57cb0a7fa4019df"
CANDIDATE_DIGEST = CANDIDATE_IMAGE.split("@", 1)[1]
ROLLBACK_RESCUE_IMAGE = "ghcr.io/koala-optics/muninndb@sha256:52cad8cce1a0dca7b6e64f5bffafe1a0c677667c49112513cc3ad463a953594b"
ROLLBACK_RESCUE_DIGEST = ROLLBACK_RESCUE_IMAGE.split("@", 1)[1]
ROLLBACK_RESCUE_SOURCE_COMMIT = "be975fb1215e75208adf4b340ba95e21415f04cb"
ROLLBACK_RESCUE_PATCH_COMMIT = "e486c731dfb9c20c3429022729fede7de2e052e7"
ROLLBACK_RESCUE_PROVENANCE_SHA256 = "7285d32b1082091547ce74397df63e3048b41d06a2607346927e7dec7012e251"
ROLLBACK_RESCUE_BUILD_RUN_ID = 30329362902
FLY_REGISTRY = "registry.fly.io"
CANDIDATE_MIRROR_TAG, ROLLBACK_RESCUE_MIRROR_TAG = "stage-a-candidate", "stage-a-rollback-rescue"
SOURCE_COMMIT, SOURCE_TAG = "acef6bedbbd839f9616415e6a7559ad149dc8bc8", "koala-v0.9.0-rc.2"
PRODUCTION_APP = "koala-muninndb"
PRODUCTION_MACHINE_IDS = frozenset({"6e8262d6c6d298"})
PRODUCTION_VOLUME_IDS = frozenset({"vol_vgn3o017zm3gkgz4"})
COLLISION_CONCEPTS = ("stage-a/collision/1162789", "stage-a/collision/1379192")
DIGEST_REF = re.compile(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}")
MIRROR_REF = re.compile(rf"{re.escape(FLY_REGISTRY)}/koala-stage-a-[a-z0-9-]{{4,32}}:{re.escape(CANDIDATE_MIRROR_TAG)}")
ROLLBACK_RESCUE_MIRROR_REF = re.compile(rf"{re.escape(FLY_REGISTRY)}/koala-stage-a-[a-z0-9-]{{4,32}}:{re.escape(ROLLBACK_RESCUE_MIRROR_TAG)}")
RUN_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{3,31}")
FLY_VOLUME_NAME_RE = re.compile(r"[a-z0-9_]{1,30}")
SENSITIVE_TEXT = re.compile(r"https?://|(?i:authorization|bearer|password|secret|token|x-amz-|fly_api)")
RECEIPT_KEYS = frozenset({"schema_version", "status", "exit_code", "run_id", "source", "images", "corpus", "resources", "measurements", "gates", "cleanup", "orphans", "detail", "limitations"})

class RehearsalError(RuntimeError): status = "UNKNOWN"
class RehearsalFailed(RehearsalError): status = "FAILED"
class RehearsalUnknown(RehearsalError): pass

class RehearsalProtocolFailed(RehearsalFailed):
    """A JSON-RPC PROTOCOL error came back, so the request never reached tool semantics.

    Separated from RehearsalFailed because the two mean opposite things to a caller that
    EXPECTS a failure. The hard-delete check reads a purged record and treats any
    RehearsalFailed as proof the record is gone; a protocol error there is not evidence of
    deletion, it is evidence the question was never answered. Still FAILED, not UNKNOWN: the
    server responded, and a response saying no is a result.

    Raised only for codes OUTSIDE the -32000..-32099 server band. #74 raised this class for
    every error object regardless of code, which is what broke runs 30290534176 and
    30302595011 - see RehearsalToolFailed.
    """

class RehearsalToolFailed(RehearsalFailed):
    """The server answered, at tool level, with an implementation-defined error.

    A SIBLING of RehearsalProtocolFailed rather than a subclass, and that is the whole
    mechanism: the hard-delete check already reads `except RehearsalProtocolFailed: raise`
    followed by `except RehearsalFailed: pass`, so a tool error falls to the second clause and
    counts as proof the record is gone, while a protocol fault still re-raises. No new branch
    at the call site; the classification moves into _post where the code is actually visible.

    Why this exists: #74 collapsed the distinction, raising RehearsalProtocolFailed for ANY
    error object. Runs 30290534176 and 30302595011 then died at the hard-delete check on
    `code=-32000 message=tool error: engram not found` - the server correctly reporting the
    record was purged, which is that check's PASS condition, re-raised as fatal. Both runs
    stopped three gates short of the rollback phase they were dispatched to measure, and the
    identical detail was misread as a rollback failure because the ABSENT gates were not read.

    Everywhere else this is an ordinary RehearsalFailed: still FAILED, still never retried by
    `call`, still carrying the server's own code and message into the receipt.
    """

@dataclass(frozen=True)
class RunIdentity:
    run_id: str
    app_name: str
    volume_name: str
    candidate_volume_name: str
    backup_volume_name: str
    restore_volume_name: str
    rollback_volume_name: str
    confirmation: str

@dataclass(frozen=True)
class CorpusSpec:
    count: int = DEFAULT_RECORD_COUNT
    batch_size: int = DEFAULT_BATCH_SIZE
    payload_bytes: int = DEFAULT_PAYLOAD_BYTES
    seed: str = "koala-stage-a-v1"
    payload_shape: str = "opaque"

@dataclass
class CorpusReceipt:
    submitted: int = 0
    accepted: int = 0
    batches: int = 0
    manifest_sha256: str = ""
    retained_ids: dict[str, list[str]] = field(default_factory=dict)
    batch_latencies_ms: list[float] = field(default_factory=list)

@dataclass(frozen=True)
class IngestProgress:
    submitted: int
    accepted: int
    batches: int
    elapsed_s: float
    batch_latency: dict[str, float | int | None]

@dataclass(frozen=True)
class DiskSample:
    phase: str
    used_bytes: int
    available_bytes: int
    total_bytes: int
    @property
    def free_percent(self) -> float:
        return 100.0 * self.available_bytes / self.total_bytes if self.total_bytes else 0.0

@dataclass(frozen=True)
class ResourceSample:
    phase: str
    cpu_percent: float
    rss_bytes: int

@dataclass(frozen=True)
class Gate:
    status: str
    detail: str
    measured: float | int | None = None
    limit: float | int | None = None

@dataclass
class ResourceLedger:
    app: str | None = None
    volume_id: str | None = None
    candidate_volume_id: str | None = None
    backup_volume_id: str | None = None
    restore_volume_id: str | None = None
    rollback_volume_id: str | None = None
    retained_machine_id: str | None = None
    machine_id: str | None = None
    snapshot_id: str | None = None

def build_identity(run_id: str) -> RunIdentity:
    if not RUN_ID_RE.fullmatch(run_id):
        raise RehearsalUnknown("invalid run ID")
    digest = hashlib.sha256(f"koala-stage-a:{run_id}".encode()).hexdigest()[:10]
    app_name = f"koala-stage-a-{run_id}"
    volume_prefix = f"ksa_{digest}"
    identity = RunIdentity(
        run_id,
        app_name,
        f"{volume_prefix}_src",
        f"{volume_prefix}_can",
        f"{volume_prefix}_bak",
        f"{volume_prefix}_rst",
        f"{volume_prefix}_rbk",
        f"STAGE-A-{run_id}-{digest}",
    )
    assert_not_production(identity)
    return identity

def assert_not_production(identity: RunIdentity) -> None:
    volumes = (identity.volume_name, identity.candidate_volume_name, identity.backup_volume_name,
               identity.restore_volume_name, identity.rollback_volume_name)
    if identity.app_name == PRODUCTION_APP or not identity.app_name.startswith("koala-stage-a-"):
        raise RehearsalUnknown("refusing production or non-Stage-A app name")
    if len(set(volumes)) != len(volumes) or any(
        name in PRODUCTION_VOLUME_IDS or not FLY_VOLUME_NAME_RE.fullmatch(name)
        for name in volumes
    ):
        raise RehearsalUnknown("refusing production or invalid Stage-A volume name")

def assert_owned(value: str, identity: RunIdentity, kind: str) -> None:
    if value in PRODUCTION_MACHINE_IDS or value in PRODUCTION_VOLUME_IDS or value == PRODUCTION_APP:
        raise RehearsalUnknown(f"refusing preserved production {kind}")
    names = {
        "app-name": {identity.app_name},
        "volume-name": {
            identity.volume_name,
            identity.candidate_volume_name,
            identity.backup_volume_name,
            identity.restore_volume_name,
            identity.rollback_volume_name,
        },
    }
    if kind in names and value not in names[kind]:
        raise RehearsalUnknown(f"refusing unowned {kind}")

def validate_image(
    ref: str,
    role: str,
    *,
    expected_candidate: str = CANDIDATE_IMAGE,
    expected_rollback_rescue: str = ROLLBACK_RESCUE_IMAGE,
) -> str:
    """Refuse any image reference that is not the exact expected identity for its role.

    Exact string equality against the expected reference is the binding check. The candidate
    and rollback-rescue roles each accept their digest-pinned source identity or only their
    own run-owned Fly mirror tag. Fly's machine-create API rejects a digest-pinned
    config.image with "invalid image identifier", so launch references are tags; each tag's
    digest is asserted separately before any machine launch.
    """
    if role == "baseline":
        expected, accepted_shape = BASELINE_IMAGE, ref == BASELINE_IMAGE
    elif role == "candidate":
        expected = expected_candidate
        accepted_shape = bool(DIGEST_REF.fullmatch(ref) or MIRROR_REF.fullmatch(ref))
    elif role == "rollback-rescue":
        expected = expected_rollback_rescue
        accepted_shape = bool(DIGEST_REF.fullmatch(ref) or ROLLBACK_RESCUE_MIRROR_REF.fullmatch(ref))
    else:
        raise RehearsalUnknown(f"unknown image role: {role}")
    if ref != expected or not accepted_shape:
        raise RehearsalUnknown(f"{role} image differs from qualified immutable identity")
    return ref

def validate_spec(spec: CorpusSpec, *, minimum_count: int = MIN_RECORD_COUNT) -> None:
    if spec.count < minimum_count: raise RehearsalUnknown("record count below required scale")
    if not 1 <= spec.batch_size <= MAX_BATCH_SIZE: raise RehearsalUnknown("invalid batch size")
    if not MIN_PAYLOAD_BYTES <= spec.payload_bytes <= MAX_PAYLOAD_BYTES: raise RehearsalUnknown("invalid payload calibration")
    if not spec.seed or len(spec.seed) > 128: raise RehearsalUnknown("invalid synthetic seed")
    if spec.payload_shape not in {"opaque", "lexical"}: raise RehearsalUnknown("invalid payload shape")

def validate_calibration_spec(spec: CorpusSpec) -> None:
    if spec.count != CALIBRATION_SAMPLE_COUNT or spec.payload_bytes != CALIBRATION_LOW_PAYLOAD_BYTES:
        raise RehearsalUnknown("calibration corpus differs from fixed pilot contract")
    validate_spec(spec, minimum_count=CALIBRATION_SAMPLE_COUNT)


def validate_execute_spec(spec: CorpusSpec) -> None:
    validate_spec(spec)
    if spec.payload_shape != DEFAULT_PAYLOAD_SHAPE or spec.payload_bytes != DEFAULT_PAYLOAD_BYTES:
        raise RehearsalUnknown("execute corpus differs from qualified lexical contract")

def validate_tail_probe_spec(spec: CorpusSpec) -> None:
    """Pin the probe corpus, exactly as calibration pins its own.

    The probe shrinks the record COUNT and nothing else: payload shape and size stay on
    the qualified lexical contract, so the semantic probes, the migration, the archive and
    the restore command all run against the real record shape. Only the ingest gets short.
    `validate_execute_spec` is deliberately untouched - a real run still requires the full
    502,385, and a probe corpus can never reach it because the count is pinned here.
    """
    if spec.count != TAIL_PROBE_SAMPLE_COUNT:
        raise RehearsalUnknown("tail-probe corpus differs from fixed probe contract")
    if spec.payload_shape != DEFAULT_PAYLOAD_SHAPE or spec.payload_bytes != DEFAULT_PAYLOAD_BYTES:
        raise RehearsalUnknown("tail-probe corpus differs from qualified lexical contract")
    validate_spec(spec, minimum_count=TAIL_PROBE_SAMPLE_COUNT)

def fnv1a_32(value: str) -> int:
    result = 2166136261
    for byte in value.encode():
        result = ((result ^ byte) * 16777619) & 0xFFFFFFFF
    return result

def deterministic_payload(seed: str, index: int, length: int) -> str:
    raw = hashlib.shake_256(f"{seed}:{index}".encode()).digest(math.ceil(length * 3 / 4))
    return base64.b64encode(raw).decode()[:length]

def lexical_payload(seed: str, index: int, length: int) -> str:
    vocabulary = (
        "synthetic amber beacon calm delta ember field gentle harbor ivory "
        "jasmine kind lantern meadow north olive plain quiet river silver "
        "timber umber valley willow xenon yellow zenith"
    ).split()
    digest = hashlib.shake_256(f"lexical:{seed}:{index}".encode()).digest(32)
    words = ["synthetic", f"record{index}", f"hash{digest.hex()[:12]}"]
    cursor = 0
    while len(" ".join(words)) < length:
        words.append(vocabulary[digest[cursor % len(digest)] % len(vocabulary)])
        cursor += 1
    return " ".join(words)[:length]

def payload_for(shape: str, seed: str, index: int, length: int) -> str:
    if shape == "opaque":
        return deterministic_payload(seed, index, length)
    if shape == "lexical":
        return lexical_payload(seed, index, length)
    raise RehearsalUnknown("invalid payload shape")

def probe_kind(index: int) -> str | None:
    if index < 2: return "collision"
    if index == 43: return "hard-delete"
    if index in (97, 194, 291, 388, 485, 582, 679, 776, 873, 970): return "isolation"
    if index % 1000 == 42: return "ordering"
    if index in (50, 51, 57): return "fuzzy"
    return None

def record_for(spec: CorpusSpec, index: int) -> dict[str, Any]:
    cohort, seconds, kind = index % 1000, index % 2_419_200, probe_kind(index)
    vault = "stage-a-isolation" if kind == "isolation" else "stage-a-primary"
    concept = COLLISION_CONCEPTS[index] if kind == "collision" else f"stage-a/concept/{cohort:04d}"
    if kind == "isolation": concept = f"stage-a/isolation/{index:07d}"
    content = json.dumps({"schema": CORPUS_SCHEMA_VERSION, "synthetic": True, "index": index, "payload": payload_for(spec.payload_shape, spec.seed, index, spec.payload_bytes)}, sort_keys=True, separators=(",", ":"))
    memory: dict[str, Any] = {
        "concept": concept, "content": content,
        "created_at": f"2025-01-{1 + seconds // 86400:02d}T{seconds // 3600 % 24:02d}:{seconds // 60 % 60:02d}:{seconds % 60:02d}Z",
        "confidence": 1.0,
    }
    if kind:
        memory.update({
            "summary": f"Synthetic Stage A probe {index}",
            "tags": ["koala-stage-a", "synthetic-only", f"probe-{kind}"],
            "entities": [{"name": f"Stage A Entity {cohort % 50:02d}", "type": "synthetic"}, {"name": f"Stage A Group {cohort % 7}", "type": "group"}],
        })
    return {"vault": vault, "key": f"record-{index:07d}", "probe_kind": kind, "memory": memory}

@lru_cache(maxsize=4)
def shape_counts(count: int) -> dict[str, int]:
    probes = sum(probe_kind(index) is not None for index in range(count))
    return {"shape_version": CORPUS_SHAPE_VERSION, "bulk_records": count - probes, "probe_records": probes}

def iter_records(spec: CorpusSpec, *, minimum_count: int = MIN_RECORD_COUNT) -> Iterator[dict[str, Any]]:
    validate_spec(spec, minimum_count=minimum_count)
    for index in range(spec.count): yield record_for(spec, index)

def iter_batches(items: Iterable[dict[str, Any]], size: int) -> Iterator[list[dict[str, Any]]]:
    if not 1 <= size <= MAX_BATCH_SIZE: raise RehearsalUnknown("invalid batch size")
    batch: list[dict[str, Any]] = []
    for item in items:
        batch.append(item)
        if len(batch) == size: yield batch; batch = []
    if batch: yield batch

def canonical_record(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode()

def decode_batch_result(result: Any, expected: int) -> list[str]:
    if not isinstance(result, dict) or result.get("total") != expected or not isinstance(result.get("results"), list):
        raise RehearsalFailed("invalid batch result envelope")
    ids = []
    for index, item in enumerate(result["results"]):
        if not isinstance(item, dict) or item.get("index") != index or item.get("status") != "ok" or not item.get("id"):
            raise RehearsalFailed(f"batch item {index} failed")
        ids.append(str(item["id"]))
    if len(ids) != expected: raise RehearsalFailed("batch result count mismatch")
    return ids

def ingest_corpus(
    client: Any,
    spec: CorpusSpec,
    *,
    minimum_count: int = MIN_RECORD_COUNT,
    progress: Callable[[IngestProgress], None] | None = None,
    progress_interval: int = PROGRESS_BATCH_INTERVAL,
) -> CorpusReceipt:
    if progress_interval < 1: raise RehearsalUnknown("invalid progress interval")
    receipt, digest, started = CorpusReceipt(), hashlib.sha256(), time.monotonic()
    retained = {"collision": [], "ordering": [], "isolation": [], "hard_delete": []}
    for batch in iter_batches(iter_records(spec, minimum_count=minimum_count), spec.batch_size):
        groups: dict[str, list[dict[str, Any]]] = {}
        for record in batch:
            digest.update(canonical_record(record)); groups.setdefault(record["vault"], []).append(record)
        for vault, records in groups.items():
            result, latency = client.call("muninn_remember_batch", {"vault": vault, "memories": [r["memory"] for r in records]})
            ids = decode_batch_result(result, len(records)); receipt.batch_latencies_ms.append(latency)
            receipt.batches += 1; receipt.submitted += len(records); receipt.accepted += len(ids)
            for record, memory_id in zip(records, ids):
                index = int(record["key"].split("-")[-1])
                if index < 2: retained["collision"].append(memory_id)
                if index % 1000 == 42:
                    retained["ordering"].append(memory_id); retained["ordering"] = retained["ordering"][-50:]
                if record["vault"] == "stage-a-isolation" and len(retained["isolation"]) < 10: retained["isolation"].append(memory_id)
                if index == 43: retained["hard_delete"].append(memory_id)
            if progress and receipt.batches % progress_interval == 0:
                progress(IngestProgress(
                    receipt.submitted, receipt.accepted, receipt.batches,
                    time.monotonic() - started, latency_summary(receipt.batch_latencies_ms),
                ))
    if receipt.accepted != spec.count: raise RehearsalFailed("accepted count mismatch")
    receipt.manifest_sha256, receipt.retained_ids = digest.hexdigest(), retained
    return receipt

def percentile(values: Sequence[float], percent: float) -> float | None:
    if not values: return None
    ordered = sorted(values); position = (len(ordered) - 1) * percent
    lower, upper = math.floor(position), math.ceil(position)
    return float(ordered[lower]) if lower == upper else ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)

def latency_summary(values: Sequence[float]) -> dict[str, float | int | None]:
    return {"count": len(values), "p50_ms": round(percentile(values, .5), 3) if values else None,
            "p95_ms": round(percentile(values, .95), 3) if values else None,
            "max_ms": round(max(values), 3) if values else None}

def transport_baseline_ms(summaries: dict[str, Any]) -> float | None:
    """The tunnel's per-request floor, read off the cheapest query classes.

    `exact` (a concept lookup matching 1-2 records) and `read` (a direct id fetch) do almost
    no server work, and their p50s track each other within 0.4% on runs 14, 15 and 16 (11%
    on run 13) - which is what a transport-dominated reading looks like. Taking the min
    subtracts the least, so the resulting net figure stays on the strict side.
    """
    values = [summaries[name]["p50_ms"] for name in ("exact", "read")
              if summaries.get(name, {}).get("count") and summaries[name].get("p50_ms") is not None]
    return min(values) if values else None

def threshold_gate(name: str, measured: float | int | None, limit: float | int) -> Gate:
    if measured is None: return Gate("UNKNOWN", f"{name} not measured", measured, limit)
    passed = measured <= limit
    return Gate("PASSED" if passed else "FAILED", f"{name} {'passed' if passed else 'exceeded threshold'}", measured, limit)

def disk_gate(samples: Sequence[DiskSample]) -> Gate:
    if not samples: return Gate("UNKNOWN", "no disk samples")
    peak, free = max(s.used_bytes for s in samples), min(s.free_percent for s in samples)
    passed = peak <= MAX_PEAK_BYTES and free >= MIN_FREE_PERCENT
    return Gate("PASSED" if passed else "FAILED", f"peak={peak} minimum_free_percent={free:.2f}", peak, MAX_PEAK_BYTES)

def direct_store_growth_gate(empty: DiskSample, settled: DiskSample) -> Gate:
    net_growth = settled.used_bytes - empty.used_bytes
    passed = 0 < net_growth <= MAX_STORE_BYTES
    detail = f"direct same-volume settled net growth bytes={net_growth}"
    return Gate("PASSED" if passed else "FAILED", detail, net_growth, MAX_STORE_BYTES)


def logical_vault_counts(spec: CorpusSpec) -> dict[str, int]:
    isolation = sum(probe_kind(index) == "isolation" for index in range(spec.count))
    return {"stage-a-primary": spec.count - isolation, "stage-a-isolation": isolation}


def legacy_baseline_counts(spec: CorpusSpec) -> dict[str, int]:
    logical = logical_vault_counts(spec)
    return {
        "stage-a-primary": logical["stage-a-primary"] + spec.batch_size,
        "stage-a-isolation": logical["stage-a-isolation"] + 1,
    }


def require_legacy_baseline_counts(actual: dict[str, int], spec: CorpusSpec) -> None:
    expected = legacy_baseline_counts(spec)
    if actual != expected:
        raise RehearsalFailed(f"baseline vault counts differ from exact legacy fingerprint: expected={expected} actual={actual}")

def require_disk_safety(sample: DiskSample) -> None:
    if sample.used_bytes > MAX_PEAK_BYTES or sample.free_percent < MIN_FREE_PERCENT:
        raise RehearsalFailed(
            f"ingestion disk safety failed: used={sample.used_bytes} free_percent={sample.free_percent:.2f}"
        )

def calibration_projection(
    low_empty: DiskSample,
    low_populated: DiskSample,
    high_empty: DiskSample,
    high_populated: DiskSample,
    sample_count: int = CALIBRATION_SAMPLE_COUNT,
) -> dict[str, Any]:
    if sample_count != CALIBRATION_SAMPLE_COUNT:
        raise RehearsalUnknown("calibration sample count differs from fixed pilot contract")
    low_net = low_populated.used_bytes - low_empty.used_bytes
    high_net = high_populated.used_bytes - high_empty.used_bytes
    if low_net <= 0 or high_net <= 0:
        raise RehearsalUnknown("calibration store did not grow across both independent samples")
    payload_delta = CALIBRATION_HIGH_PAYLOAD_BYTES - CALIBRATION_LOW_PAYLOAD_BYTES
    low_bytes_per_record = low_net / sample_count
    high_bytes_per_record = high_net / sample_count
    bytes_per_payload_byte = (high_bytes_per_record - low_bytes_per_record) / payload_delta
    fixed_bytes_per_record = low_bytes_per_record - bytes_per_payload_byte * CALIBRATION_LOW_PAYLOAD_BYTES
    if bytes_per_payload_byte <= 0 or fixed_bytes_per_record < 0:
        raise RehearsalUnknown("calibration slope or fixed overhead invalid")
    empty_used_bytes = max(low_empty.used_bytes, high_empty.used_bytes)
    projected_minimum = empty_used_bytes + DEFAULT_RECORD_COUNT * (
        fixed_bytes_per_record + bytes_per_payload_byte * MIN_PAYLOAD_BYTES
    )
    recommended = round(
        (TARGET_STORE_BYTES - empty_used_bytes - DEFAULT_RECORD_COUNT * fixed_bytes_per_record)
        / (DEFAULT_RECORD_COUNT * bytes_per_payload_byte)
    )
    recommendation = recommended if MIN_PAYLOAD_BYTES <= recommended <= MAX_PAYLOAD_BYTES else None
    return {
        "low_empty_used_bytes": low_empty.used_bytes,
        "low_sample_used_bytes": low_populated.used_bytes,
        "low_net_growth_bytes": low_net,
        "high_empty_used_bytes": high_empty.used_bytes,
        "high_sample_used_bytes": high_populated.used_bytes,
        "high_net_growth_bytes": high_net,
        "projection_empty_used_bytes": empty_used_bytes,
        "sample_count_each": sample_count,
        "bytes_per_payload_byte": round(bytes_per_payload_byte, 6),
        "fixed_bytes_per_record": round(fixed_bytes_per_record, 3),
        "projected_minimum_bytes": round(projected_minimum),
        "recommended_payload_bytes": recommendation,
    }

def ablation_projection(samples: dict[str, tuple[int, int]]) -> dict[str, Any]:
    expected = {name for name, _, _ in ABLATION_COHORTS}
    if set(samples) != expected:
        raise RehearsalUnknown("ablation cohort evidence missing or unexpected")
    result: dict[str, Any] = {}
    for shape in ("opaque", "lexical"):
        low_empty, low_populated = samples[f"{shape}-1k"]
        high_empty, high_populated = samples[f"{shape}-4k"]
        low_net, high_net = low_populated - low_empty, high_populated - high_empty
        if low_net <= 0 or high_net <= 0:
            raise RehearsalUnknown(f"{shape} ablation store did not grow")
        low_bpr, high_bpr = low_net / CALIBRATION_SAMPLE_COUNT, high_net / CALIBRATION_SAMPLE_COUNT
        slope = (high_bpr - low_bpr) / (CALIBRATION_HIGH_PAYLOAD_BYTES - CALIBRATION_LOW_PAYLOAD_BYTES)
        fixed = low_bpr - slope * CALIBRATION_LOW_PAYLOAD_BYTES
        if slope <= 0 or fixed < 0:
            raise RehearsalUnknown(f"{shape} ablation model is invalid")
        result[shape] = {
            "low_net_growth_bytes": low_net,
            "high_net_growth_bytes": high_net,
            "bytes_per_payload_byte": round(slope, 6),
            "fixed_bytes_per_record": round(fixed, 3),
        }
    result["fixed_shape_delta_bytes_per_record"] = round(
        result["opaque"]["fixed_bytes_per_record"] - result["lexical"]["fixed_bytes_per_record"], 3,
    )
    return result

def wait_for_storage_quiet(
    runtime: Any,
    identity: RunIdentity,
    machine_id: str,
    phase: str,
    *,
    timeout_s: float = STORAGE_QUIET_TIMEOUT_S,
    interval_s: float = STORAGE_QUIET_INTERVAL_S,
    stable_samples: int = STORAGE_QUIET_SAMPLES,
    tolerance_bytes: int = STORAGE_QUIET_TOLERANCE_BYTES,
) -> dict[str, Any]:
    if timeout_s <= 0 or interval_s <= 0 or stable_samples < 2 or tolerance_bytes < 0:
        raise RehearsalUnknown("invalid storage quiet-window contract")
    started, samples, stable = time.monotonic(), [], 0
    while time.monotonic() - started <= timeout_s:
        sample = runtime.disk_sample(identity, machine_id, f"{phase}-settling")
        require_disk_safety(sample)
        if samples and abs(sample.used_bytes - samples[-1].used_bytes) <= tolerance_bytes:
            stable += 1
        else:
            stable = 0
        samples.append(sample)
        if stable >= stable_samples:
            return {"settled": sample, "samples": samples, "witness": "bounded-df-quiet-window"}
        time.sleep(interval_s)
    raise RehearsalUnknown("storage quiet-window deadline expired")

def combine_status(gates: dict[str, Gate], orphans: Sequence[str], *, probe: bool = False) -> str:
    """Reduce the gate set to one verdict, and refuse a skipped gate outside a probe.

    Only the tail probe may skip a gate, and only the four whose thresholds are functions
    of corpus size. A SKIPPED gate reaching a qualification run would otherwise read as a
    pass, which is the exact shape of weakening a gate to make a corpus fit, so it is
    forced to UNKNOWN here rather than trusted to never happen.
    """
    if any(g.status == "SKIPPED" for g in gates.values()) and not probe: return "UNKNOWN"
    if orphans or any(g.status == "UNKNOWN" for g in gates.values()): return "UNKNOWN"
    if any(g.status == "FAILED" for g in gates.values()): return "FAILED"
    return "PASSED"

def scale_gate(probe: bool, gate: Gate, name: str) -> Gate:
    """Keep a corpus-scale gate's real verdict, or record why the probe cannot judge it."""
    if not probe: return gate
    return Gate("SKIPPED", f"{name} is a function of corpus size and is not judged at probe scale")

def require_single_mount(mounts: list[dict[str, str]], role: str) -> None:
    """Refuse a machine config Fly cannot launch.

    A Fly machine takes at most one volume. Run 30202877942 reached the backup helper
    after passing every substantive gate and died on "invalid config.mounts, only 1
    volume supported", because create_backup mounted the source and backup volumes
    together and create_restore mounted the backup and restore volumes together. Both
    were structurally impossible from the day they were written; nothing before that run
    had ever reached them. Asserting here fails at config construction, in the unit
    tests, rather than after a two-hour rehearsal.
    """
    if len(mounts) > 1:
        raise RehearsalUnknown(f"{role} config requests {len(mounts)} volumes; Fly machines take one")


def shell_command(script: str) -> str:
    """Wrap a shell script so that `flyctl machine exec` actually runs it in a shell.

    `machine exec` takes ONE command string (flyctl v0.4.52 internal/command/machine/exec.go
    declares cobra.RangeArgs(1, 2) and sends fly.MachineExecRequest{Cmd: string}); the API
    word-splits that string and execs it directly. There is no shell, so pipes, globs,
    semicolons and $(...) are consumed as literal argv words rather than interpreted. That
    is why `df -Pk /data` has always worked while every measurement command has returned
    empty stdout. The offline helpers never hit this because they pass an explicit
    ["/bin/sh", "-c", command] ARRAY through init.exec.

    Wrapping in double quotes keeps the script one word through the API's split while
    leaving single quotes available to the script itself, so the script must contain no
    double quote. That constraint is asserted rather than escaped: silently mangling a
    measurement command is the failure mode this whole function exists to end.

    A backslash is refused for the same reason, and the refusal is not theoretical. Runs
    30183128792 and 30185035316 both reported "missing MuninnDB process measurement" while
    the shell canary passed, because the canary carries no backslash and the measurement
    carried \\( and \\). Feeding the arriving program back through awk locally reproduces
    the receipt exactly: with the escapes the program parses every process, and with the
    backslashes dropped /(.*)/ matches the whole line, the field split behind it yields
    nothing, and the parse count falls to zero on mawk and gawk alike. Write parenthesis
    literals as the bracket expressions [(] and [)], which need no escape at all.
    """
    if '"' in script:
        raise RehearsalUnknown("shell command must not contain a double quote")
    if "\\" in script:
        raise RehearsalUnknown("shell command must not contain a backslash; it does not survive transport")
    return f'/bin/sh -c "{script}"'

def json_rpc_detail(error: Any) -> str:
    """Render a JSON-RPC error object into a bounded, receipt-safe string.

    Run 30283211992 lost its rollback diagnosis to one discarded value. The rollback store
    returned a JSON-RPC error, the server had therefore already said exactly what was wrong,
    and the raise site threw the whole object away and wrote the constant "MCP JSON-RPC error"
    instead. The receipt named no code, no message, no method and no vault, so a 66-minute run
    produced a failure that could only be guessed at - the same shape as the bare
    "MCP transport failed: TimeoutError" that cost runs 16, 17 and 18 their diagnosis.

    `data` is included even though it is arbitrary-shaped and server-controlled. Omitting it is
    cheap to justify and expensive to be wrong about: if the cause is in there, leaving it out
    costs another full run to learn what one string would have said. It is rendered with
    json.dumps(default=str) so an unserializable payload degrades to its repr rather than
    raising inside the error path - a diagnostic helper that can itself throw would replace the
    server's error with its own.

    Each field is capped independently rather than the composed string, so a verbose message
    cannot crowd out the code and a large data blob cannot crowd out either. safe_detail still
    applies downstream; this bound exists so that what reaches it is already the informative
    part. A non-dict error is carried as its message rather than dropped, because a server that
    violates the JSON-RPC shape is itself the finding.
    """
    fields = error if isinstance(error, dict) else {"message": error}
    parts = [f"code={fields.get('code')}", f"message={str(fields.get('message', ''))[:JSON_RPC_DETAIL_CHARS]}"]
    if "data" in fields:
        parts.append(f"data={json.dumps(fields['data'], default=str)[:JSON_RPC_DETAIL_CHARS]}")
    return " ".join(parts)

def json_rpc_failure(error: Any) -> RehearsalFailed:
    """Choose the exception class by error code: did the server answer, or not?

    The single question this answers is whether a caller that EXPECTS a failure may treat this
    one as evidence. Inside -32000..-32099 the server answered at tool level, so a hard-delete
    read that comes back "engram not found" is proof the record is gone. Outside that band the
    request never reached tool semantics, so the same caller learned nothing.

    An absent, non-integer, or out-of-band code is classed PROTOCOL, not tool, because the two
    mistakes are not symmetric. Calling a protocol fault a tool error would let the hard-delete
    gate PASS on a server that never answered - the exact hazard #74 was built to close, and a
    false PASS is a qualification defect. Calling a tool error a protocol fault costs a
    dispatch, which is what runs 30290534176 and 30302595011 cost. Bounded loss over silent
    acquittal, consistent with the rest of this harness treating an error as never a valid
    empty result.
    """
    code = error.get("code") if isinstance(error, dict) else None
    detail = f"MCP JSON-RPC error {json_rpc_detail(error)}"
    if isinstance(code, int) and JSON_RPC_SERVER_ERROR_MIN <= code <= JSON_RPC_SERVER_ERROR_MAX:
        return RehearsalToolFailed(detail)
    return RehearsalProtocolFailed(detail)

def safe_detail(value: str, limit: int = SAFE_DETAIL_CHARS) -> str:
    """Compact a diagnostic to a bounded excerpt, blanking it entirely if anything matches.

    Both ends are kept. Run 30212272430 composed the flyctl error and the stalled-helper
    reading into one string, and a tail-only budget dropped the error while keeping the
    reading, so the receipt described what the helper was doing without saying what had
    failed. The error had to be recovered from an older run that predated the reading.
    The head is therefore preserved alongside the tail and the middle is dropped instead.

    The limit is a verbosity bound, not a safety one. Redaction is decided by
    SENSITIVE_TEXT over exactly the text that is returned, so nothing reaches a caller
    unchecked. A match lying wholly inside the dropped middle is not emitted either, and
    the marker between the halves keeps them from splicing into a match that neither end
    contained. Only the budget varies by caller; the predicate never does.
    """
    compact = " ".join(value.split())
    if len(compact) > limit:
        budget = max(limit - len(TRUNCATION_MARKER), 2)
        head = budget // 3
        compact = f"{compact[:head]}{TRUNCATION_MARKER}{compact[head - budget:]}"
    return "[REDACTED: sensitive diagnostic omitted]" if SENSITIVE_TEXT.search(compact) else compact

def atomic_write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, 0o600); os.replace(temporary, path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)

def write_receipt(path: Path, receipt: dict[str, Any]) -> str:
    unknown = set(receipt) - RECEIPT_KEYS
    if unknown: raise RehearsalUnknown(f"receipt has unapproved keys: {sorted(unknown)}")
    sanitized = json.loads(json.dumps(receipt))
    for key, value in list(sanitized.items()):
        # "detail" carries the cause of an UNKNOWN, which now includes the stalled-helper
        # reading, and a 400 character tail truncated that back to the last probe. It gets a
        # wider budget than the other fields, which are short by construction.
        if isinstance(value, str): sanitized[key] = safe_detail(value, RECEIPT_DETAIL_CHARS if key == "detail" else SAFE_DETAIL_CHARS)
    atomic_write_json(path, sanitized); digest = hashlib.sha256(path.read_bytes()).hexdigest()
    hash_path = path.with_suffix(path.suffix + ".sha256")
    fd, temporary = tempfile.mkstemp(prefix=f".{hash_path.name}.", dir=hash_path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(digest + "\n"); stream.flush(); os.fsync(stream.fileno())
        os.chmod(temporary, 0o600); os.replace(temporary, hash_path)
    finally:
        if os.path.exists(temporary): os.unlink(temporary)
    return digest

def corpus_evidence(spec: CorpusSpec, receipt: CorpusReceipt | IngestProgress | None) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "schema_version": CORPUS_SCHEMA_VERSION,
        "seed": spec.seed,
        "requested_count": spec.count,
        "payload_bytes": spec.payload_bytes,
        "payload_shape": spec.payload_shape,
        **shape_counts(spec.count),
    }
    if isinstance(receipt, CorpusReceipt):
        evidence.update({
            "submitted": receipt.submitted,
            "accepted": receipt.accepted,
            "batches": receipt.batches,
            "manifest_sha256": receipt.manifest_sha256,
            "batch_latency": latency_summary(receipt.batch_latencies_ms),
        })
    elif isinstance(receipt, IngestProgress):
        evidence.update({
            "submitted": receipt.submitted,
            "accepted": receipt.accepted,
            "batches": receipt.batches,
            "elapsed_s": round(receipt.elapsed_s, 3),
            "batch_latency": receipt.batch_latency,
            "complete": False,
        })
    return evidence

def receipt_document(
    identity: RunIdentity,
    spec: CorpusSpec,
    *,
    status: str,
    exit_code: int,
    detail: str,
    ledger: ResourceLedger,
    measurements: dict[str, Any],
    gates: dict[str, Gate],
    cleanup_result: dict[str, str],
    orphans: Sequence[str],
    corpus: CorpusReceipt | IngestProgress | None,
    mode: str = "execute",
    candidate_ref: str = CANDIDATE_IMAGE,
    rollback_rescue_ref: str = ROLLBACK_RESCUE_IMAGE,
) -> dict[str, Any]:
    bounded_measurements = json.loads(json.dumps(measurements))
    bounded_measurements["mode"] = mode
    limitations = [
        "Synthetic rehearsal is not production deployment authorization.",
        "Production data, backups, volumes, machines, app, and credentials are prohibited.",
    ]
    if mode in {"ablate", "execute"}:
        limitations.append(
            "The bounded df quiet-window witnesses disk settlement; it does not prove asynchronous FTS or provenance queues are empty."
        )
    if mode == "execute":
        limitations.append(
            "The candidate mirror is written to the run-owned Fly app repository; registry-repository retention is not covered by the machine and volume orphan scan."
        )
        limitations.append(
            "Fly machine-create rejects a digest-pinned config.image, so the candidate launches from the run-owned mirror tag; identity rests on the digest assertion taken before launch, not on the launch reference itself."
        )
        limitations.append(
            "The rollback-rescue reader launches from its own run-owned mirror tag; identity rests on its separate digest assertion before measured work, not on the launch reference itself."
        )
        limitations.append(
            "The pre-ingestion provisioning probe is mountless, so it proves candidate image and guest provisioning and the machine exec shell transport only; volume attachment, readiness, the resource measurement itself, and every measured gate remain first exercised by the real machines."
        )
        limitations.append(
            "query_latency is judged net of a transport baseline because every query crosses a WireGuard tunnel to the guest; the 150ms net limit is bounded above four observed readings (117.5/82.5/77.8/90.1), which is a thin basis, and the baseline is inferred from the cheapest query classes rather than measured server-side."
        )
        limitations.append(
            "Operational rollback is tested by updating the retained baseline Machine in place to the separately qualified rollback-rescue reader while keeping its original volume attached; candidate archive restore separately tests disaster recovery. Neither path authorizes production deployment."
        )
        limitations.append(
            "Historical correction: runs 30290534176 and 30302595011 stopped at hard-delete verification, not rollback. A -32000 tool-level 'engram not found' response is the hard-delete pass condition; protocol faults still fail closed."
        )
        limitations.append(
            "The retained Machine removes the late new-Machine placement race observed in run 30334224252. Its rescue-image update is still a documented reboot, so a rollback result proves this run's pinned-host path, not an unconditional Fly capacity guarantee."
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "exit_code": exit_code,
        "run_id": identity.run_id,
        "source": {"commit": SOURCE_COMMIT, "tag": SOURCE_TAG},
        "images": {
            "baseline": BASELINE_IMAGE,
            "baseline_digest": BASELINE_DIGEST,
            "candidate": CANDIDATE_IMAGE,
            "candidate_digest": CANDIDATE_DIGEST,
            "candidate_ref_executed": candidate_ref,
            "rollback_rescue": ROLLBACK_RESCUE_IMAGE,
            "rollback_rescue_digest": ROLLBACK_RESCUE_DIGEST,
            "rollback_rescue_ref_executed": rollback_rescue_ref,
            "rollback_rescue_role": "retained-original rollback rescue reader",
            "rollback_rescue_source_commit": ROLLBACK_RESCUE_SOURCE_COMMIT,
            "rollback_rescue_patch_commit": ROLLBACK_RESCUE_PATCH_COMMIT,
            "rollback_rescue_provenance_sha256": ROLLBACK_RESCUE_PROVENANCE_SHA256,
            "rollback_rescue_build_run_id": ROLLBACK_RESCUE_BUILD_RUN_ID,
        },
        "corpus": corpus_evidence(spec, corpus),
        "resources": {key: value for key, value in asdict(ledger).items() if value},
        "measurements": bounded_measurements,
        "gates": {name: asdict(gate) for name, gate in gates.items()},
        "cleanup": cleanup_result,
        "orphans": list(orphans),
        "detail": detail,
        "limitations": limitations,
    }

# Only reads are retried. A timed-out mutation may already have reached the server, so
# replaying it could double-apply; any method absent from this set gets exactly one attempt.
IDEMPOTENT_METHODS = frozenset({"muninn_find_by_concept", "muninn_find_by_entity", "muninn_read", "muninn_recall", "muninn_status"})
MCP_CALL_ATTEMPTS = 3

class MCPClient:
    def __init__(self, url: str, auth_value: str, timeout: float = 60.0):
        if not re.fullmatch(r"http://(?:127\.0\.0\.1|localhost):[0-9]+/mcp", url): raise RehearsalUnknown("MCP endpoint must be loopback")
        self.url, self.auth_value, self.timeout, self.request_id = url, auth_value, timeout, 0
        self.transport_retries = 0
    def _post(self, payload: dict[str, Any], timeout_s: float | None = None) -> dict[str, Any]:
        request = urllib.request.Request(self.url, data=json.dumps(payload).encode(), method="POST",
            headers={"Authorization": f"Bearer {self.auth_value}", "Content-Type": "application/json"})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=self.timeout if timeout_s is None else timeout_s) as response:
                parsed = json.loads(response.read().decode())
        except (OSError, ValueError, urllib.error.URLError) as exc: raise RehearsalUnknown(f"MCP transport failed: {type(exc).__name__}") from exc
        # Classified here rather than at the call sites: this is the only place the error code is
        # in scope, and a site that re-derived it from the message string would be exactly the
        # string-matching the typed classes exist to avoid.
        if parsed.get("error"): raise json_rpc_failure(parsed["error"])
        return parsed
    def initialize(self, timeout_s: float = READINESS_LIMIT_S) -> None:
        deadline = time.monotonic() + timeout_s
        while True:
            self.request_id += 1
            try:
                self._post({"jsonrpc": "2.0", "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "koala-stage-a", "version": "1"}}, "id": self.request_id})
                return
            except RehearsalUnknown:
                if time.monotonic() >= deadline:
                    raise RehearsalUnknown("MCP readiness deadline expired")
                time.sleep(1)
    def call(self, method: str, arguments: dict[str, Any], *, timeout_s: float | None = None,
             attempts: int | None = None) -> tuple[Any, float]:
        """Issue one tools/call, retrying a READ whose transport failed.

        Run 30228878183 lost its rollback verdict to a single TimeoutError about two hours
        in, on the fifth proxy of the run. `initialize` already retries to a deadline and
        every flyctl surface retries three times, but `call` had exactly one attempt, so one
        tunnel hiccup was fatal. Only RehearsalUnknown - transport - is retried;
        RehearsalFailed is an application error and must surface, never be replayed away.
        The timer restarts per attempt, so a retried call contributes only its successful
        attempt's latency and cannot inflate the measurement it feeds.

        `timeout_s` and `attempts` override the socket budget and the retry count for one
        call. `wait_cold_query` uses both to give a cold store a single long attempt rather
        than three short ones that abort the same work; `run_query_probes` uses `timeout_s`
        alone on the cold paths, keeping its retries. The override is clamped to the method's
        own default, so it can only ever lower the retry count - passing a large `attempts`
        can never win a mutation the replay the default denies it.

        Both failure classes out of `_post` are re-raised naming the method and vault - a
        transport failure on the last attempt, and a JSON-RPC protocol error immediately - and
        the protocol error keeps its concrete type so a caller that distinguishes it still can.
        The receipt detail is the only forensic surface a failed run leaves behind, and four
        runs in a row spent an hour each to produce a detail that named nothing.
        """
        default_attempts = MCP_CALL_ATTEMPTS if method in IDEMPOTENT_METHODS else 1
        budget = default_attempts if attempts is None else max(1, min(attempts, default_attempts))
        for attempt in range(budget):
            self.request_id += 1; started = time.monotonic()
            try:
                response = self._post({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": method, "arguments": arguments}, "id": self.request_id}, timeout_s)
                break
            except RehearsalUnknown as exc:
                self.transport_retries += 1
                # A bare "MCP transport failed: TimeoutError" cost three runs their diagnosis:
                # 30228878183, 30235793478 and 30270851093 all carried that byte-identical
                # detail and not one of them said WHICH call died, so #71 blamed a flaky tunnel
                # and #72 blamed the first query. Naming the method makes the detail a pointer.
                if attempt + 1 == budget: raise RehearsalUnknown(f"{method}: {exc}") from exc
                time.sleep(attempt + 1)
            except RehearsalFailed as exc:
                # NOT retried, and deliberately a separate clause rather than a wider first one:
                # an application error is a real answer and replaying it would be the mutation
                # hazard IDEMPOTENT_METHODS exists to prevent. RehearsalFailed and
                # RehearsalUnknown are siblings under RehearsalError, so neither clause shadows
                # the other.
                #
                # _post raises at the JSON-RPC protocol layer, where the method is not in scope,
                # which is why run 30283211992's receipt read exactly "MCP JSON-RPC error" and
                # named nothing. Every RehearsalFailed raised BELOW this loop already carries
                # its method; this was the one path in the class that did not. The vault goes in
                # too: query_counts walks stage-a-primary AND stage-a-isolation, so on the
                # rollback path the method alone still would not say which store said no.
                raise type(exc)(f"{method}({arguments.get('vault', '-')}): {exc}") from exc
        content = response.get("result", {}).get("content", [])
        if not content or not isinstance(content[0], dict) or "text" not in content[0]: raise RehearsalFailed(f"{method} returned no content")
        try: result = json.loads(content[0]["text"])
        except (TypeError, json.JSONDecodeError) as exc: raise RehearsalFailed(f"{method} returned non-JSON") from exc
        if isinstance(result, dict) and result.get("error"): raise RehearsalFailed(f"{method} application error")
        return result, (time.monotonic() - started) * 1000

def _safe_process_error(proc: subprocess.CompletedProcess[str]) -> str:
    return safe_detail((proc.stderr or proc.stdout or "no diagnostic output").strip())

class FlyRuntime:
    """Injected seam around every Fly operation; construction performs no calls."""
    def __init__(self, runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run, popen: Callable[..., subprocess.Popen[str]] = subprocess.Popen):
        self.runner, self.popen = runner, popen
        self.candidate_ref = CANDIDATE_IMAGE
        self.rollback_rescue_ref = ROLLBACK_RESCUE_IMAGE
    def run(self, args: list[str], *, stdin: str | None = None, timeout: int = 600) -> subprocess.CompletedProcess[str]:
        proc = self.runner(["flyctl", *args], input=stdin, text=True, capture_output=True, timeout=timeout)
        if proc.returncode: raise RehearsalUnknown(f"flyctl {args[0]} failed: {_safe_process_error(proc)}")
        return proc
    def crane(self, args: list[str], *, timeout: int = 1800) -> subprocess.CompletedProcess[str]:
        proc = self.runner(["crane", *args], text=True, capture_output=True, timeout=timeout)
        if proc.returncode: raise RehearsalUnknown(f"crane {args[0]} failed: {_safe_process_error(proc)}")
        return proc
    def json(self, args: list[str], *, timeout: int = 600) -> Any:
        for attempt in range(3):
            try:
                return json.loads(self.run([*args, "--json"], timeout=timeout).stdout)
            except json.JSONDecodeError as exc:
                if attempt == 2:
                    raise RehearsalUnknown(f"flyctl {args[0]} returned invalid JSON") from exc
                time.sleep(attempt + 1)
        raise AssertionError("unreachable")
    def preflight(self, identity: RunIdentity) -> None:
        assert_not_production(identity)
        proc = self.runner(["flyctl", "status", "-a", identity.app_name], text=True, capture_output=True, timeout=60)
        if proc.returncode == 0: raise RehearsalUnknown("run-owned app already exists")
    def create_app(self, identity: RunIdentity) -> str:
        self.run(["apps", "create", identity.app_name, "--org", FLY_ORG]); return identity.app_name
    def mirror_candidate(self, identity: RunIdentity) -> str:
        """Copy the qualified candidate manifest into the run-owned Fly registry repository.

        Fly holds no credential for the private source registry, so the digest-pinned
        manifest is copied verbatim into the disposable app's own repository. The copy is
        refused unless its digest still equals the qualified immutable identity, so
        mirroring cannot substitute a different image. Registry-repository retention after
        app destruction is Fly's behavior and is not asserted here.

        The returned launch reference is the mirror TAG, not a digest reference: Fly's
        machine-create rejects a digest-pinned config.image with "invalid image identifier"
        even after resolving the manifest (observed in run 30165273639). Identity is still
        bound by the digest assertion immediately above, which reads the tag's own manifest
        digest and refuses any value other than the qualified one. The residual exposure is
        a repoint of this tag between assertion and launch, in a repository this run created
        and which no other writer targets; it is disclosed as a receipt limitation.
        """
        assert_not_production(identity)
        target = f"{FLY_REGISTRY}/{identity.app_name}"
        mirrored_ref = f"{target}:{CANDIDATE_MIRROR_TAG}"
        self.crane(["copy", CANDIDATE_IMAGE, mirrored_ref])
        mirrored_digest = self.crane(["digest", mirrored_ref]).stdout.strip()
        if mirrored_digest != CANDIDATE_DIGEST:
            raise RehearsalUnknown("mirrored candidate digest differs from qualified immutable identity")
        if not MIRROR_REF.fullmatch(mirrored_ref): raise RehearsalUnknown("mirrored candidate reference is not a run-owned mirror tag")
        self.candidate_ref = mirrored_ref
        return self.candidate_ref

    def mirror_rollback_rescue(self, identity: RunIdentity) -> str:
        """Bind the qualified rollback-rescue digest to its own run-owned Fly tag."""
        assert_not_production(identity)
        target = f"{FLY_REGISTRY}/{identity.app_name}"
        mirrored_ref = f"{target}:{ROLLBACK_RESCUE_MIRROR_TAG}"
        self.crane(["copy", ROLLBACK_RESCUE_IMAGE, mirrored_ref])
        mirrored_digest = self.crane(["digest", mirrored_ref]).stdout.strip()
        if mirrored_digest != ROLLBACK_RESCUE_DIGEST:
            raise RehearsalUnknown("mirrored rollback-rescue digest differs from qualified immutable identity")
        if not ROLLBACK_RESCUE_MIRROR_REF.fullmatch(mirrored_ref):
            raise RehearsalUnknown("mirrored rollback-rescue reference is not a run-owned mirror tag")
        self.rollback_rescue_ref = mirrored_ref
        return self.rollback_rescue_ref

    def install_auth(self, identity: RunIdentity, auth_value: str) -> None:
        env_name = "MUNINN" + "_MCP_TOKEN"
        self.run(["secrets", "import", "-a", identity.app_name, "--stage"], stdin=f"{env_name}={auth_value}\nMUNINN_LOCAL_EMBED=0\n")
    def volume_state(self, identity: RunIdentity, volume_id: str) -> str:
        volumes = self.json(["volumes", "list", "-a", identity.app_name])
        if not isinstance(volumes, list): raise RehearsalUnknown("volume listing returned invalid shape")
        matches = [v for v in volumes if isinstance(v, dict) and v.get("id") == volume_id]
        if len(matches) != 1: raise RehearsalUnknown("volume state missing or ambiguous")
        state = str(matches[0].get("state", ""))
        if not state: raise RehearsalUnknown("volume state absent")
        return state

    def wait_volume_hydrated(self, identity: RunIdentity, volume_id: str, *,
                             timeout_s: float = VOLUME_READY_LIMIT_S,
                             interval_s: float = VOLUME_READY_POLL_INTERVAL_S) -> float:
        """Hold a fork until stable `created` before this harness mounts it.

        Fly permits mounting while a fork is hydrating and lazily fetches missing blocks,
        but that is not deterministic enough for a qualification launch. Measured on a
        disposable app, a 14 GB fork reported `restoring`, flyctl abandoned its start-wait
        at ~62s, and the machine started unaided at 3m13s with the data intact. Runs
        30217281791 and 30220383793 hit that same launch race after forking the backup
        volume. Waiting here chooses stable launch behavior; it does not claim Fly forbids
        hydration-time mounts.

        A near-empty fork reaches `created` on the first poll, which is why the race did not
        appear before the corpus was large.
        """
        if timeout_s <= 0 or interval_s <= 0: raise RehearsalUnknown("invalid volume readiness contract")
        started, deadline = time.monotonic(), time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            state = self.volume_state(identity, volume_id)
            if state == VOLUME_READY_STATE: return time.monotonic() - started
            # An unrecognised state is never waited out: it may be terminal, and polling a
            # dead volume to the deadline would report a timeout instead of the real state.
            if state not in VOLUME_HYDRATING_STATES:
                raise RehearsalUnknown(f"forked volume entered unexpected state: {safe_detail(state)}")
            time.sleep(interval_s)
        raise RehearsalUnknown(f"forked volume did not finish hydrating within {timeout_s:.0f}s")

    def create_volume(self, identity: RunIdentity, name: str, *, snapshot_id: str | None = None) -> str:
        assert_owned(name, identity, "volume-name")
        args = ["volumes", "create", name, "-a", identity.app_name, "--region", FLY_REGION, "--size", str(VOLUME_SIZE_GB), "--scheduled-snapshots=false", "--yes"]
        if snapshot_id: args.extend(["--snapshot-id", snapshot_id])
        result = self.json(args); volume_id = str(result.get("id", "")) if isinstance(result, dict) else ""
        if not volume_id or volume_id in PRODUCTION_VOLUME_IDS: raise RehearsalUnknown("invalid or preserved volume ID")
        # Only a fork hydrates; a fresh volume is mountable on return and polling it would
        # add a listing call to every provisioning path for a state it already holds.
        if snapshot_id: self.wait_volume_hydrated(identity, volume_id)
        return volume_id
    def _machine_config(
        self,
        identity: RunIdentity,
        volume_id: str,
        image: str,
        role: str,
    ) -> dict[str, Any]:
        if volume_id in PRODUCTION_VOLUME_IDS: raise RehearsalUnknown("refusing production volume")
        if role in {"baseline", "retained-baseline"}:
            image_role = "baseline"
        elif role == "rollback":
            image_role = "rollback-rescue"
        elif role in {"candidate", "clean-restart", "crash-restart", "hard-delete-check", "restore"}:
            image_role = "candidate"
        else:
            raise RehearsalUnknown(f"unknown machine role: {role}")
        validate_image(
            image,
            image_role,
            expected_candidate=self.candidate_ref,
            expected_rollback_rescue=self.rollback_rescue_ref,
        )
        mounts = [{"volume": volume_id, "path": "/data"}]
        require_single_mount(mounts, role)
        server_args = ["--daemon", "--data", "/data", "--listen-host", "0.0.0.0", "--mcp-addr", f"0.0.0.0:{MCP_PORT}"]
        if role == "retained-baseline":
            server_command = " ".join(["muninndb-server", *server_args])
            init = {"exec": ["/bin/sh", "-c", f"{server_command} & pid=$!; printf %s $pid > /tmp/stage-a-server.pid; wait $pid; exec sleep infinity"]}
        else:
            init = {"cmd": server_args}
        return {
            "image": image,
            "init": init,
            "restart": {"policy": "no"},
            "guest": {"cpu_kind": "performance", "cpus": 16, "memory_mb": 32768},
            "mounts": mounts,
            "metadata": {"koala_stage_a_run": identity.run_id, "role": role},
            "services": [],
        }

    def create_machine(self, identity: RunIdentity, volume_id: str, image: str, role: str) -> str:
        config = json.dumps(self._machine_config(identity, volume_id, image, role), sort_keys=True)
        name = f"koala-stage-a-{identity.run_id}-{role}"
        proc = self.run(["machine", "run", image, "-a", identity.app_name, "--region", FLY_REGION, "--name", name, "--machine-config", config, "--restart", "no", "--skip-dns-registration", "--detach"])
        matches = re.findall(r"(?m)^\s*Machine ID:\s*([0-9a-f]+)\s*$", proc.stdout)
        if len(matches) != 1 or matches[0] in PRODUCTION_MACHINE_IDS: raise RehearsalUnknown("invalid or preserved machine ID")
        return matches[0]

    def update_machine(
        self,
        identity: RunIdentity,
        machine_id: str,
        volume_id: str,
        image: str,
        role: str,
    ) -> None:
        if machine_id in PRODUCTION_MACHINE_IDS: raise RehearsalUnknown("refusing production machine")
        config = json.dumps(self._machine_config(identity, volume_id, image, role), sort_keys=True)
        self.run(["machine", "update", machine_id, "-a", identity.app_name, "--machine-config", config,
                  "--restart", "no", "--skip-dns-registration", "--wait-timeout",
                  str(math.ceil(READINESS_LIMIT_S)), "--yes"], timeout=math.ceil(READINESS_LIMIT_S) + 60)

    def quiesce_baseline(self, identity: RunIdentity, machine_id: str) -> None:
        """Gracefully stop only MuninnDB while retaining the allocated Fly Machine."""
        if machine_id in PRODUCTION_MACHINE_IDS: raise RehearsalUnknown("refusing production machine")
        command = shell_command(
            "set -eu; pid=$(cat /tmp/stage-a-server.pid); kill -TERM $pid; "
            "i=0; while kill -0 $pid 2>/dev/null; do i=$((i+1)); "
            "test $i -le 300; sleep 1; done; sync; "
            "test ! -d /proc/$pid"
        )
        self.run(["machine", "exec", machine_id, "-a", identity.app_name, "--timeout", "330", command], timeout=360)
        if self.machine_status(identity, machine_id).get("state") != "started":
            raise RehearsalUnknown("retained baseline machine no longer holds its allocation")
    def machine_status(self, identity: RunIdentity, machine_id: str) -> dict[str, Any]:
        if machine_id in PRODUCTION_MACHINE_IDS: raise RehearsalUnknown("refusing production machine")
        machines = self.json(["machines", "list", "-a", identity.app_name])
        matches = [x for x in machines if isinstance(x, dict) and x.get("id") == machine_id]
        if len(matches) != 1: raise RehearsalUnknown("machine status missing or ambiguous")
        return matches[0]
    def wait_ready(self, identity: RunIdentity, machine_id: str, timeout_s: float) -> float:
        started, deadline = time.monotonic(), time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self.machine_status(identity, machine_id).get("state") == "started": return time.monotonic() - started
            time.sleep(5)
        raise RehearsalUnknown("readiness deadline expired")
    def stalled_helper_diagnostics(self, identity: RunIdentity, machine_id: str) -> str:
        """Describe a helper that is still running past its deadline, before it is destroyed.

        Run 30206002340 spent 45 minutes waiting for the backup helper to stop, then
        destroyed it during cleanup, so the only surviving evidence was the deadline
        message itself. Nothing said whether the backup command had hung, was merely slow,
        or had finished while the machine failed to exit. The helper is still running at
        this point, so its logs, its process table and its data directory are all still
        readable, and each answers a different one of those three questions:

        - the command's own stdout and stderr say how far it got
        - a live muninndb-server or tar process means it hung inside that step
        - a checkpoint directory or a partial archive shows what had been produced

        Every probe is best effort and bounded. A diagnostic that raised, or that hung,
        would replace the real failure with its own, so each one swallows its exception
        and reports the reason inline instead.
        """
        parts: list[str] = []
        def probe(label: str, argv: list[str]) -> None:
            try:
                text = self.run(argv, timeout=60).stdout.strip()
            except Exception as exc:  # a diagnostic must never replace the failure it describes
                parts.append(f"{label}=<unavailable: {safe_detail(str(exc))}>"); return
            lines = [safe_detail(line) for line in text.splitlines()[-STALL_DIAGNOSTIC_LINES:] if line.strip()]
            parts.append(f"{label}={' / '.join(lines)}" if lines else f"{label}=<empty>")
        # Redaction is applied per line rather than to the whole capture. safe_detail blanks
        # its entire input when any part matches, and both of these probes reliably contain a
        # match that is not itself a secret: the store holds a file named auth_secret, and
        # server log lines carry a URL. Redacting the blob would therefore return
        # "[REDACTED]" in precisely the case this exists to explain. Per line, a matching
        # line still redacts whole and is never emitted; only its neighbours survive. The
        # predicate is unchanged, so nothing SENSITIVE_TEXT would have caught gets through.
        probe("logs", ["logs", "-a", identity.app_name, "--machine", machine_id, "--no-tail"])
        # The two artifact paths are named rather than listed, both to keep the reading
        # targeted and to avoid emitting the store's own filenames. A checkpoint directory
        # that exists and is growing means the backup step is slow rather than wedged; a
        # partial archive means tar is; neither present means it never got that far.
        probe("artifacts", ["machine", "exec", machine_id, "-a", identity.app_name, "--timeout", "30",
                            shell_command("du -sk /data/stage-a-backup 2>/dev/null; "
                                          "ls -o /data/stage-a-backup.tgz 2>/dev/null; "
                                          "df -Pk /data | tail -1")])
        try:
            parts.append(f"processes={self.process_names(identity, machine_id)}")
        except Exception as exc:
            parts.append(f"processes=<unavailable: {safe_detail(str(exc))}>")
        return " | ".join(parts)

    def wait_stopped(self, identity: RunIdentity, machine_id: str, timeout_s: float) -> float:
        """Poll the helper's state until it stops, instead of holding one long wait call.

        `flyctl machine wait` holds a single request open for the whole deadline. In run
        30212272430 that call failed about a minute into a 45 minute budget while the
        helper was still doing useful work: the archive was growing and tar and gzip were
        both alive. One dropped long-lived request is not evidence that the helper failed,
        yet it ended the rehearsal as though it were. Polling machine_status on the cadence
        wait_ready already uses replaces that single 45 minute request with short
        independent ones, and leaves the deadline itself unchanged.

        Polling trades one fragile request for many short ones, and over a long wait there
        are enough of them that a single transient error is likely, so a bounded run of
        consecutive failures is absorbed rather than treated as a verdict. The count resets
        on any successful reading, so a persistent fault still surfaces quickly and never
        consumes the whole deadline in silence.
        """
        started, deadline, failures = time.monotonic(), time.monotonic() + timeout_s, 0
        while True:
            try:
                state = self.machine_status(identity, machine_id).get("state"); failures = 0
            except RehearsalUnknown as exc:
                failures += 1
                if failures > HELPER_STATUS_RETRIES: raise RehearsalUnknown(f"helper state unreadable: {exc}") from exc
                state = None
            if state == "stopped": break
            if time.monotonic() >= deadline:
                raise RehearsalUnknown(
                    f"helper did not reach stopped within {math.ceil(timeout_s)}s, currently "
                    f"{state} || reading at deadline: "
                    f"{self.stalled_helper_diagnostics(identity, machine_id)}")
            time.sleep(HELPER_POLL_INTERVAL_S)
        status = self.run(["machine", "status", machine_id, "-a", identity.app_name], timeout=60).stdout
        exit_codes = re.findall(r"exit_code\s*[=:]\s*([0-9]+)", status)
        if not exit_codes: raise RehearsalUnknown("offline helper exit code missing")
        if int(exit_codes[-1]) != 0: raise RehearsalFailed(f"offline helper exited {exit_codes[-1]}")
        return time.monotonic() - started
    def proxy(self, identity: RunIdentity, machine_id: str, local_port: int) -> subprocess.Popen[str]:
        private_ip = self.machine_status(identity, machine_id).get("private_ip")
        if not isinstance(private_ip, str) or not private_ip: raise RehearsalUnknown("private IP missing")
        return self.popen(["flyctl", "proxy", f"{local_port}:{MCP_PORT}", private_ip, "-a", identity.app_name, "--bind-addr", "127.0.0.1", "--quiet"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, text=True)
    def disk_sample(self, identity: RunIdentity, machine_id: str, phase: str) -> DiskSample:
        command = ["machine", "exec", machine_id, "-a", identity.app_name, "--timeout", "30", "df -Pk /data"]
        for attempt in range(3):
            try:
                output = self.run(command).stdout
                break
            except RehearsalUnknown as exc:
                if "408" not in str(exc) or attempt == 2: raise
                time.sleep(attempt + 1)
        rows = [line.split() for line in output.splitlines() if line.strip()]
        if len(rows) < 2 or len(rows[-1]) < 6: raise RehearsalUnknown("invalid disk measurement")
        total, used, available = map(int, rows[-1][1:4]); return DiskSample(phase, used * 1024, available * 1024, total * 1024)
    def resource_sample(self, identity: RunIdentity, machine_id: str, phase: str) -> ResourceSample:
        """Sum CPU percent and RSS across MuninnDB processes, reading /proc rather than ps.

        The previous implementation shelled out to `ps -eo pcpu=,rss=,comm=`. That option
        set is procps-specific and is rejected by BusyBox ps, which produced empty stdout
        and the bare "invalid CPU or memory measurement" that ended runs 30173477457 and
        30179378599. This method only ever runs against the CANDIDATE machine (via
        migration_samples), so the incompatibility could not surface until a run first
        reached the candidate transition, roughly 1.5 hours in, and the error text named
        no command and quoted no output.

        /proc is present on any Linux image, and the arithmetic reproduces exactly what ps
        computes: pcpu is (utime+stime)/HZ over process elapsed time, rss is the stat page
        count scaled to KiB. Semantics are therefore unchanged; only the source is.

        The command is wrapped by shell_command because `machine exec` provides no shell
        (see that function); the pipe in the original ps form and the command substitution
        in the first /proc form were both consumed as literal argv words, which is why runs
        30173477457, 30179378599 and 30181298432 all returned empty stdout.
        """
        command = shell_command(
            "awk -v hz=$(getconf CLK_TCK 2>/dev/null || echo 100) "
            "-v pg=$(getconf PAGESIZE 2>/dev/null || echo 4096) "
            "'" + PROCFS_RESOURCE_AWK + "' /proc/uptime /proc/[0-9]*/stat"
        )
        captured = self.run(["machine", "exec", machine_id, "-a", identity.app_name, "--timeout", "30", command]).stdout
        fields = captured.split()
        if len(fields) != 2:
            raise RehearsalUnknown(f"invalid CPU or memory measurement; command output was {captured.strip()[:200]!r}")
        try: cpu_percent, rss_kib = float(fields[0]), int(fields[1])
        except ValueError as exc: raise RehearsalUnknown("invalid CPU or memory values") from exc
        if cpu_percent < 0 or rss_kib <= 0:
            raise RehearsalUnknown("missing MuninnDB process measurement; processes present: "
                                   f"{self.process_names(identity, machine_id)}")
        return ResourceSample(phase, cpu_percent, rss_kib * 1024)

    def process_names(self, identity: RunIdentity, machine_id: str) -> str:
        """List the process names actually visible, for a measurement that found none.

        A reading of zero has two very different causes: MuninnDB has not started yet, or
        it is running under a name the comm filter does not match. The receipt cannot
        distinguish them without the inventory, and guessing wrong costs a full ~1.5 hour
        cycle, which is how runs 30173477457, 30179378599 and 30181298432 were each spent.

        Kernel threads are excluded by parentage, and truncation announces itself. Run
        30185035316's inventory did neither: sixteen cpuhp threads sorted ahead of anything
        useful, a silent 200 character cap cut the line mid-token at "(jb", and the one name
        the probe existed to look for would have sorted past the cut. That inventory was
        read as evidence MuninnDB never started, which it was not evidence of at all.

        Diagnostic only: it never turns a failed measurement into a passing one, and if the
        probe itself fails the caller still raises on the original missing measurement.
        """
        probe = shell_command(
            "awk 'FNR==1{if(match($0,/[(].*[)]/)==0)next;"
            "n=split(substr($0,RSTART+RLENGTH+1),f);if(n<2)next;"
            "if($1==2||f[2]==2)next;print substr($0,RSTART+1,RLENGTH-2)}' /proc/[0-9]*/stat"
        )
        try:
            output = self.run(["machine", "exec", machine_id, "-a", identity.app_name,
                               "--timeout", "30", probe]).stdout
        except RehearsalError:
            return "unavailable"
        names = sorted(set(output.split()))
        if not names: return "none"
        joined = ",".join(names)
        return joined if len(joined) <= PROCESS_INVENTORY_CHARS else f"{joined[:PROCESS_INVENTORY_CHARS]}...({len(names)} names, truncated)"
    def migration_samples(self, identity: RunIdentity, machine_id: str, timeout_s: float,
                          interval_s: float = 5.0) -> tuple[float, list[DiskSample], list[ResourceSample]]:
        started, deadline, disks, resources = time.monotonic(), time.monotonic() + timeout_s, [], []
        last_error: RehearsalUnknown | None = None
        while time.monotonic() < deadline:
            status = self.machine_status(identity, machine_id).get("state")
            if status in {"stopped", "failed", "destroyed"}: raise RehearsalFailed(f"candidate stopped during migration: {status}")
            if status in {"started", "starting", "created"}:
                # Fly reports "started" when the VM boots, not when MuninnDB is serving, so
                # the first poll routinely lands before any MuninnDB process exists. Run
                # 30183128792 failed on exactly that: the exec succeeded and returned a
                # real reading of zero processes. A not-yet-running process is therefore a
                # retry condition until the deadline, never a measurement. This tolerates
                # only the timing; the deadline still bounds it, a crashed candidate still
                # fails immediately on the state check above, and an unmeasurable candidate
                # still ends the run UNKNOWN rather than recording a zero.
                try:
                    disk = self.disk_sample(identity, machine_id, "migration")
                    resource = self.resource_sample(identity, machine_id, "migration")
                except RehearsalUnknown as exc:
                    last_error = exc
                else:
                    disks.append(disk); resources.append(resource)
                    if status == "started": return time.monotonic() - started, disks, resources
            time.sleep(interval_s)
        expired = "migration readiness deadline expired"
        raise RehearsalUnknown(f"{expired}; last sampling error: {last_error}" if last_error else expired)
    def _snapshots(self, identity: RunIdentity, volume_id: str) -> list[dict[str, str]]:
        result = self.json(["volumes", "snapshots", "list", volume_id, "-a", identity.app_name])
        if not isinstance(result, list):
            raise RehearsalUnknown("snapshot list returned invalid shape")
        snapshots = []
        for item in result:
            if not isinstance(item, dict):
                raise RehearsalUnknown("snapshot list entry invalid")
            snapshot_id = item.get("id")
            status = item.get("status")
            created_at = item.get("created_at")
            if not isinstance(snapshot_id, str) or not isinstance(status, str) or not isinstance(created_at, str) or not created_at:
                raise RehearsalUnknown("snapshot list entry missing identity or status")
            if status not in {"waiting", "running", "created"}:
                raise RehearsalUnknown(f"snapshot entered non-success status: {safe_detail(status)}")
            if status == "created" and not snapshot_id:
                raise RehearsalUnknown("created snapshot ID missing")
            snapshots.append({"id": snapshot_id, "status": status, "created_at": created_at})
        return snapshots
    def snapshot(self, identity: RunIdentity, volume_id: str, *,
                 timeout_s: float = SNAPSHOT_LIMIT_S,
                 interval_s: float = SNAPSHOT_POLL_INTERVAL_S) -> str:
        if timeout_s <= 0 or interval_s <= 0:
            raise RehearsalUnknown("invalid snapshot wait contract")
        before = self._snapshots(identity, volume_id)
        pending = [item for item in before if item["status"] in {"waiting", "running"}]
        if len(pending) > 1:
            raise RehearsalUnknown("multiple snapshots already in flight")
        baseline_created_ids = {
            item["id"] for item in before if item["status"] == "created"
        }
        if not pending:
            try:
                self.run(["volumes", "snapshots", "create", volume_id, "-a", identity.app_name])
            except RehearsalUnknown as exc:
                if "failed_precondition: snapshot is already scheduled" not in str(exc):
                    raise
                collision = self._snapshots(identity, volume_id)
                completed = {
                    item["id"] for item in collision if item["status"] == "created"
                } - baseline_created_ids
                if len(completed) > 1:
                    raise RehearsalUnknown("new snapshot identity is ambiguous") from exc
                if completed:
                    return next(iter(completed))
                pending = [item for item in collision if item["status"] in {"waiting", "running"}]
                if len(pending) != 1:
                    raise RehearsalUnknown("scheduled snapshot could not be identified") from exc
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            snapshots = self._snapshots(identity, volume_id)
            current_created_ids = {
                item["id"] for item in snapshots if item["status"] == "created"
            }
            new_created_ids = current_created_ids - baseline_created_ids
            if len(new_created_ids) > 1:
                raise RehearsalUnknown("new snapshot identity is ambiguous")
            if new_created_ids:
                return next(iter(new_created_ids))
            time.sleep(interval_s)
        raise RehearsalUnknown("snapshot creation deadline expired")
    def owned_machines(self, identity: RunIdentity) -> list[tuple[str, str]]:
        """List run-owned Machine IDs and roles, whatever the ledger believes."""
        machines = self.json(["machines", "list", "-a", identity.app_name])
        if not isinstance(machines, list):
            raise RehearsalUnknown("machine listing returned invalid resources")
        found = []
        for machine in machines:
            if not isinstance(machine, dict): continue
            machine_id = str(machine.get("id", ""))
            metadata = (machine.get("config") or {}).get("metadata") or {}
            if (machine_id and machine_id not in PRODUCTION_MACHINE_IDS
                    and metadata.get("koala_stage_a_run") == identity.run_id):
                found.append((machine_id, str(metadata.get("role", ""))))
        return found

    def owned_machine_ids(self, identity: RunIdentity) -> list[str]:
        """List the machines Fly actually holds for this run, whatever the ledger believes.

        The platform creates a machine before flyctl reports its ID, so a launch that fails
        after creation returns no ID to record. Run 30220383793 lost its restore helper
        exactly there: the machine existed, the ledger never learned of it, cleanup skipped
        it, and the volume it still held then refused to be destroyed. Asking the platform
        what exists closes that gap for every launch site at once, rather than guarding
        each one separately.

        Deliberately permissive where discover_owned_resources raises. This runs during
        cleanup, where refusing to answer would strand the very resource it exists to find.
        Ownership is still enforced by run metadata and production IDs are still excluded,
        so a permissive read cannot widen what may be destroyed.
        """
        return [machine_id for machine_id, _role in self.owned_machines(identity)]
    def launch_failure_diagnostics(self, identity: RunIdentity, helper_name: str,
                                   mounts: list[dict[str, str]]) -> str:
        """Say why a helper never reached its start state, while the evidence still exists.

        Runs 30217281791 and 30220383793 both died launching the restore helper, and all
        flyctl offered was "machine failed to reach desired start state". That sentence
        cannot distinguish a machine that never booted from one that booted and whose
        command exited at once, and the two have opposite causes: the first points at the
        volume being mounted, the second at the command being run.

        Three facts separate them and none survives cleanup, so all three are read here:
        the machine's state and exit events, its logs, and the reported state of the volume
        it was asked to mount. The restore volume is a fork of a snapshot taken seconds
        earlier. Fly permits hydration-time mounts, but the volume state is still the first
        useful fact when a deterministic machine launch fails.

        Every probe is best effort and bounded, on the same reasoning as
        stalled_helper_diagnostics: a diagnostic that raised would replace the failure it
        exists to explain. Log lines are redacted per line for the reason given there.
        """
        parts: list[str] = []
        match = None
        try:
            machines = self.json(["machines", "list", "-a", identity.app_name])
            match = next((m for m in machines if isinstance(m, dict)
                          and m.get("name") == helper_name), None)
        except Exception as exc:
            parts.append(f"machine=<unavailable: {safe_detail(str(exc))}>")
        if match is None:
            parts.append("machine=<absent: nothing was created>")
        else:
            machine_id = str(match.get("id", ""))
            parts.append(f"machine={machine_id} state={match.get('state')}")
            described = []
            for event in (match.get("events") or [])[:STALL_DIAGNOSTIC_LINES]:
                if not isinstance(event, dict): continue
                exit_code = ((event.get("request") or {}).get("exit_event") or {}).get("exit_code")
                described.append(f"{event.get('type')}:{event.get('status')}"
                                 + (f":exit={exit_code}" if exit_code is not None else ""))
            if described: parts.append("events=" + " / ".join(described))
            try:
                text = self.run(["logs", "-a", identity.app_name, "--machine", machine_id,
                                 "--no-tail"], timeout=60).stdout
                lines = [safe_detail(line) for line in
                         text.splitlines()[-STALL_DIAGNOSTIC_LINES:] if line.strip()]
                parts.append("logs=" + (" / ".join(lines) if lines else "<empty>"))
            except Exception as exc:
                parts.append(f"logs=<unavailable: {safe_detail(str(exc))}>")
        for mount in mounts:
            volume_id = str(mount.get("volume", ""))
            try:
                volumes = self.json(["volumes", "list", "-a", identity.app_name])
                volume = next((v for v in volumes if isinstance(v, dict)
                               and v.get("id") == volume_id), None)
                parts.append(f"volume={volume_id} state="
                             + (str(volume.get("state")) if volume else "<absent>"))
            except Exception as exc:
                parts.append(f"volume={volume_id} state=<unavailable: {safe_detail(str(exc))}>")
        return " ".join(parts)
    def _offline_helper(self, identity: RunIdentity, image: str, role: str,
                        mounts: list[dict[str, str]], command: str) -> str:
        require_single_mount(mounts, role)
        helper_name = f"koala-stage-a-{identity.run_id}-{role}"
        config = json.dumps({"image": image, "init": {"exec": ["/bin/sh", "-c", command]},
            "restart": {"policy": "no"}, "guest": {"cpu_kind": "performance", "cpus": 16, "memory_mb": 32768},
            "mounts": mounts, "metadata": {"koala_stage_a_run": identity.run_id, "role": role}, "services": []}, sort_keys=True)
        try:
            proc = self.run(["machine", "run", image, "-a", identity.app_name, "--region", FLY_REGION,
                "--name", helper_name, "--machine-config", config, "--restart", "no",
                "--skip-dns-registration", "--detach"])
        except RehearsalUnknown as exc:
            # The launch can fail after the machine exists, so the diagnosis is read here
            # while it does. Cleanup finds the machine itself through owned_machine_ids.
            raise RehearsalUnknown(f"{role} helper launch failed: {exc} || "
                f"{self.launch_failure_diagnostics(identity, helper_name, mounts)}") from exc
        matches = re.findall(r"(?m)^\s*Machine ID:\s*([0-9a-f]+)\s*$", proc.stdout)
        if len(matches) != 1 or matches[0] in PRODUCTION_MACHINE_IDS:
            raise RehearsalUnknown(f"{role} helper ID missing")
        return matches[0]
    def provisioning_probe(self, identity: RunIdentity, image: str) -> str:
        """Launch a mountless no-op machine to prove candidate provisioning before ingestion.

        Six consecutive rehearsals spent roughly 1.5 hours ingesting 502,385 records and
        then failed within seconds on a Fly provisioning call against the candidate image
        (run 30165273639: "invalid image identifier"; run 30173477457: "invalid CPU or
        memory measurement"). This probe launches the same image with the same guest spec
        the real machines use, so that class of fault costs minutes instead of a full
        ingest. It adds no gate and relaxes none; it only moves failure earlier.

        Deliberately mountless: attaching the source volume would let the candidate
        initialise a store on it and corrupt the empty-to-settled footprint measurement.
        Volume attachment is therefore NOT covered here and is still first exercised by
        the real candidate machine.
        """
        validate_image(image, "candidate", expected_candidate=self.candidate_ref)
        return self._offline_helper(identity, image, "preflight-probe", [], "sleep 120")

    def exec_canary(self, identity: RunIdentity, machine_id: str) -> str:
        """Prove `machine exec` reaches a real shell before the ingest commits 1.5 hours.

        Runs the identical shell_command wrapping and single-quoted awk shape that the
        migration resource sample uses, so a transport or quoting fault fails the run in
        minutes. Runs 30173477457, 30179378599 and 30181298432 each spent a full corpus
        ingest to discover that a measurement command returned empty stdout.

        This proves the exec transport and the presence of a shell and awk. It does NOT
        prove the resource measurement itself: the probe is mountless and runs no MuninnDB
        process, so the summed CPU and RSS values are still first measured on the real
        candidate machine.
        """
        command = shell_command("awk 'BEGIN{print 6*7}'")
        captured = self.run(["machine", "exec", machine_id, "-a", identity.app_name,
                             "--timeout", "30", command]).stdout
        if captured.strip() != EXEC_CANARY_TOKEN:
            raise RehearsalUnknown("machine exec shell canary failed; expected "
                                   f"{EXEC_CANARY_TOKEN!r}, output was {captured.strip()[:200]!r}")
        return captured.strip()
    def create_backup(self, identity: RunIdentity, volume_id: str, image: str) -> tuple[str, str]:
        """Take a real MuninnDB backup, writing the archive onto the source volume.

        A Fly machine mounts one volume, so the archive cannot be written to a second
        volume here. It is written beside the store instead and reaches the restore volume
        by volume fork, which is how the rollback path already moves a volume's contents
        (create_volume --snapshot-id). What the gate measures is unchanged: MuninnDB's own
        backup subcommand runs against the live store, and the archive's sha256 and byte
        count are recorded for the restore side to verify.
        """
        validate_image(image, "candidate", expected_candidate=self.candidate_ref)
        if volume_id in PRODUCTION_VOLUME_IDS:
            raise RehearsalUnknown("refusing production backup volume")
        archive = f"{BACKUP_ARCHIVE_DIR}/stage-a-backup.tgz"
        command = ("set -eu; rm -rf /data/stage-a-backup; "
            "muninndb-server backup --data-dir /data --output /data/stage-a-backup; "
            "tar -C /data/stage-a-backup -czf \"$A\" .; sha256sum \"$A\" | cut -d' ' -f1 > \"$A.sha256\"; "
            "stat -c %s \"$A\" > \"$A.bytes\"; rm -rf /data/stage-a-backup")
        command = f"A={archive}; {command}"
        mounts = [{"volume": volume_id, "path": "/data"}]
        return self._offline_helper(identity, image, "backup", mounts, command), archive
    def hard_delete(self, identity: RunIdentity, volume_id: str, image: str,
                    vault: str, memory_id: str) -> str:
        validate_image(image, "candidate", expected_candidate=self.candidate_ref)
        if volume_id in PRODUCTION_VOLUME_IDS or not re.fullmatch(r"[A-Za-z0-9_-]+", vault) or not re.fullmatch(r"[A-Za-z0-9_-]+", memory_id):
            raise RehearsalUnknown("invalid hard-delete target")
        command = (f"set -eu; muninndb-server exec forget --data-dir /data "
            f"--vault {vault} --id {memory_id}")
        return self._offline_helper(identity, image, "hard-delete", [{"volume": volume_id, "path": "/data"}], command)
    def create_restore(self, identity: RunIdentity, restore_volume_id: str,
                       image: str, archive_path: str) -> str:
        """Reconstitute the store from the archive alone, on a fork of the backup volume.

        The restore volume is a fork of the volume the backup was written to, so it arrives
        carrying BOTH the archive and a copy of the original store. Leaving that copy in
        place would mean the queries downstream proved only that a volume fork works. The
        store is therefore deleted before extraction, and everything downstream then reads
        a store that only the archive could have produced, which is a stricter test of the
        backup than the two-mount copy it replaces.

        The archive and its two sidecars are removed only at the very end, after the
        receipt that records their size and checksum has been written. Under `set -eu`
        that point is reached only if every step succeeded, so a failure at any stage
        leaves the archive in place for diagnosis, while a success hands the restore
        machine a data directory holding nothing but what the archive produced. That
        matters because the two-mount version extracted into a pristine volume, and
        MuninnDB would otherwise be asked to open a store littered with a 1.8 GB tarball
        it has never seen. The empty-target precondition the two-mount version asserted is
        replaced by an explicit wipe, since the fork guarantees the target is NOT empty.
        """
        validate_image(image, "candidate", expected_candidate=self.candidate_ref)
        if restore_volume_id in PRODUCTION_VOLUME_IDS:
            raise RehearsalUnknown("refusing production restore volume")
        command = (f"set -eu; A={archive_path}; test -f \"$A\"; test -f \"$A.sha256\"; "
            "test -f \"$A.bytes\"; test \"$(sha256sum \"$A\" | cut -d' ' -f1)\" = \"$(cat \"$A.sha256\")\"; "
            "find /data -mindepth 1 -maxdepth 1 ! -name 'stage-a-backup.tgz*' -exec rm -rf {} +; "
            "test -z \"$(find /data -mindepth 1 -maxdepth 1 ! -name 'stage-a-backup.tgz*' -print -quit)\"; "
            "tar -xzf \"$A\" -C /data; "
            "printf 'bytes=' > /data/.stage-a-restore-receipt; cat \"$A.bytes\" >> /data/.stage-a-restore-receipt; "
            "printf 'sha256=' >> /data/.stage-a-restore-receipt; cat \"$A.sha256\" >> /data/.stage-a-restore-receipt; "
            "rm -f \"$A\" \"$A.sha256\" \"$A.bytes\"; "
            "test -z \"$(find /data -maxdepth 1 -name 'stage-a-backup.tgz*' -print -quit)\"")
        mounts = [{"volume": restore_volume_id, "path": "/data"}]
        return self._offline_helper(identity, image, "restore-copy", mounts, command)
    def backup_measurement(self, identity: RunIdentity, machine_id: str) -> dict[str, Any]:
        proc = self.run(["machine", "exec", machine_id, "-a", identity.app_name, "--timeout", "60",
                         "cat /data/.stage-a-restore-receipt"])
        fields = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
        if not fields.get("bytes", "").isdigit() or not re.fullmatch(r"[0-9a-f]{64}", fields.get("sha256", "")):
            raise RehearsalUnknown("backup measurement missing")
        return {"bytes": int(fields["bytes"]), "sha256": fields["sha256"]}
    def stop_machine(self, identity: RunIdentity, machine_id: str, *, force: bool = False) -> None:
        args = ["machine", "stop", machine_id, "-a", identity.app_name]
        if force: args.extend(["--signal", "SIGKILL", "--timeout", "1"])
        self.run(args)
    def destroy_machine(self, identity: RunIdentity, machine_id: str) -> None:
        if machine_id in PRODUCTION_MACHINE_IDS: raise RehearsalUnknown("refusing production machine")
        self.run(["machine", "destroy", machine_id, "-a", identity.app_name, "--force"])
    def destroy_volume(self, identity: RunIdentity, volume_id: str) -> None:
        if volume_id in PRODUCTION_VOLUME_IDS: raise RehearsalUnknown("refusing production volume")
        self.run(["volumes", "destroy", volume_id, "-a", identity.app_name, "--yes"])
    def destroy_app(self, identity: RunIdentity) -> None:
        assert_owned(identity.app_name, identity, "app-name"); self.run(["apps", "destroy", identity.app_name, "--yes"])
    def list_owned_resources(self, identity: RunIdentity) -> list[str]:
        proc = self.runner(["flyctl", "status", "-a", identity.app_name], text=True, capture_output=True, timeout=60)
        return [] if proc.returncode else [identity.app_name]
    def discover_owned_resources(self, identity: RunIdentity) -> ResourceLedger:
        assert_not_production(identity)
        status = self.runner(["flyctl", "status", "-a", identity.app_name], text=True, capture_output=True, timeout=60)
        if status.returncode:
            return ResourceLedger()
        machines = self.json(["machines", "list", "-a", identity.app_name])
        volumes = self.json(["volumes", "list", "-a", identity.app_name])
        if not isinstance(machines, list) or not isinstance(volumes, list):
            raise RehearsalUnknown("cleanup discovery returned invalid resources")
        machine_ids: dict[str, str] = {}
        for machine in machines:
            if not isinstance(machine, dict): raise RehearsalUnknown("cleanup machine entry invalid")
            machine_id = str(machine.get("id", ""))
            metadata = (machine.get("config") or {}).get("metadata") or {}
            role = str(metadata.get("role", ""))
            if (not machine_id or machine_id in PRODUCTION_MACHINE_IDS
                    or metadata.get("koala_stage_a_run") != identity.run_id):
                raise RehearsalUnknown("cleanup discovered unowned machine")
            if role in {"retained-baseline", "rollback"}:
                slot = "retained_machine_id"
            elif role in {"baseline", "candidate", "clean-restart", "crash-restart",
                          "hard-delete-check", "restore", "preflight-probe", "backup",
                          "hard-delete", "restore-copy"}:
                slot = "machine_id"
            else:
                raise RehearsalUnknown("cleanup discovered unknown machine role")
            if slot in machine_ids:
                raise RehearsalUnknown("cleanup discovered duplicate machine role")
            machine_ids[slot] = machine_id
        by_name: dict[str, str] = {}
        allowed_names = {
            identity.volume_name,
            identity.candidate_volume_name,
            identity.backup_volume_name,
            identity.restore_volume_name,
            identity.rollback_volume_name,
        }
        for volume in volumes:
            if not isinstance(volume, dict): raise RehearsalUnknown("cleanup volume entry invalid")
            volume_id, name = str(volume.get("id", "")), str(volume.get("name", ""))
            if volume_id in PRODUCTION_VOLUME_IDS or name not in allowed_names or name in by_name:
                raise RehearsalUnknown("cleanup discovered unowned or duplicate volume")
            by_name[name] = volume_id
        return ResourceLedger(
            app=identity.app_name,
            retained_machine_id=machine_ids.get("retained_machine_id"),
            machine_id=machine_ids.get("machine_id"),
            volume_id=by_name.get(identity.volume_name),
            candidate_volume_id=by_name.get(identity.candidate_volume_name),
            backup_volume_id=by_name.get(identity.backup_volume_name),
            restore_volume_id=by_name.get(identity.restore_volume_name),
            rollback_volume_id=by_name.get(identity.rollback_volume_name),
        )

def termination_handler(signum: int, _frame: Any) -> None:
    raise RehearsalUnknown(f"rehearsal terminated by signal {signum}")

def install_termination_handlers() -> None:
    signal.signal(signal.SIGTERM, termination_handler)
    signal.signal(signal.SIGINT, termination_handler)

def terminate_proxy(proxy: subprocess.Popen[str] | None) -> None:
    if proxy is None: return
    try:
        proxy.terminate(); proxy.wait(timeout=5)
    except (OSError, subprocess.SubprocessError):
        try:
            proxy.kill(); proxy.wait(timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            raise RehearsalUnknown("local proxy could not be terminated") from exc

def with_cleanup_concern(detail: str, orphans: list[str]) -> str:
    """Add the cleanup concern to a detail without discarding the reason the run ended.

    Cleanup runs in a finally block, so it observes every outcome including a phase that
    raised. Overwriting the detail there let the last thing that happened describe the run
    instead of the thing that ended it: run 30217281791 reached the restore phase, failed
    inside it, and reported only "cleanup uncertainty or orphaned resources", so the error
    was absent from the receipt and from the workflow log, and could not be recovered at
    all. The orphan list is already its own receipt field, so the detail names the concern
    and leaves the enumeration there.

    An orphan still forces UNKNOWN at every caller. A resource that may have survived the
    run is not a passing rehearsal, and nothing here softens that.
    """
    return safe_detail(f"{detail} || cleanup: {len(orphans)} resource(s) may remain", RECEIPT_DETAIL_CHARS)

def cleanup(runtime: FlyRuntime, identity: RunIdentity, ledger: ResourceLedger) -> tuple[dict[str, str], list[str]]:
    """Destroy the run's own resources, retrying a failed destroy and recording why it failed.

    Machines are destroyed before the volumes they mount, so a volume destroy can arrive
    while the platform still considers the volume attached. Run 30217281791 lost its
    verdict to exactly that: the restore volume's destroy failed once and was reported as
    an orphan, with no reason recorded and no second attempt. A bounded retry answers the
    transient case, and any resource that still refuses to go is a possible leak that must
    keep failing the run rather than being assumed away.

    The failure text is kept beside the status because "destroy_failed" alone cannot
    distinguish a detach race from a credential or quota fault, and the two need different
    responses. It goes through the same redaction predicate as every other diagnostic.
    """
    results, orphans = {}, []
    if (ledger.machine_id and ledger.retained_machine_id
            and ledger.machine_id == ledger.retained_machine_id):
        duplicate_machine_id = ledger.machine_id
        ledger.machine_id = None
        results["machine_topology_error"] = "one Machine ID occupied both ledger slots"
        orphans.append(f"{duplicate_machine_id}:duplicate-machine-ledger-slots")
    # A machine the ledger never learned of still holds its volume, and the volume destroy
    # then fails on a binding to a machine nobody is going to destroy. That is how run
    # 30220383793 reported an orphan. The platform is asked what survived before anything
    # is destroyed, so a machine lost to a failed launch is destroyed in the ordinary order.
    if ledger.app:
        try:
            surviving = runtime.owned_machines(identity)
        except Exception as exc:
            surviving = []
            results["machine_discovery_error"] = safe_detail(f"{type(exc).__name__}: {exc}")
        known_ids = {item for item in (ledger.retained_machine_id, ledger.machine_id) if item}
        unexpected_machines: list[str] = []
        for machine_id, role in surviving:
            if machine_id in known_ids: continue
            if role in {"retained-baseline", "rollback"} and not ledger.retained_machine_id:
                ledger.retained_machine_id = machine_id
                results["retained_machine_recovered"] = machine_id
            elif role in {"baseline", "candidate", "clean-restart", "crash-restart",
                          "hard-delete-check", "restore", "preflight-probe", "backup",
                          "hard-delete", "restore-copy"} and not ledger.machine_id:
                ledger.machine_id = machine_id
                results["machine_recovered"] = machine_id
            else:
                unexpected_machines.append(machine_id)
        for machine_id in unexpected_machines:
            try:
                runtime.destroy_machine(identity, machine_id)
                results[f"unexpected_machine_{machine_id}"] = "destroyed"
            except Exception as exc:
                results[f"unexpected_machine_{machine_id}"] = "destroy_failed"
                results[f"unexpected_machine_{machine_id}_error"] = safe_detail(f"{type(exc).__name__}: {exc}")
            # Even successful cleanup cannot turn an unexplained topology into a passing run.
            orphans.append(f"{machine_id}:unexpected-machine-topology")
    for label in ("machine_id", "retained_machine_id", "restore_volume_id", "backup_volume_id", "rollback_volume_id",
                  "candidate_volume_id", "volume_id"):
        resource = getattr(ledger, label)
        if not resource: results[label] = "not_created"; continue
        failure: Exception | None = None
        for attempt in range(DESTROY_ATTEMPTS):
            try:
                runtime.destroy_machine(identity, resource) if label in {"machine_id", "retained_machine_id"} else runtime.destroy_volume(identity, resource)
                failure = None; break
            except Exception as exc:
                failure = exc
                if attempt + 1 < DESTROY_ATTEMPTS: time.sleep(DESTROY_RETRY_DELAY_S)
        if failure is None: results[label] = "destroyed"; setattr(ledger, label, None)
        else:
            results[label] = "destroy_failed"
            results[f"{label}_error"] = safe_detail(f"{type(failure).__name__}: {failure}")
            orphans.append(resource)
    if ledger.app:
        try: runtime.destroy_app(identity); results["app"] = "destroyed"; ledger.app = None
        except Exception: results["app"] = "destroy_failed"; orphans.append(identity.app_name)
    else: results["app"] = "not_created"
    try: orphans.extend(x for x in runtime.list_owned_resources(identity) if x not in orphans)
    except Exception: orphans.append(f"{identity.run_id}:orphan-scan-unknown")
    return results, orphans

def cleanup_only(
    identity: RunIdentity,
    receipt_path: Path,
    *,
    runtime: FlyRuntime | None = None,
) -> int:
    runtime = runtime or FlyRuntime()
    status, exit_code, detail = "UNKNOWN", 2, "cleanup did not complete"
    cleanup_result: dict[str, str] = {}
    orphans: list[str] = []
    ledger = ResourceLedger()
    try:
        ledger = runtime.discover_owned_resources(identity)
        cleanup_result, orphans = cleanup(runtime, identity, ledger)
        if orphans: detail = "cleanup uncertainty or orphaned resources"
        else: status, exit_code, detail = "PASSED", 0, "run-owned resources absent after cleanup"
    except RehearsalError as exc:
        detail = safe_detail(str(exc), RECEIPT_DETAIL_CHARS)
        orphans = [f"{identity.run_id}:cleanup-discovery-unknown"]
    except Exception as exc:
        detail = f"unexpected {type(exc).__name__}"
        orphans = [f"{identity.run_id}:cleanup-discovery-unknown"]
    spec = CorpusSpec()
    write_receipt(receipt_path, receipt_document(
        identity, spec, status=status, exit_code=exit_code, detail=detail,
        ledger=ledger, measurements={}, gates={}, cleanup_result=cleanup_result,
        orphans=orphans, corpus=None, mode="cleanup-only",
    ))
    return exit_code

def wait_cold_query(client: MCPClient, vault: str, concept: str = COLLISION_CONCEPTS[0],
                    timeout_s: float = COLD_QUERY_LIMIT_S,
                    interval_s: float = COLD_QUERY_POLL_INTERVAL_S) -> float:
    """Hold until a store on a freshly created volume answers a real DATA query.

    Every other readiness surface here is deadline-based: initialize waits 5 minutes,
    wait_ready 5, wait_volume_hydrated 15, wait_stopped 45. The data queries were the
    exception - they got one 60-second socket timeout - so an incidental client setting stood
    in for ROLLBACK_LIMIT_S and decided the phase three runs in a row.

    The probe is `muninn_find_by_concept`, NOT `muninn_status`. #72 probed status and measured
    0.077s and 0.159s on run 30270851093, because status reads metadata and never faults a
    data block in. Status is also the exact call query_count issues, so that wait warmed the
    one call that was already fast and left the expensive surface after it untouched. A concept
    lookup goes through the index, which is the class of work that exceeds 60s on a cold fork.

    Each attempt is given the WHOLE remaining budget rather than a fixed slice, because the
    two failure shapes want opposite handling. A store that is merely slow needs one
    uninterrupted attempt: chopping it into 60-second tries aborts the same work repeatedly
    and never converges, which is what three retries did on run 30235793478. A server that
    is not listening yet fails immediately with a refused connection, costs almost nothing,
    and is retried after interval_s. A server that accepts and never answers consumes the
    budget once and then fails naming the deadline.

    RehearsalFailed is deliberately not caught: an application error means the store answered
    and said no. That is a real result and must surface, never be waited out. The probe's
    RESULT is deliberately not checked either - run_query_probes validates it a few lines
    later, and a readiness wait that also asserted correctness would conflate "not ready yet"
    with "wrong answer".

    The returned figure is a measurement, not a gate. This wait is NOT sufficient on its own:
    warming one concept lookup cannot warm the entity index, the read path, or the fuzzy path,
    so the cold paths also pass a per-probe budget to run_query_probes. Guessing which index
    faults first is the error this docstring exists to not repeat.
    """
    if timeout_s <= 0 or interval_s <= 0: raise RehearsalUnknown("invalid cold-query contract")
    started, deadline = time.monotonic(), time.monotonic() + timeout_s
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0: break
        try:
            client.call("muninn_find_by_concept", {"vault": vault, "concept": concept, "limit": 50},
                        timeout_s=remaining, attempts=1)
            return time.monotonic() - started
        except RehearsalUnknown:
            if time.monotonic() + interval_s >= deadline: break
            time.sleep(interval_s)
    raise RehearsalUnknown(f"cold data query did not answer within {timeout_s:.0f}s")

def query_count(client: MCPClient, vault: str) -> tuple[int, float]:
    result, latency = client.call("muninn_status", {"vault": vault})
    if not isinstance(result, dict): raise RehearsalFailed("invalid status envelope")
    for key in ("total_memories", "total_engrams", "memory_count", "engram_count"):
        if isinstance(result.get(key), int): return result[key], latency
    raise RehearsalUnknown("status count missing")

def query_counts(client: MCPClient) -> tuple[dict[str, int], list[float]]:
    counts, latencies = {}, []
    for vault in ("stage-a-primary", "stage-a-isolation"):
        counts[vault], latency = query_count(client, vault); latencies.append(latency)
    return counts, latencies

def result_ids(result: Any) -> list[str]:
    return [str(x["id"]) for x in result.get("engrams", []) if isinstance(x, dict) and x.get("id")] if isinstance(result, dict) else []

def verify_entity_ordering(result: Any, expected_newest: Sequence[str]) -> None:
    actual = result_ids(result)
    if actual != list(expected_newest):
        raise RehearsalFailed("capped entity results are incomplete or not newest-first")

def run_lifecycle_probes(client: MCPClient, receipt: CorpusReceipt) -> None:
    target = receipt.retained_ids["ordering"][0]
    before, _ = client.call("muninn_find_by_concept", {"vault": "stage-a-primary", "concept": "stage-a/concept/0042", "limit": 50})
    if target not in result_ids(before): raise RehearsalFailed("lifecycle target missing before mutation")
    client.call("muninn_state", {"vault": "stage-a-primary", "id": target, "state": "archived", "reason": "synthetic Stage A"})
    archived, _ = client.call("muninn_find_by_concept", {"vault": "stage-a-primary", "concept": "stage-a/concept/0042", "limit": 50})
    if target in result_ids(archived): raise RehearsalFailed("archived record remained indexed")
    client.call("muninn_state", {"vault": "stage-a-primary", "id": target, "state": "active", "reason": "synthetic Stage A restore"})
    client.call("muninn_forget", {"vault": "stage-a-primary", "id": target})
    forgotten, _ = client.call("muninn_find_by_concept", {"vault": "stage-a-primary", "concept": "stage-a/concept/0042", "limit": 50})
    if target in result_ids(forgotten): raise RehearsalFailed("soft-deleted record remained indexed")
    restored, _ = client.call("muninn_restore", {"vault": "stage-a-primary", "id": target})
    if not isinstance(restored, dict) or restored.get("restored") is not True: raise RehearsalFailed("soft-delete restore failed")

def baseline_read_witness(client: MCPClient, receipt: CorpusReceipt) -> Gate:
    """Point-read, on the ORIGINAL baseline machine, the exact ids run_query_probes reads later.

    The reason given for this gate when it was built was wrong and is withdrawn. It read run
    30290534176's `muninn_read(stage-a-primary): MCP JSON-RPC error code=-32000 message=tool
    error: engram not found` as the rollback fork denying an id its own indexes had just
    returned, and reasoned from run_query_probes' control flow accordingly. That detail came
    from the hard-delete check instead, where a failed read is the PASS condition, and the run
    never reached the rollback phase at all: hard_delete_cleanup, backup_restore and
    pre_migration_rollback are absent from its receipt and no fork volume was created. The
    cause was #74 collapsing tool errors into protocol errors, since fixed in _post.

    The gate is kept because its narrow claim is still worth a receipt and costs nothing.
    muninn_read is otherwise never exercised on the baseline machine - baseline_legacy_counts
    checks counts and baseline_status checks muninn_status - so a legacy image that could not
    point-read its own retained ids would have looked healthy. Measured on run 30302595011:
    PASSED, ok=2/2 at probe scale. The corrected topology gives the witness a direct role: it
    establishes that the untouched original is readable before the candidate clone is made,
    and the retained-original rollback repeats those reads after candidate qualification.

    It is a Gate rather than a raise, deliberately. A raise here would abort before candidate
    qualification and retained-original rollback, costing another dispatch to test the full
    topology; as a gate, one run reports every phase. It cannot hide a failure either:
    combine_status returns FAILED when ANY gate is FAILED, so a failed witness fails the run
    without truncating it. This is not an error being treated as a valid empty result - the
    server's own message is carried into the detail, and the gate goes FAILED.

    ok is recorded as a count because 0-of-10 and 9-of-10 are different defects: the first is a
    read path that resolves nothing, the second is one absent record. An empty id set fails
    rather than passes, since a witness that could not run must never read as evidence.
    """
    ids = receipt.retained_ids["ordering"][:BASELINE_READ_WITNESS_IDS]
    if not ids: return Gate("FAILED", "no retained ordering ids to point-read on the baseline", 0, 0)
    ok, first_error = 0, ""
    for memory_id in ids:
        try:
            client.call("muninn_read", {"vault": "stage-a-primary", "id": memory_id}); ok += 1
        except RehearsalError as exc:
            if not first_error: first_error = safe_detail(str(exc), JSON_RPC_DETAIL_CHARS)
    detail = f"baseline point-read of retained ordering ids ok={ok}/{len(ids)}"
    if first_error: detail = f"{detail} first_error={first_error}"
    return Gate("PASSED" if ok == len(ids) else "FAILED", detail, ok, len(ids))


def run_query_probes(client: MCPClient, receipt: CorpusReceipt, *,
                     timeout_s: float | None = None) -> dict[str, list[float]]:
    """Time the bounded query surface that the query_latency gate reads.

    `timeout_s` raises the per-call SOCKET budget without touching what is measured or
    judged. It defaults to None, so the gated candidate path keeps the client's 60 seconds
    exactly as before; the restore and rollback paths pass COLD_QUERY_LIMIT_S because each
    starts a fresh machine and exercises index and data paths that may not be warm. Three
    historical snapshot-fork runs died here on the 60-second default (30228878183,
    30235793478, 30270851093); operational rollback no longer uses that topology.

    Raising a socket budget cannot flatter a latency reading: the budget decides when to give
    up, and the timer records how long the answer actually took. It cannot loosen a gate
    either - the rollback and restore latencies are recorded but ungated, and the phase gates
    RESTORE_LIMIT_S and ROLLBACK_LIMIT_S still bound the total elapsed time of the phase, so
    a store slow enough to matter still fails on the limit that was chosen to judge it.

    The fuzzy probe used to take two samples, so its "p95" was arithmetically just the
    slower of two readings. Run 30206002340 failed the gate on it at 263.191 against a
    250ms limit; back-solving that run's reported p50 and max puts the two samples at
    245.77 and 264.11, straddling the threshold. Run 30202877942 drew 214.356 from the
    same two-sample instrument and passed. Neither run measured anything a percentile
    could be computed from, so neither says whether RC2 fuzzy latency is acceptable.

    The threshold is deliberately unchanged at 250ms. What changes is that the number is
    now measurable: every non-empty context, three passes, 24 samples. Repeats are
    interleaved a full cycle apart rather than run back to back, and because p95 is a tail
    statistic the warm repeats move the median without flattering the tail.

    This is a harder gate than the one it replaces, not a softer one. The old pair queried
    Entity 00 and Group 2, which match 2 and 1 records; the set below also queries
    Entity 42 and Group 0, which match 503 and 504. Those were never measured before, so a
    failure here is a real reading of a case the gate previously skipped.
    """
    samples: dict[str, list[float]] = {"exact": [], "entity": [], "read": [], "fuzzy": []}
    for index, concept in enumerate(COLLISION_CONCEPTS):
        result, latency = client.call("muninn_find_by_concept", {"vault": "stage-a-primary", "concept": concept, "limit": 50}, timeout_s=timeout_s)
        if result_ids(result) != [receipt.retained_ids["collision"][index]]: raise RehearsalFailed("collision hydration failed")
        samples["exact"].append(latency)
    for entity in ("Stage A Entity 00", "Stage A Entity 07", "Stage A Entity 42"):
        result, latency = client.call("muninn_find_by_entity", {"vault": "stage-a-primary", "entity_name": entity, "limit": 50}, timeout_s=timeout_s); samples["entity"].append(latency)
        if entity == "Stage A Entity 42": verify_entity_ordering(result, list(reversed(receipt.retained_ids["ordering"])))
    for memory_id in receipt.retained_ids["ordering"][:10]:
        _, latency = client.call("muninn_read", {"vault": "stage-a-primary", "id": memory_id}, timeout_s=timeout_s); samples["read"].append(latency)
    for _ in range(FUZZY_PASSES):
        for context in FUZZY_CONTEXTS:
            _, latency = client.call("muninn_recall", {"vault": "stage-a-primary", "context": list(context), "limit": 10}, timeout_s=timeout_s); samples["fuzzy"].append(latency)
    isolated_concept = "stage-a/isolation/0000097"
    cross, _ = client.call("muninn_find_by_concept", {"vault": "stage-a-primary", "concept": isolated_concept, "limit": 50}, timeout_s=timeout_s)
    if result_ids(cross): raise RehearsalFailed("vault isolation failed")
    isolated, _ = client.call("muninn_find_by_concept", {"vault": "stage-a-isolation", "concept": isolated_concept, "limit": 50}, timeout_s=timeout_s)
    if len(result_ids(isolated)) != 1: raise RehearsalFailed("isolated vault lookup failed")
    return samples

def plan(identity: RunIdentity, spec: CorpusSpec, *, mode: str = "execute") -> dict[str, Any]:
    # Each plan mode is held to its OWN corpus contract, so a plan can never render a
    # corpus its run would refuse. Without the probe branch, `--plan-mode execute`
    # rejects the 2,000-record probe corpus and the workflow cannot render its artifact.
    if mode == "tail-probe": validate_tail_probe_spec(spec)
    elif mode in {"calibrate", "ablate"}: validate_calibration_spec(spec)
    else: validate_execute_spec(spec)
    validate_image(BASELINE_IMAGE, "baseline"); validate_image(CANDIDATE_IMAGE, "candidate")
    validate_image(ROLLBACK_RESCUE_IMAGE, "rollback-rescue")
    result = {"mode": f"{mode}-plan", "run_id": identity.run_id, "confirmation_required_for_execute": identity.confirmation,
              "source_commit": SOURCE_COMMIT, "source_tag": SOURCE_TAG, "baseline_image": BASELINE_IMAGE,
              "baseline_digest": BASELINE_DIGEST, "candidate_image": CANDIDATE_IMAGE,
              "rollback_rescue_image": ROLLBACK_RESCUE_IMAGE,
              "rollback_rescue_digest": ROLLBACK_RESCUE_DIGEST,
              "rollback_rescue_provenance_sha256": ROLLBACK_RESCUE_PROVENANCE_SHA256,
              "record_count": spec.count, "batch_size": spec.batch_size,
              "payload_bytes": spec.payload_bytes, "payload_shape": spec.payload_shape, "volume_gb": VOLUME_SIZE_GB,
              "generated_resources": {"app": identity.app_name, "source_volume": identity.volume_name,
                                      "candidate_volume": identity.candidate_volume_name,
                                      "backup_volume": identity.backup_volume_name, "restore_volume": identity.restore_volume_name,
                                      "rollback_volume": "cleanup-compatibility-only"},
              "note": "plan-only: zero Fly mutations, credentials, network queries, or production access"}
    if mode == "execute":
        result["storage_qualification"] = {
            "method": "direct-same-volume-empty-to-settled-net-growth",
            "maximum_net_growth_bytes": MAX_STORE_BYTES,
            "maximum_peak_bytes": MAX_PEAK_BYTES,
            "minimum_free_percent": MIN_FREE_PERCENT,
        }
        result["snapshot_qualification"] = {
            "method": "completed-id-set-difference",
            "success_status": "created",
            "timeout_s": SNAPSHOT_LIMIT_S,
            "poll_interval_s": SNAPSHOT_POLL_INTERVAL_S,
            "already_scheduled_policy": "adopt-exactly-one-observed-in-flight-snapshot",
        }
        result["candidate_image_access"] = {
            "method": "digest-pinned-copy-into-run-owned-fly-registry-repository",
            "reason": "Fly holds no credential for the private source registry",
            "source": CANDIDATE_IMAGE,
            "target": f"{FLY_REGISTRY}/{identity.app_name}:{CANDIDATE_MIRROR_TAG}",
            "executed_reference": f"{FLY_REGISTRY}/{identity.app_name}:{CANDIDATE_MIRROR_TAG}",
            "required_digest": CANDIDATE_DIGEST,
            "digest_mismatch_policy": "UNKNOWN",
            "identity_binding": "crane digest of the mirror tag must equal the qualified digest before any machine launch",
            "launch_reference_form": "tag",
            "launch_reference_reason": "Fly machine-create rejects a digest-pinned config.image with 'invalid image identifier' (observed run 30165273639)",
            "ordering": "immediately after app creation, before any corpus ingestion",
            "scope": "run-owned app repository only; no shared or production repository is written",
        }
        result["rollback_rescue_image_access"] = {
            "method": "digest-pinned-copy-into-separate-run-owned-fly-registry-tag",
            "reason": "retained-original rollback requires the separately qualified rescue reader, while Fly launches tags",
            "source": ROLLBACK_RESCUE_IMAGE,
            "target": f"{FLY_REGISTRY}/{identity.app_name}:{ROLLBACK_RESCUE_MIRROR_TAG}",
            "executed_reference": f"{FLY_REGISTRY}/{identity.app_name}:{ROLLBACK_RESCUE_MIRROR_TAG}",
            "required_digest": ROLLBACK_RESCUE_DIGEST,
            "digest_mismatch_policy": "UNKNOWN",
            "identity_binding": "crane digest of the rollback-rescue mirror tag must equal the qualified digest before any measured work",
            "role": "retained-original rollback rescue reader",
            "source_commit": ROLLBACK_RESCUE_SOURCE_COMMIT,
            "patch_commit": ROLLBACK_RESCUE_PATCH_COMMIT,
            "provenance_sha256": ROLLBACK_RESCUE_PROVENANCE_SHA256,
            "build_run_id": ROLLBACK_RESCUE_BUILD_RUN_ID,
            "scope": "separate tag in the run-owned app repository only; never candidate or baseline identity",
        }
        result["provisioning_probe"] = {
            "purpose": "surface candidate image and guest provisioning faults before the corpus ingest, not after it",
            "ordering": "immediately after the mirror digest assertion, before any volume or measured machine exists",
            "shape": "mountless machine using the same guest spec as every real machine, held briefly for one exec canary, then destroyed",
            "mounts": "none, so the measured source volume cannot be written before its empty disk sample",
            "exec_canary": "runs the same shell wrapping and quoting the migration resource sample uses, and requires the exact expected output",
            "failure_policy": "UNKNOWN",
            "coverage_limit": "image resolution, guest sizing, machine create and boot, and the machine exec shell transport only; volume attachment and the resource measurement itself are not covered",
            "gate_effect": "none; no gate is added, removed, or relaxed",
        }
        result["falsification_evidence"] = {
            "run_id": FALSIFICATION_RUN_ID,
            "receipt_sha256": FALSIFICATION_RECEIPT_SHA256,
            "finding": "fixed-record-count payload cohorts cannot identify fixed per-record overhead",
        }
        result["count_qualification"] = {
            "logical_counts": logical_vault_counts(spec),
            "baseline_exact_legacy_fingerprint": legacy_baseline_counts(spec),
            "candidate_requires_exact_logical_counts": True,
        }
        result["rollback_qualification"] = {
            "topology": "retained-running-machine-and-original-volume",
            "candidate_source": "stable clone of the completed pre-migration snapshot",
            "operational_rollback": "the allocated baseline Machine stays running after graceful server quiescence, then is updated in place to the separately qualified rollback-rescue reader on the untouched original volume",
            "rollback_rescue_image": ROLLBACK_RESCUE_IMAGE,
            "rollback_rescue_digest": ROLLBACK_RESCUE_DIGEST,
            "rollback_rescue_provenance_sha256": ROLLBACK_RESCUE_PROVENANCE_SHA256,
            "disaster_recovery": "candidate archive restore is qualified separately",
            "legacy_rollback_volume": "cleanup compatibility only; never created by execute",
        }
        result["limitations"] = [
            "Synthetic rehearsal is not production deployment authorization.",
            "Production data, backups, volumes, machines, app, and credentials are prohibited.",
            "The bounded df quiet-window witnesses disk settlement; it does not prove asynchronous FTS or provenance queues are empty.",
        ]
    return result

def calibrate(
    identity: RunIdentity,
    spec: CorpusSpec,
    receipt_path: Path,
    *,
    runtime: FlyRuntime | None = None,
    client_factory: Callable[[str, str], MCPClient] | None = None,
    local_port: int = 18750,
) -> int:
    runtime = runtime or FlyRuntime(); client_factory = client_factory or (lambda url, auth: MCPClient(url, auth))
    ledger, proxy = ResourceLedger(), None
    gates: dict[str, Gate] = {}; measurements: dict[str, Any] = {"disk_samples": [], "latencies": {}}
    corpus_receipt: CorpusReceipt | IngestProgress | None = None
    cleanup_result: dict[str, str] = {}; orphans: list[str] = []
    detail, status, exit_code = "calibration did not complete", "UNKNOWN", 2
    auth_value = secrets.token_urlsafe(32)
    try:
        validate_calibration_spec(spec); validate_image(BASELINE_IMAGE, "baseline"); runtime.preflight(identity)
        ledger.app = runtime.create_app(identity); runtime.install_auth(identity, auth_value)

        def ingest_independent_cohort(
            cohort_spec: CorpusSpec,
            cohort: str,
            port: int,
        ) -> tuple[DiskSample, DiskSample, CorpusReceipt]:
            nonlocal corpus_receipt, proxy
            ledger.volume_id = runtime.create_volume(identity, identity.volume_name)
            ledger.machine_id = runtime.create_machine(identity, ledger.volume_id, BASELINE_IMAGE, "baseline")
            runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
            empty = runtime.disk_sample(identity, ledger.machine_id, f"calibration-{cohort}-empty")
            measurements["disk_samples"].append(asdict(empty) | {"free_percent": empty.free_percent})
            proxy = runtime.proxy(identity, ledger.machine_id, port)
            client = client_factory(f"http://127.0.0.1:{port}/mcp", auth_value); client.initialize()

            def checkpoint(progress: IngestProgress) -> None:
                nonlocal corpus_receipt
                corpus_receipt = progress
                sample = runtime.disk_sample(identity, ledger.machine_id or "", f"calibration-{cohort}-ingestion")
                require_disk_safety(sample)
                measurements["latest_disk_sample"] = asdict(sample) | {"free_percent": sample.free_percent}
                write_receipt(receipt_path, receipt_document(
                    identity, spec, status="UNKNOWN", exit_code=2,
                    detail=f"calibration {cohort} ingestion in progress",
                    ledger=ledger, measurements=measurements, gates=gates, cleanup_result={}, orphans=[],
                    corpus=progress, mode="calibrate",
                ))

            cohort_receipt = ingest_corpus(
                client, cohort_spec, minimum_count=CALIBRATION_SAMPLE_COUNT, progress=checkpoint,
            )
            corpus_receipt = cohort_receipt
            populated = runtime.disk_sample(identity, ledger.machine_id, f"calibration-{cohort}-populated")
            require_disk_safety(populated)
            measurements["disk_samples"].append(asdict(populated) | {"free_percent": populated.free_percent})
            terminate_proxy(proxy); proxy = None
            return empty, populated, cohort_receipt

        low_empty, low_populated, low_receipt = ingest_independent_cohort(spec, "low", local_port)
        measurements["low_sample"] = corpus_evidence(spec, low_receipt)
        runtime.destroy_machine(identity, ledger.machine_id or ""); ledger.machine_id = None
        runtime.destroy_volume(identity, ledger.volume_id or ""); ledger.volume_id = None

        high_spec = CorpusSpec(
            CALIBRATION_SAMPLE_COUNT, spec.batch_size, CALIBRATION_HIGH_PAYLOAD_BYTES,
            f"{spec.seed}-high",
        )
        high_empty, high_populated, high_receipt = ingest_independent_cohort(
            high_spec, "high", local_port + 1,
        )
        projection = calibration_projection(low_empty, low_populated, high_empty, high_populated)
        measurements["calibration"] = projection
        measurements["high_sample"] = corpus_evidence(high_spec, high_receipt)
        if projection["projected_minimum_bytes"] > MAX_STORE_BYTES:
            gates["minimum_payload_projection"] = Gate(
                "FAILED", "minimum payload projects above maximum Stage A footprint",
                projection["projected_minimum_bytes"], MAX_STORE_BYTES,
            )
            detail = "minimum-payload calibration requires synthetic record-shape reduction"
        elif projection["recommended_payload_bytes"] is None:
            gates["payload_recommendation"] = Gate("UNKNOWN", "calibrated payload recommendation is out of bounds")
            detail = "calibration could not produce a bounded payload recommendation"
        else:
            gates["payload_recommendation"] = Gate(
                "PASSED", "bounded payload recommendation measured; full Stage A not run",
                projection["recommended_payload_bytes"], MAX_PAYLOAD_BYTES,
            )
            detail = "calibration completed; full Stage A remains separately gated"
        status = combine_status(gates, [])
        exit_code = 0 if status == "PASSED" else (1 if status == "FAILED" else 2)
    except RehearsalError as exc: status, exit_code, detail = exc.status, 1 if exc.status == "FAILED" else 2, safe_detail(str(exc), RECEIPT_DETAIL_CHARS)
    except Exception as exc: status, exit_code, detail = "UNKNOWN", 2, f"unexpected {type(exc).__name__}"
    finally:
        try: terminate_proxy(proxy)
        except RehearsalError: status, exit_code, detail = "UNKNOWN", 2, "local proxy cleanup uncertain"
        cleanup_result, orphans = cleanup(runtime, identity, ledger)
        if orphans: status, exit_code, detail = "UNKNOWN", 2, with_cleanup_concern(detail, orphans)
        write_receipt(receipt_path, receipt_document(
            identity, spec, status=status, exit_code=exit_code, detail=detail, ledger=ledger,
            measurements=measurements, gates=gates, cleanup_result=cleanup_result,
            orphans=orphans, corpus=corpus_receipt, mode="calibrate",
        ))
    return exit_code

def ablate(
    identity: RunIdentity,
    spec: CorpusSpec,
    receipt_path: Path,
    *,
    runtime: FlyRuntime | None = None,
    client_factory: Callable[[str, str], MCPClient] | None = None,
    local_port: int = 18750,
) -> int:
    runtime = runtime or FlyRuntime(); client_factory = client_factory or (lambda url, auth: MCPClient(url, auth))
    ledger, proxy = ResourceLedger(), None
    gates: dict[str, Gate] = {}; measurements: dict[str, Any] = {"cohorts": {}, "disk_samples": []}
    corpus_receipt: CorpusReceipt | IngestProgress | None = None
    receipt_spec = spec
    cleanup_result: dict[str, str] = {}; orphans: list[str] = []
    detail, status, exit_code = "storage ablation did not complete", "UNKNOWN", 2
    auth_value = secrets.token_urlsafe(32)
    samples: dict[str, tuple[int, int]] = {}
    try:
        validate_calibration_spec(spec); validate_image(BASELINE_IMAGE, "baseline"); runtime.preflight(identity)
        ledger.app = runtime.create_app(identity); runtime.install_auth(identity, auth_value)
        for offset, (cohort, shape, payload_bytes) in enumerate(ABLATION_COHORTS):
            cohort_spec = CorpusSpec(
                CALIBRATION_SAMPLE_COUNT, spec.batch_size, payload_bytes,
                f"{spec.seed}-{cohort}", shape,
            )
            receipt_spec = cohort_spec
            ledger.volume_id = runtime.create_volume(identity, identity.volume_name)
            ledger.machine_id = runtime.create_machine(identity, ledger.volume_id, BASELINE_IMAGE, "baseline")
            runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
            empty = runtime.disk_sample(identity, ledger.machine_id, f"ablation-{cohort}-empty")
            require_disk_safety(empty)
            proxy = runtime.proxy(identity, ledger.machine_id, local_port + offset)
            client = client_factory(f"http://127.0.0.1:{local_port + offset}/mcp", auth_value); client.initialize()

            def checkpoint(progress: IngestProgress) -> None:
                nonlocal corpus_receipt
                corpus_receipt = progress
                write_receipt(receipt_path, receipt_document(
                    identity, spec, status="UNKNOWN", exit_code=2,
                    detail=f"ablation {cohort} ingestion in progress", ledger=ledger,
                    measurements=measurements, gates=gates, cleanup_result={}, orphans=[],
                    corpus=progress, mode="ablate",
                ))

            cohort_receipt = ingest_corpus(
                client, cohort_spec, minimum_count=CALIBRATION_SAMPLE_COUNT, progress=checkpoint,
            )
            corpus_receipt, receipt_spec = cohort_receipt, cohort_spec
            immediate = runtime.disk_sample(identity, ledger.machine_id, f"ablation-{cohort}-immediate")
            require_disk_safety(immediate)
            quiet = wait_for_storage_quiet(runtime, identity, ledger.machine_id, f"ablation-{cohort}")
            settled = quiet["settled"]
            samples[cohort] = (empty.used_bytes, settled.used_bytes)
            measurements["cohorts"][cohort] = {
                "payload_shape": shape,
                "payload_bytes": payload_bytes,
                "empty": asdict(empty) | {"free_percent": empty.free_percent},
                "immediate": asdict(immediate) | {"free_percent": immediate.free_percent},
                "settled": asdict(settled) | {"free_percent": settled.free_percent},
                "settlement_samples": [asdict(item) | {"free_percent": item.free_percent} for item in quiet["samples"]],
                "settlement_witness": quiet["witness"],
                "corpus": corpus_evidence(cohort_spec, cohort_receipt),
            }
            terminate_proxy(proxy); proxy = None
            runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
            runtime.destroy_volume(identity, ledger.volume_id); ledger.volume_id = None
        measurements["ablation"] = ablation_projection(samples)
        gates["ablation_evidence"] = Gate("PASSED", "four independent settled baseline cohorts measured", len(samples), len(ABLATION_COHORTS))
        status, exit_code = "PASSED", 0
        detail = "storage ablation completed; full Stage A was not run"
    except RehearsalError as exc: status, exit_code, detail = exc.status, 1 if exc.status == "FAILED" else 2, safe_detail(str(exc), RECEIPT_DETAIL_CHARS)
    except Exception as exc: status, exit_code, detail = "UNKNOWN", 2, f"unexpected {type(exc).__name__}"
    finally:
        try: terminate_proxy(proxy)
        except RehearsalError: status, exit_code, detail = "UNKNOWN", 2, "local proxy cleanup uncertain"
        cleanup_result, orphans = cleanup(runtime, identity, ledger)
        if orphans: status, exit_code, detail = "UNKNOWN", 2, with_cleanup_concern(detail, orphans)
        write_receipt(receipt_path, receipt_document(
            identity, receipt_spec, status=status, exit_code=exit_code, detail=detail, ledger=ledger,
            measurements=measurements, gates=gates, cleanup_result=cleanup_result,
            orphans=orphans, corpus=corpus_receipt, mode="ablate",
        ))
    return exit_code

def execute(identity: RunIdentity, spec: CorpusSpec, receipt_path: Path, *, runtime: FlyRuntime | None = None,
            client_factory: Callable[[str, str], MCPClient] | None = None, local_port: int = 18750,
            probe: bool = False) -> int:
    """Run every Stage A phase. With probe=True, run them against a probe-scale corpus.

    Fifteen rehearsals died one defect at a time because the tail phases - backup, volume
    snapshot, fork, restore and rollback - are only ever reached after a roughly 50-minute
    ingest of 502,385 records, so each tail defect cost a full run to find. The probe runs
    the identical code path against 2,000 records, which puts the same faults minutes from
    the start instead of an hour. It is the tail counterpart of `provisioning_probe`, which
    already does this for the phases BEFORE the ingest, and it relaxes nothing: the four
    corpus-scale gates are recorded SKIPPED rather than loosened, and the probe's own status
    can never be PASSED, so the workflow's verdict step cannot accept it as qualification.
    """
    runtime = runtime or FlyRuntime(); client_factory = client_factory or (lambda url, auth: MCPClient(url, auth))
    ledger, proxy = ResourceLedger(), None
    gates: dict[str, Gate] = {}; measurements: dict[str, Any] = {"disk_samples": [], "latencies": {}}
    corpus_receipt: CorpusReceipt | None = None; cleanup_result: dict[str, str] = {}; orphans: list[str] = []
    candidate_ref, rollback_rescue_ref = CANDIDATE_IMAGE, ROLLBACK_RESCUE_IMAGE
    detail, status, exit_code = "rehearsal did not complete", "UNKNOWN", 2
    auth_value = secrets.token_urlsafe(32)
    try:
        validate_tail_probe_spec(spec) if probe else validate_execute_spec(spec)
        validate_image(BASELINE_IMAGE, "baseline"); validate_image(CANDIDATE_IMAGE, "candidate")
        validate_image(ROLLBACK_RESCUE_IMAGE, "rollback-rescue"); runtime.preflight(identity)
        ledger.app = runtime.create_app(identity)
        candidate_ref = runtime.mirror_candidate(identity)
        rollback_rescue_ref = runtime.mirror_rollback_rescue(identity)
        runtime.install_auth(identity, auth_value)
        ledger.machine_id = runtime.provisioning_probe(identity, candidate_ref)
        runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
        runtime.exec_canary(identity, ledger.machine_id)
        runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        ledger.volume_id = runtime.create_volume(identity, identity.volume_name)
        ledger.retained_machine_id = runtime.create_machine(
            identity, ledger.volume_id, BASELINE_IMAGE, "retained-baseline")
        runtime.wait_ready(identity, ledger.retained_machine_id, READINESS_LIMIT_S)
        empty = runtime.disk_sample(identity, ledger.retained_machine_id, "baseline-empty")
        require_disk_safety(empty)
        measurements["disk_samples"].append(asdict(empty) | {"free_percent": empty.free_percent})
        proxy = runtime.proxy(identity, ledger.retained_machine_id, local_port)
        client = client_factory(f"http://127.0.0.1:{local_port}/mcp", auth_value); client.initialize()
        # A serving baseline is the only point in the run where a MuninnDB process is known
        # to exist, so it is the only place the resource measurement can be witnessed rather
        # than assumed. It never was: resource_sample is called nowhere but migration_samples,
        # so runs 30183128792 and 30185035316 each paid a full corpus ingest to discover that
        # the measurement could not read a process at all. Taking one here fails a broken
        # measurement in minutes, against roughly 2.2 hours at the candidate transition, and
        # it distinguishes a broken measurement from a candidate that never starts.
        measurements["baseline_resource_sample"] = asdict(runtime.resource_sample(
            identity, ledger.retained_machine_id, "baseline-serving"))
        def checkpoint(progress: IngestProgress) -> None:
            nonlocal corpus_receipt
            corpus_receipt = progress
            sample = runtime.disk_sample(
                identity, ledger.retained_machine_id or "", "baseline-ingestion")
            require_disk_safety(sample)
            measurements["latest_disk_sample"] = asdict(sample) | {"free_percent": sample.free_percent}
            write_receipt(receipt_path, receipt_document(
                identity, spec, status="UNKNOWN", exit_code=2, detail="baseline ingestion in progress",
                ledger=ledger, measurements=measurements, gates=gates, cleanup_result={}, orphans=[],
                corpus=progress, candidate_ref=candidate_ref, rollback_rescue_ref=rollback_rescue_ref,
            ))
        # `ingest_corpus` re-validates the corpus through `iter_records`, whose own floor
        # defaults to the FULL qualification count. Passing the entry contract at the top
        # of this function is not enough: run 30225546284 provisioned, launched the
        # baseline, and then refused its own probe corpus here with "record count below
        # required scale". calibrate and ablate already thread their floor the same way.
        corpus_receipt = ingest_corpus(
            client, spec,
            minimum_count=TAIL_PROBE_SAMPLE_COUNT if probe else MIN_RECORD_COUNT,
            progress=checkpoint,
        )
        immediate = runtime.disk_sample(
            identity, ledger.retained_machine_id, "baseline-immediate")
        require_disk_safety(immediate)
        measurements["disk_samples"].append(asdict(immediate) | {"free_percent": immediate.free_percent})
        quiet = wait_for_storage_quiet(
            runtime, identity, ledger.retained_machine_id, "baseline-storage")
        settled = quiet["settled"]
        measurements["disk_samples"].extend(
            asdict(sample) | {"free_percent": sample.free_percent}
            for sample in quiet["samples"]
        )
        measurements["storage_settlement_witness"] = quiet["witness"]
        measurements["direct_net_store_growth_bytes"] = settled.used_bytes - empty.used_bytes
        gates["store_footprint"] = scale_gate(probe, direct_store_growth_gate(empty, settled), "store footprint")
        baseline_counts, status_samples = query_counts(client); measurements["baseline_counts"] = baseline_counts
        gates["baseline_status"] = threshold_gate("baseline status", max(status_samples) / 1000, STATUS_LIMIT_S)
        require_legacy_baseline_counts(baseline_counts, spec)
        gates["baseline_legacy_counts"] = Gate(
            "PASSED",
            f"immutable baseline matched exact legacy fingerprint={baseline_counts}",
            sum(baseline_counts.values()),
            spec.count + spec.batch_size + 1,
        )
        gates["baseline_read_witness"] = baseline_read_witness(client, corpus_receipt)
        terminate_proxy(proxy); proxy = None
        runtime.quiesce_baseline(identity, ledger.retained_machine_id)
        ledger.snapshot_id = runtime.snapshot(identity, ledger.volume_id)
        clone_started = time.monotonic()
        ledger.candidate_volume_id = runtime.create_volume(
            identity,
            identity.candidate_volume_name,
            snapshot_id=ledger.snapshot_id,
        )
        measurements["candidate_clone_to_stable_s"] = time.monotonic() - clone_started
        measurements["volume_topology"] = {
            "candidate_source": "pre-migration-snapshot",
            "pre_migration_snapshot_id": ledger.snapshot_id,
            "original_volume_id": ledger.volume_id,
            "candidate_volume_id": ledger.candidate_volume_id,
            "operational_rollback": "retained-running-machine-updated-in-place",
            "retained_machine_id": ledger.retained_machine_id,
            "legacy_rollback_volume": "not_created",
        }
        migration_started = time.monotonic(); ledger.machine_id = runtime.create_machine(
            identity, ledger.candidate_volume_id, candidate_ref, "candidate")
        candidate_ready, migration_disks, migration_resources = runtime.migration_samples(identity, ledger.machine_id, MIGRATION_LIMIT_S)
        migration_s = time.monotonic() - migration_started
        measurements["disk_samples"].extend(asdict(sample) | {"free_percent": sample.free_percent} for sample in migration_disks)
        measurements["migration_resources"] = [asdict(sample) for sample in migration_resources]
        gates["migration_duration"] = scale_gate(probe, threshold_gate("migration duration", migration_s, MIGRATION_LIMIT_S), "migration duration")
        readiness_started = time.monotonic(); proxy = runtime.proxy(identity, ledger.machine_id, local_port); candidate = client_factory(f"http://127.0.0.1:{local_port}/mcp", auth_value); candidate.initialize()
        _, readiness_status_ms = query_count(candidate, "stage-a-primary")
        readiness_s = time.monotonic() - readiness_started
        measurements["candidate_readiness_s"] = readiness_s
        gates["candidate_readiness"] = threshold_gate("candidate readiness after migration", readiness_s, READINESS_LIMIT_S)
        gates["candidate_status"] = threshold_gate("candidate status", readiness_status_ms / 1000, STATUS_LIMIT_S)
        migrated_counts, _ = query_counts(candidate)
        logical_counts = logical_vault_counts(spec)
        measurements["candidate_counts"] = migrated_counts
        gates["candidate_logical_counts"] = Gate(
            "PASSED" if migrated_counts == logical_counts else "FAILED",
            f"logical={logical_counts} candidate={migrated_counts}",
            sum(migrated_counts.values()),
            spec.count,
        )
        samples = run_query_probes(candidate, corpus_receipt); run_lifecycle_probes(candidate, corpus_receipt)
        gates["semantic_probes"] = Gate("PASSED", "exact-concept, entity ordering, vault isolation, collision hydration, lifecycle filtering, and fuzzy reads passed")
        measurements["latencies"] = {name: latency_summary(values) for name, values in samples.items()}
        gross_p95 = max(summary["p95_ms"] or 0 for summary in measurements["latencies"].values() if summary["count"])
        baseline_p50 = transport_baseline_ms(measurements["latencies"])
        net_p95 = None if baseline_p50 is None else round(gross_p95 - baseline_p50, 3)
        # Gross and baseline are both recorded, so the subtraction is auditable from the
        # receipt and a slow tunnel stays visible rather than being silently absorbed. A
        # missing baseline yields None, which threshold_gate records UNKNOWN, never a pass.
        measurements["query_transport"] = {"gross_p95_ms": gross_p95, "baseline_p50_ms": baseline_p50,
                                           "net_p95_ms": net_p95, "gross_limit_ms": QUERY_P95_LIMIT_MS,
                                           "net_limit_ms": QUERY_NET_P95_LIMIT_MS,
                                           "transport_retries": candidate.transport_retries}
        gates["query_latency"] = scale_gate(probe, threshold_gate("bounded query net p95", net_p95, QUERY_NET_P95_LIMIT_MS), "bounded query net p95")
        post = runtime.disk_sample(identity, ledger.machine_id, "post-migration"); measurements["disk_samples"].append(asdict(post) | {"free_percent": post.free_percent})
        all_disk_samples = [empty, immediate, *quiet["samples"], *migration_disks, post]
        gates["disk_headroom"] = scale_gate(probe, disk_gate(all_disk_samples), "disk headroom")
        gates["resource_sampling"] = Gate("PASSED" if migration_resources else "UNKNOWN", "migration CPU and RSS samples captured", len(migration_resources))
        terminate_proxy(proxy); proxy = None; runtime.stop_machine(identity, ledger.machine_id); runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        ledger.machine_id = runtime.create_machine(identity, ledger.candidate_volume_id, candidate_ref, "clean-restart"); runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
        runtime.stop_machine(identity, ledger.machine_id, force=True); runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        ledger.machine_id = runtime.create_machine(identity, ledger.candidate_volume_id, candidate_ref, "crash-restart"); runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
        gates["restart_durability"] = Gate("PASSED", "clean and forced-crash restarts reached readiness")
        runtime.stop_machine(identity, ledger.machine_id); runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        hard_delete_id = corpus_receipt.retained_ids["hard_delete"][0]
        hard_delete_helper = runtime.hard_delete(identity, ledger.candidate_volume_id, candidate_ref, "stage-a-primary", hard_delete_id)
        ledger.machine_id = hard_delete_helper; runtime.wait_stopped(identity, hard_delete_helper, READINESS_LIMIT_S)
        runtime.destroy_machine(identity, hard_delete_helper); ledger.machine_id = None
        ledger.machine_id = runtime.create_machine(identity, ledger.candidate_volume_id, candidate_ref, "hard-delete-check"); runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
        proxy = runtime.proxy(identity, ledger.machine_id, local_port); hard_delete_client = client_factory(f"http://127.0.0.1:{local_port}/mcp", auth_value); hard_delete_client.initialize()
        deleted_concept, _ = hard_delete_client.call("muninn_find_by_concept", {"vault": "stage-a-primary", "concept": "stage-a/concept/0043", "limit": 50})
        deleted_entity, _ = hard_delete_client.call("muninn_find_by_entity", {"vault": "stage-a-primary", "entity_name": "Stage A Entity 43", "limit": 50})
        if hard_delete_id in result_ids(deleted_concept) or hard_delete_id in result_ids(deleted_entity): raise RehearsalFailed("hard-deleted record remained indexed")
        try: hard_delete_client.call("muninn_read", {"vault": "stage-a-primary", "id": hard_delete_id})
        # A read that fails is the PASS condition here, which makes this the one place in the
        # harness where an error is deliberately treated as evidence. A protocol error is not
        # evidence of deletion - it means the question was never answered - so it is re-raised
        # rather than counted as proof. Ordered before the general clause because
        # RehearsalProtocolFailed IS a RehearsalFailed and would otherwise be swallowed by it.
        #
        # The expected answer here is RehearsalToolFailed: a purged record reads back
        # `code=-32000 message=tool error: engram not found`, which is the server saying the
        # record is gone. That class is a SIBLING of RehearsalProtocolFailed, so it lands on the
        # general clause below and counts as proof, with no branch of its own. This ordering is
        # therefore only correct while _post classifies by code - when #74 raised
        # RehearsalProtocolFailed for every error object, the narrowed clause swallowed the PASS
        # condition and killed runs 30290534176 and 30302595011 here, three gates short of the
        # rollback phase they were dispatched to measure.
        except RehearsalProtocolFailed: raise
        except RehearsalFailed: pass
        else: raise RehearsalFailed("hard-deleted record remained readable")
        hard_delete_counts, _ = query_counts(hard_delete_client); terminate_proxy(proxy); proxy = None
        expected_after_delete = dict(logical_counts); expected_after_delete["stage-a-primary"] -= 1
        if hard_delete_counts != expected_after_delete: raise RehearsalFailed("hard-delete count delta was not exactly one")
        gates["hard_delete_cleanup"] = Gate("PASSED", "offline hard delete removed primary and reverse-index reachability")
        runtime.stop_machine(identity, ledger.machine_id); runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        backup_started = time.monotonic()
        backup_helper, backup_path = runtime.create_backup(identity, ledger.candidate_volume_id, candidate_ref)
        ledger.machine_id = backup_helper; runtime.wait_stopped(identity, backup_helper, RESTORE_LIMIT_S)
        measurements["backup_duration_s"] = time.monotonic() - backup_started
        runtime.destroy_machine(identity, backup_helper); ledger.machine_id = None
        restore_started = time.monotonic()
        # The archive is on the source volume, and a Fly machine mounts one volume, so it
        # reaches the restore volume by fork rather than by a second mount. The restore
        # helper then deletes the forked store and rebuilds it from the archive alone.
        backup_snapshot_id = runtime.snapshot(identity, ledger.candidate_volume_id)
        measurements["backup_snapshot_id"] = backup_snapshot_id
        ledger.restore_volume_id = runtime.create_volume(identity, identity.restore_volume_name, snapshot_id=backup_snapshot_id)
        restore_helper = runtime.create_restore(identity, ledger.restore_volume_id, candidate_ref, backup_path)
        ledger.machine_id = restore_helper; runtime.wait_stopped(identity, restore_helper, RESTORE_LIMIT_S)
        runtime.destroy_machine(identity, restore_helper); ledger.machine_id = None
        ledger.machine_id = runtime.create_machine(identity, ledger.restore_volume_id, candidate_ref, "restore"); runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
        measurements["backup"] = runtime.backup_measurement(identity, ledger.machine_id)
        proxy = runtime.proxy(identity, ledger.machine_id, local_port); restore_client = client_factory(f"http://127.0.0.1:{local_port}/mcp", auth_value); restore_client.initialize()
        measurements["restore_cold_query_s"] = wait_cold_query(restore_client, "stage-a-primary")
        restored_counts, _ = query_counts(restore_client); restored_samples = run_query_probes(restore_client, corpus_receipt, timeout_s=COLD_QUERY_LIMIT_S); terminate_proxy(proxy); proxy = None
        if restored_counts != expected_after_delete: raise RehearsalFailed("restored counts differ from backup source")
        measurements["restored_latencies"] = {name: latency_summary(values) for name, values in restored_samples.items()}
        measurements["restore_to_query_s"] = time.monotonic() - restore_started; gates["backup_restore"] = threshold_gate("restore-to-query", measurements["restore_to_query_s"], RESTORE_LIMIT_S)
        runtime.stop_machine(identity, ledger.machine_id); runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        rollback_started = time.monotonic()
        runtime.update_machine(
            identity, ledger.retained_machine_id, ledger.volume_id, rollback_rescue_ref, "rollback")
        runtime.wait_ready(identity, ledger.retained_machine_id, READINESS_LIMIT_S)
        proxy = runtime.proxy(identity, ledger.retained_machine_id, local_port); rollback_client = client_factory(f"http://127.0.0.1:{local_port}/mcp", auth_value); rollback_client.initialize()
        measurements["rollback_cold_query_s"] = wait_cold_query(rollback_client, "stage-a-primary")
        rollback_counts, _ = query_counts(rollback_client); rollback_samples = run_query_probes(rollback_client, corpus_receipt, timeout_s=COLD_QUERY_LIMIT_S); terminate_proxy(proxy); proxy = None
        require_legacy_baseline_counts(rollback_counts, spec)
        measurements["rollback_counts"] = {
            "behavior": "exact-known-legacy-fingerprint",
            "counts": rollback_counts,
        }
        measurements["rollback_latencies"] = {name: latency_summary(values) for name, values in rollback_samples.items()}
        measurements["rollback_check_s"] = time.monotonic() - rollback_started
        gates["pre_migration_rollback"] = threshold_gate(
            "retained-original pre-migration rollback",
            measurements["rollback_check_s"],
            ROLLBACK_LIMIT_S,
        )
        detail = "all measured Stage A phases completed"
    except RehearsalError as exc: status, exit_code, detail = exc.status, 1 if exc.status == "FAILED" else 2, safe_detail(str(exc), RECEIPT_DETAIL_CHARS)
    except Exception as exc: status, exit_code, detail = "UNKNOWN", 2, f"unexpected {type(exc).__name__}"
    finally:
        try: terminate_proxy(proxy)
        except RehearsalError: status, exit_code, detail = "UNKNOWN", 2, "local proxy cleanup uncertain"
        cleanup_result, orphans = cleanup(runtime, identity, ledger); computed = combine_status(gates, orphans, probe=probe)
        if detail == "all measured Stage A phases completed": status, exit_code = computed, 0 if computed == "PASSED" else (1 if computed == "FAILED" else 2)
        if orphans: status, exit_code, detail = "UNKNOWN", 2, with_cleanup_concern(detail, orphans)
        if probe and status == "PASSED":
            # A probe proves the tail executes, never that the candidate qualifies: it
            # ingested 2,000 records and did not judge four gates. Renaming the success
            # is what keeps the workflow's `receipt.status == "PASSED"` check honest.
            status, detail = "TAIL_PROBE_PASS", f"{detail} at probe scale; four corpus-scale gates not judged"
        write_receipt(receipt_path, receipt_document(
            identity, spec, status=status, exit_code=exit_code, detail=detail, ledger=ledger,
            measurements=measurements, gates=gates, cleanup_result=cleanup_result,
            orphans=orphans, corpus=corpus_receipt, candidate_ref=candidate_ref,
            rollback_rescue_ref=rollback_rescue_ref,
            mode="tail_probe" if probe else "execute",
        ))
    return exit_code

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__); mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    mode.add_argument("--calibrate", action="store_true")
    mode.add_argument("--ablate", action="store_true")
    mode.add_argument("--tail-probe", action="store_true")
    mode.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--run-id", required=True); parser.add_argument("--confirm"); parser.add_argument("--record-count", type=int)
    parser.add_argument("--plan-mode", choices=("execute", "calibrate", "ablate", "tail-probe"), default="execute")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE); parser.add_argument("--payload-bytes", type=int)
    parser.add_argument("--seed", default="koala-stage-a-v1"); parser.add_argument("--receipt", type=Path, default=Path("stage-a-receipt.json")); parser.add_argument("--json", action="store_true")
    return parser

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        identity = build_identity(args.run_id)
        probing = args.tail_probe or (args.dry_run and args.plan_mode == "tail-probe")
        calibrating = args.calibrate or args.ablate or (args.dry_run and args.plan_mode in {"calibrate", "ablate"})
        default_count = TAIL_PROBE_SAMPLE_COUNT if probing else (CALIBRATION_SAMPLE_COUNT if calibrating else DEFAULT_RECORD_COUNT)
        spec = CorpusSpec(
            args.record_count if args.record_count is not None else default_count,
            args.batch_size,
            args.payload_bytes if args.payload_bytes is not None else (CALIBRATION_LOW_PAYLOAD_BYTES if calibrating else DEFAULT_PAYLOAD_BYTES),
            args.seed,
            "opaque" if calibrating else DEFAULT_PAYLOAD_SHAPE,
        )
        if not (args.execute or args.calibrate or args.ablate or args.tail_probe or args.cleanup_only):
            print(json.dumps(plan(identity, spec, mode=args.plan_mode), indent=2 if args.json else None, sort_keys=True)); return 0
        if args.confirm != identity.confirmation:
            print("REFUSED: mutating mode requires the exact run-specific confirmation", file=sys.stderr); print(f"Required confirmation: {identity.confirmation}", file=sys.stderr); return 2
        install_termination_handlers()
        if args.cleanup_only: return cleanup_only(identity, args.receipt)
        if args.calibrate: return calibrate(identity, spec, args.receipt)
        if args.ablate: return ablate(identity, spec, args.receipt)
        return execute(identity, spec, args.receipt, probe=args.tail_probe)
    except RehearsalError as exc: print(f"Stage A refused: {safe_detail(str(exc))}", file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main())
