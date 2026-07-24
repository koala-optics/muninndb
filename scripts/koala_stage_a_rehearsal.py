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
DEFAULT_PAYLOAD_BYTES = 10_900
MIN_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES = 1_000, 32_000
CALIBRATION_SAMPLE_COUNT = 25_000
CALIBRATION_LOW_PAYLOAD_BYTES, CALIBRATION_HIGH_PAYLOAD_BYTES = MIN_PAYLOAD_BYTES, 4_000
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
MIN_STORE_BYTES, MAX_STORE_BYTES = 11 * 1024**3 // 2, 13 * 1024**3 // 2
TARGET_STORE_BYTES = 6 * 1024**3
VOLUME_SIZE_GB = 20
MAX_PEAK_BYTES, MIN_FREE_PERCENT = 14 * 1024**3, 30.0
MIGRATION_LIMIT_S, READINESS_LIMIT_S = 45 * 60, 5 * 60
QUERY_P95_LIMIT_MS, STATUS_LIMIT_S = 250.0, 30.0
RESTORE_LIMIT_S, ROLLBACK_LIMIT_S = 45 * 60, 30 * 60
FLY_REGION, FLY_ORG, MCP_PORT = "ewr", "personal", 8750
BASELINE_IMAGE = "registry.fly.io/koala-muninndb:deployment-01KSWRX9GKW5M94MQQCBZSJZHS"
BASELINE_DIGEST = "sha256:c06842e1452f2aab4c1f01207adf9406bfe757b4984da516568006f1f5c8ad86"
CANDIDATE_IMAGE = "ghcr.io/koala-optics/muninndb@sha256:e46c96ac5359707970692070b2298a4b4be877bdfc918c30231da2663d5d06b8"
SOURCE_COMMIT, SOURCE_TAG = "7251eca0dbfda2cd5e459a174a61322d82562f0b", "koala-v0.9.0-rc.1"
PRODUCTION_APP = "koala-muninndb"
PRODUCTION_MACHINE_IDS = frozenset({"6e8262d6c6d298"})
PRODUCTION_VOLUME_IDS = frozenset({"vol_vgn3o017zm3gkgz4"})
COLLISION_CONCEPTS = ("stage-a/collision/1162789", "stage-a/collision/1379192")
DIGEST_REF = re.compile(r"[a-z0-9./-]+@sha256:[0-9a-f]{64}")
RUN_ID_RE = re.compile(r"[a-z0-9][a-z0-9-]{3,31}")
FLY_VOLUME_NAME_RE = re.compile(r"[a-z0-9_]{1,30}")
SENSITIVE_TEXT = re.compile(r"https?://|(?i:authorization|bearer|password|secret|token|x-amz-|fly_api)")
RECEIPT_KEYS = frozenset({"schema_version", "status", "exit_code", "run_id", "source", "images", "corpus", "resources", "measurements", "gates", "cleanup", "orphans", "detail", "limitations"})

class RehearsalError(RuntimeError): status = "UNKNOWN"
class RehearsalFailed(RehearsalError): status = "FAILED"
class RehearsalUnknown(RehearsalError): pass

@dataclass(frozen=True)
class RunIdentity:
    run_id: str
    app_name: str
    volume_name: str
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
    backup_volume_id: str | None = None
    restore_volume_id: str | None = None
    rollback_volume_id: str | None = None
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
        f"{volume_prefix}_bak",
        f"{volume_prefix}_rst",
        f"{volume_prefix}_rbk",
        f"STAGE-A-{run_id}-{digest}",
    )
    assert_not_production(identity)
    return identity

def assert_not_production(identity: RunIdentity) -> None:
    volumes = (identity.volume_name, identity.backup_volume_name, identity.restore_volume_name, identity.rollback_volume_name)
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
            identity.backup_volume_name,
            identity.restore_volume_name,
            identity.rollback_volume_name,
        },
    }
    if kind in names and value not in names[kind]:
        raise RehearsalUnknown(f"refusing unowned {kind}")

def validate_image(ref: str, role: str) -> str:
    expected = BASELINE_IMAGE if role == "baseline" else CANDIDATE_IMAGE
    if ref != expected or (role != "baseline" and not DIGEST_REF.fullmatch(ref)):
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

def threshold_gate(name: str, measured: float | int | None, limit: float | int) -> Gate:
    if measured is None: return Gate("UNKNOWN", f"{name} not measured", measured, limit)
    passed = measured <= limit
    return Gate("PASSED" if passed else "FAILED", f"{name} {'passed' if passed else 'exceeded threshold'}", measured, limit)

def disk_gate(samples: Sequence[DiskSample]) -> Gate:
    if not samples: return Gate("UNKNOWN", "no disk samples")
    peak, free = max(s.used_bytes for s in samples), min(s.free_percent for s in samples)
    passed = peak <= MAX_PEAK_BYTES and free >= MIN_FREE_PERCENT
    return Gate("PASSED" if passed else "FAILED", f"peak={peak} minimum_free_percent={free:.2f}", peak, MAX_PEAK_BYTES)

def store_footprint_gate(used: int | None) -> Gate:
    if used is None: return Gate("UNKNOWN", "pre-migration footprint missing")
    passed = MIN_STORE_BYTES <= used <= MAX_STORE_BYTES
    return Gate("PASSED" if passed else "FAILED", f"pre-migration bytes={used}", used, MAX_STORE_BYTES)

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
    cohort: str,
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
        sample = runtime.disk_sample(identity, machine_id, f"ablation-{cohort}-settling")
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

def combine_status(gates: dict[str, Gate], orphans: Sequence[str]) -> str:
    if orphans or any(g.status == "UNKNOWN" for g in gates.values()): return "UNKNOWN"
    if any(g.status == "FAILED" for g in gates.values()): return "FAILED"
    return "PASSED"

def safe_detail(value: str) -> str:
    compact = " ".join(value.split())[-400:]
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
        if isinstance(value, str): sanitized[key] = safe_detail(value)
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
) -> dict[str, Any]:
    bounded_measurements = json.loads(json.dumps(measurements))
    bounded_measurements["mode"] = mode
    limitations = [
        "Synthetic rehearsal is not production deployment authorization.",
        "Production data, backups, volumes, machines, app, and credentials are prohibited.",
    ]
    if mode == "ablate":
        limitations.append(
            "The bounded df quiet-window witnesses disk settlement; it does not prove asynchronous FTS or provenance queues are empty."
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "exit_code": exit_code,
        "run_id": identity.run_id,
        "source": {"commit": SOURCE_COMMIT, "tag": SOURCE_TAG},
        "images": {"baseline": BASELINE_IMAGE, "baseline_digest": BASELINE_DIGEST, "candidate": CANDIDATE_IMAGE},
        "corpus": corpus_evidence(spec, corpus),
        "resources": {key: value for key, value in asdict(ledger).items() if value},
        "measurements": bounded_measurements,
        "gates": {name: asdict(gate) for name, gate in gates.items()},
        "cleanup": cleanup_result,
        "orphans": list(orphans),
        "detail": detail,
        "limitations": limitations,
    }

class MCPClient:
    def __init__(self, url: str, auth_value: str, timeout: float = 60.0):
        if not re.fullmatch(r"http://(?:127\.0\.0\.1|localhost):[0-9]+/mcp", url): raise RehearsalUnknown("MCP endpoint must be loopback")
        self.url, self.auth_value, self.timeout, self.request_id = url, auth_value, timeout, 0
    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(self.url, data=json.dumps(payload).encode(), method="POST",
            headers={"Authorization": f"Bearer {self.auth_value}", "Content-Type": "application/json"})
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=self.timeout) as response:
                parsed = json.loads(response.read().decode())
        except (OSError, ValueError, urllib.error.URLError) as exc: raise RehearsalUnknown(f"MCP transport failed: {type(exc).__name__}") from exc
        if parsed.get("error"): raise RehearsalFailed("MCP JSON-RPC error")
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
    def call(self, method: str, arguments: dict[str, Any]) -> tuple[Any, float]:
        self.request_id += 1; started = time.monotonic()
        response = self._post({"jsonrpc": "2.0", "method": "tools/call", "params": {"name": method, "arguments": arguments}, "id": self.request_id})
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
    def run(self, args: list[str], *, stdin: str | None = None, timeout: int = 600) -> subprocess.CompletedProcess[str]:
        proc = self.runner(["flyctl", *args], input=stdin, text=True, capture_output=True, timeout=timeout)
        if proc.returncode: raise RehearsalUnknown(f"flyctl {args[0]} failed: {_safe_process_error(proc)}")
        return proc
    def json(self, args: list[str], *, timeout: int = 600) -> Any:
        try: return json.loads(self.run([*args, "--json"], timeout=timeout).stdout)
        except json.JSONDecodeError as exc: raise RehearsalUnknown(f"flyctl {args[0]} returned invalid JSON") from exc
    def preflight(self, identity: RunIdentity) -> None:
        assert_not_production(identity)
        proc = self.runner(["flyctl", "status", "-a", identity.app_name], text=True, capture_output=True, timeout=60)
        if proc.returncode == 0: raise RehearsalUnknown("run-owned app already exists")
    def create_app(self, identity: RunIdentity) -> str:
        self.run(["apps", "create", identity.app_name, "--org", FLY_ORG]); return identity.app_name
    def install_auth(self, identity: RunIdentity, auth_value: str) -> None:
        env_name = "MUNINN" + "_MCP_TOKEN"
        self.run(["secrets", "import", "-a", identity.app_name, "--stage"], stdin=f"{env_name}={auth_value}\nMUNINN_LOCAL_EMBED=0\n")
    def create_volume(self, identity: RunIdentity, name: str, *, snapshot_id: str | None = None) -> str:
        assert_owned(name, identity, "volume-name")
        args = ["volumes", "create", name, "-a", identity.app_name, "--region", FLY_REGION, "--size", str(VOLUME_SIZE_GB), "--scheduled-snapshots=false", "--yes"]
        if snapshot_id: args.extend(["--snapshot-id", snapshot_id])
        result = self.json(args); volume_id = str(result.get("id", "")) if isinstance(result, dict) else ""
        if not volume_id or volume_id in PRODUCTION_VOLUME_IDS: raise RehearsalUnknown("invalid or preserved volume ID")
        return volume_id
    def create_machine(self, identity: RunIdentity, volume_id: str, image: str, role: str) -> str:
        if volume_id in PRODUCTION_VOLUME_IDS: raise RehearsalUnknown("refusing production volume")
        validate_image(image, "baseline" if role in {"baseline", "rollback"} else "candidate")
        name = f"koala-stage-a-{identity.run_id}-{role}"
        config = json.dumps({"image": image, "init": {"cmd": ["--daemon", "--data", "/data", "--listen-host", "0.0.0.0", "--mcp-addr", f"0.0.0.0:{MCP_PORT}"]}, "restart": {"policy": "no"}, "guest": {"cpu_kind": "performance", "cpus": 16, "memory_mb": 32768}, "mounts": [{"volume": volume_id, "path": "/data"}], "metadata": {"koala_stage_a_run": identity.run_id, "role": role}, "services": []}, sort_keys=True)
        proc = self.run(["machine", "run", image, "-a", identity.app_name, "--region", FLY_REGION, "--name", name, "--machine-config", config, "--restart", "no", "--skip-dns-registration", "--detach"])
        matches = re.findall(r"(?m)^\s*Machine ID:\s*([0-9a-f]+)\s*$", proc.stdout)
        if len(matches) != 1 or matches[0] in PRODUCTION_MACHINE_IDS: raise RehearsalUnknown("invalid or preserved machine ID")
        return matches[0]
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
    def wait_stopped(self, identity: RunIdentity, machine_id: str, timeout_s: float) -> float:
        started = time.monotonic()
        self.run(["machine", "wait", machine_id, "-a", identity.app_name, "--state", "stopped",
                  "--wait-timeout", f"{math.ceil(timeout_s)}s"], timeout=math.ceil(timeout_s) + 30)
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
        command = "ps -eo pcpu=,rss=,comm= | awk '$3 ~ /muninndb/ {cpu+=$1; rss+=$2} END {printf \"%.3f %d\\n\", cpu, rss}'"
        fields = self.run(["machine", "exec", machine_id, "-a", identity.app_name, "--timeout", "30", command]).stdout.split()
        if len(fields) != 2:
            raise RehearsalUnknown("invalid CPU or memory measurement")
        try: cpu_percent, rss_kib = float(fields[0]), int(fields[1])
        except ValueError as exc: raise RehearsalUnknown("invalid CPU or memory values") from exc
        if cpu_percent < 0 or rss_kib <= 0: raise RehearsalUnknown("missing MuninnDB process measurement")
        return ResourceSample(phase, cpu_percent, rss_kib * 1024)
    def migration_samples(self, identity: RunIdentity, machine_id: str, timeout_s: float,
                          interval_s: float = 5.0) -> tuple[float, list[DiskSample], list[ResourceSample]]:
        started, deadline, disks, resources = time.monotonic(), time.monotonic() + timeout_s, [], []
        while time.monotonic() < deadline:
            status = self.machine_status(identity, machine_id).get("state")
            if status == "started":
                disks.append(self.disk_sample(identity, machine_id, "migration"))
                resources.append(self.resource_sample(identity, machine_id, "migration"))
                return time.monotonic() - started, disks, resources
            if status in {"stopped", "failed", "destroyed"}: raise RehearsalFailed(f"candidate stopped during migration: {status}")
            if status in {"starting", "created"}:
                try:
                    disks.append(self.disk_sample(identity, machine_id, "migration"))
                    resources.append(self.resource_sample(identity, machine_id, "migration"))
                except RehearsalUnknown:
                    pass
            time.sleep(interval_s)
        raise RehearsalUnknown("migration readiness deadline expired")
    def snapshot(self, identity: RunIdentity, volume_id: str) -> str:
        result = self.json(["volumes", "snapshots", "create", volume_id, "-a", identity.app_name]); snapshot_id = str(result.get("id", "")) if isinstance(result, dict) else ""
        if not snapshot_id: raise RehearsalUnknown("snapshot ID missing")
        return snapshot_id
    def _offline_helper(self, identity: RunIdentity, image: str, role: str,
                        mounts: list[dict[str, str]], command: str) -> str:
        helper_name = f"koala-stage-a-{identity.run_id}-{role}"
        config = json.dumps({"image": image, "init": {"exec": ["/bin/sh", "-c", command]},
            "restart": {"policy": "no"}, "guest": {"cpu_kind": "performance", "cpus": 16, "memory_mb": 32768},
            "mounts": mounts, "metadata": {"koala_stage_a_run": identity.run_id, "role": role}, "services": []}, sort_keys=True)
        proc = self.run(["machine", "run", image, "-a", identity.app_name, "--region", FLY_REGION,
            "--name", helper_name, "--machine-config", config, "--restart", "no",
            "--skip-dns-registration", "--detach"])
        matches = re.findall(r"(?m)^\s*Machine ID:\s*([0-9a-f]+)\s*$", proc.stdout)
        if len(matches) != 1 or matches[0] in PRODUCTION_MACHINE_IDS:
            raise RehearsalUnknown(f"{role} helper ID missing")
        return matches[0]
    def create_backup(self, identity: RunIdentity, volume_id: str, backup_volume_id: str,
                      image: str) -> tuple[str, str]:
        validate_image(image, "candidate")
        if volume_id in PRODUCTION_VOLUME_IDS or backup_volume_id in PRODUCTION_VOLUME_IDS:
            raise RehearsalUnknown("refusing production backup volume")
        archive = "/backup/stage-a-backup.tgz"
        command = ("set -eu; test -z \"$(find /backup -mindepth 1 -maxdepth 1 -print -quit)\"; "
            "muninndb-server backup --data-dir /data --output /backup/stage-a-backup; "
            "tar -C /backup/stage-a-backup -czf \"$A\" .; sha256sum \"$A\" | cut -d' ' -f1 > \"$A.sha256\"; "
            "stat -c %s \"$A\" > \"$A.bytes\"; rm -rf /backup/stage-a-backup")
        command = f"A={archive}; {command}"
        mounts = [{"volume": volume_id, "path": "/data"}, {"volume": backup_volume_id, "path": "/backup"}]
        return self._offline_helper(identity, image, "backup", mounts, command), archive
    def hard_delete(self, identity: RunIdentity, volume_id: str, image: str,
                    vault: str, memory_id: str) -> str:
        validate_image(image, "candidate")
        if volume_id in PRODUCTION_VOLUME_IDS or not re.fullmatch(r"[A-Za-z0-9_-]+", vault) or not re.fullmatch(r"[A-Za-z0-9_-]+", memory_id):
            raise RehearsalUnknown("invalid hard-delete target")
        command = (f"set -eu; muninndb-server exec forget --data-dir /data "
            f"--vault {vault} --id {memory_id}")
        return self._offline_helper(identity, image, "hard-delete", [{"volume": volume_id, "path": "/data"}], command)
    def create_restore(self, identity: RunIdentity, backup_volume_id: str, restore_volume_id: str,
                       image: str, archive_path: str) -> str:
        validate_image(image, "candidate")
        if backup_volume_id in PRODUCTION_VOLUME_IDS or restore_volume_id in PRODUCTION_VOLUME_IDS:
            raise RehearsalUnknown("refusing production restore volume")
        command = (f"set -eu; A={archive_path}; test -f \"$A\"; test -f \"$A.sha256\"; "
            "test -f \"$A.bytes\"; test \"$(sha256sum \"$A\" | cut -d' ' -f1)\" = \"$(cat \"$A.sha256\")\"; "
            "test -z \"$(find /restore -mindepth 1 -maxdepth 1 -print -quit)\"; "
            "tar -xzf \"$A\" -C /restore; "
            "printf 'bytes=' > /restore/.stage-a-restore-receipt; cat \"$A.bytes\" >> /restore/.stage-a-restore-receipt; "
            "printf 'sha256=' >> /restore/.stage-a-restore-receipt; cat \"$A.sha256\" >> /restore/.stage-a-restore-receipt")
        mounts = [{"volume": backup_volume_id, "path": "/backup"}, {"volume": restore_volume_id, "path": "/restore"}]
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
        machine_ids = []
        for machine in machines:
            if not isinstance(machine, dict): raise RehearsalUnknown("cleanup machine entry invalid")
            machine_id = str(machine.get("id", ""))
            metadata = machine.get("config", {}).get("metadata", {})
            if machine_id in PRODUCTION_MACHINE_IDS or metadata.get("koala_stage_a_run") != identity.run_id:
                raise RehearsalUnknown("cleanup discovered unowned machine")
            machine_ids.append(machine_id)
        if len(machine_ids) > 1: raise RehearsalUnknown("cleanup discovered multiple machines")
        by_name: dict[str, str] = {}
        allowed_names = {
            identity.volume_name,
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
            machine_id=machine_ids[0] if machine_ids else None,
            volume_id=by_name.get(identity.volume_name),
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

def cleanup(runtime: FlyRuntime, identity: RunIdentity, ledger: ResourceLedger) -> tuple[dict[str, str], list[str]]:
    results, orphans = {}, []
    for label in ("machine_id", "restore_volume_id", "backup_volume_id", "rollback_volume_id", "volume_id"):
        resource = getattr(ledger, label)
        if not resource: results[label] = "not_created"; continue
        try:
            runtime.destroy_machine(identity, resource) if label == "machine_id" else runtime.destroy_volume(identity, resource)
            results[label] = "destroyed"; setattr(ledger, label, None)
        except Exception: results[label] = "destroy_failed"; orphans.append(resource)
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
        detail = safe_detail(str(exc))
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

def run_query_probes(client: MCPClient, receipt: CorpusReceipt) -> dict[str, list[float]]:
    samples: dict[str, list[float]] = {"exact": [], "entity": [], "read": [], "fuzzy": []}
    for index, concept in enumerate(COLLISION_CONCEPTS):
        result, latency = client.call("muninn_find_by_concept", {"vault": "stage-a-primary", "concept": concept, "limit": 50})
        if result_ids(result) != [receipt.retained_ids["collision"][index]]: raise RehearsalFailed("collision hydration failed")
        samples["exact"].append(latency)
    for entity in ("Stage A Entity 00", "Stage A Entity 07", "Stage A Entity 42"):
        result, latency = client.call("muninn_find_by_entity", {"vault": "stage-a-primary", "entity_name": entity, "limit": 50}); samples["entity"].append(latency)
        if entity == "Stage A Entity 42": verify_entity_ordering(result, list(reversed(receipt.retained_ids["ordering"])))
    for memory_id in receipt.retained_ids["ordering"][:10]:
        _, latency = client.call("muninn_read", {"vault": "stage-a-primary", "id": memory_id}); samples["read"].append(latency)
    for context in (["Stage A Entity 00"], ["Stage A Group 2"]):
        _, latency = client.call("muninn_recall", {"vault": "stage-a-primary", "context": context, "limit": 10}); samples["fuzzy"].append(latency)
    isolated_concept = "stage-a/isolation/0000097"
    cross, _ = client.call("muninn_find_by_concept", {"vault": "stage-a-primary", "concept": isolated_concept, "limit": 50})
    if result_ids(cross): raise RehearsalFailed("vault isolation failed")
    isolated, _ = client.call("muninn_find_by_concept", {"vault": "stage-a-isolation", "concept": isolated_concept, "limit": 50})
    if len(result_ids(isolated)) != 1: raise RehearsalFailed("isolated vault lookup failed")
    return samples

def plan(identity: RunIdentity, spec: CorpusSpec, *, mode: str = "execute") -> dict[str, Any]:
    if mode in {"calibrate", "ablate"}: validate_calibration_spec(spec)
    else: validate_spec(spec)
    validate_image(BASELINE_IMAGE, "baseline"); validate_image(CANDIDATE_IMAGE, "candidate")
    return {"mode": f"{mode}-plan", "run_id": identity.run_id, "confirmation_required_for_execute": identity.confirmation,
            "source_commit": SOURCE_COMMIT, "source_tag": SOURCE_TAG, "baseline_image": BASELINE_IMAGE,
            "baseline_digest": BASELINE_DIGEST, "candidate_image": CANDIDATE_IMAGE,
            "record_count": spec.count, "batch_size": spec.batch_size,
            "payload_bytes": spec.payload_bytes, "volume_gb": VOLUME_SIZE_GB,
            "generated_resources": {"app": identity.app_name, "source_volume": identity.volume_name,
                                    "backup_volume": identity.backup_volume_name, "restore_volume": identity.restore_volume_name,
                                    "rollback_volume": identity.rollback_volume_name},
            "note": "plan-only: zero Fly mutations, credentials, network queries, or production access"}

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
    except RehearsalError as exc: status, exit_code, detail = exc.status, 1 if exc.status == "FAILED" else 2, safe_detail(str(exc))
    except Exception as exc: status, exit_code, detail = "UNKNOWN", 2, f"unexpected {type(exc).__name__}"
    finally:
        try: terminate_proxy(proxy)
        except RehearsalError: status, exit_code, detail = "UNKNOWN", 2, "local proxy cleanup uncertain"
        cleanup_result, orphans = cleanup(runtime, identity, ledger)
        if orphans: status, exit_code, detail = "UNKNOWN", 2, "cleanup uncertainty or orphaned resources"
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
            quiet = wait_for_storage_quiet(runtime, identity, ledger.machine_id, cohort)
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
    except RehearsalError as exc: status, exit_code, detail = exc.status, 1 if exc.status == "FAILED" else 2, safe_detail(str(exc))
    except Exception as exc: status, exit_code, detail = "UNKNOWN", 2, f"unexpected {type(exc).__name__}"
    finally:
        try: terminate_proxy(proxy)
        except RehearsalError: status, exit_code, detail = "UNKNOWN", 2, "local proxy cleanup uncertain"
        cleanup_result, orphans = cleanup(runtime, identity, ledger)
        if orphans: status, exit_code, detail = "UNKNOWN", 2, "cleanup uncertainty or orphaned resources"
        write_receipt(receipt_path, receipt_document(
            identity, receipt_spec, status=status, exit_code=exit_code, detail=detail, ledger=ledger,
            measurements=measurements, gates=gates, cleanup_result=cleanup_result,
            orphans=orphans, corpus=corpus_receipt, mode="ablate",
        ))
    return exit_code

def execute(identity: RunIdentity, spec: CorpusSpec, receipt_path: Path, *, runtime: FlyRuntime | None = None,
            client_factory: Callable[[str, str], MCPClient] | None = None, local_port: int = 18750) -> int:
    runtime = runtime or FlyRuntime(); client_factory = client_factory or (lambda url, auth: MCPClient(url, auth))
    ledger, proxy = ResourceLedger(), None
    gates: dict[str, Gate] = {}; measurements: dict[str, Any] = {"disk_samples": [], "latencies": {}}
    corpus_receipt: CorpusReceipt | None = None; cleanup_result: dict[str, str] = {}; orphans: list[str] = []
    detail, status, exit_code = "rehearsal did not complete", "UNKNOWN", 2
    auth_value = secrets.token_urlsafe(32)
    try:
        validate_spec(spec); validate_image(BASELINE_IMAGE, "baseline"); validate_image(CANDIDATE_IMAGE, "candidate"); runtime.preflight(identity)
        ledger.app = runtime.create_app(identity); runtime.install_auth(identity, auth_value)
        ledger.volume_id = runtime.create_volume(identity, identity.volume_name)
        ledger.machine_id = runtime.create_machine(identity, ledger.volume_id, BASELINE_IMAGE, "baseline")
        runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S); proxy = runtime.proxy(identity, ledger.machine_id, local_port)
        client = client_factory(f"http://127.0.0.1:{local_port}/mcp", auth_value); client.initialize()
        def checkpoint(progress: IngestProgress) -> None:
            nonlocal corpus_receipt
            corpus_receipt = progress
            sample = runtime.disk_sample(identity, ledger.machine_id or "", "baseline-ingestion")
            require_disk_safety(sample)
            measurements["latest_disk_sample"] = asdict(sample) | {"free_percent": sample.free_percent}
            write_receipt(receipt_path, receipt_document(
                identity, spec, status="UNKNOWN", exit_code=2, detail="baseline ingestion in progress",
                ledger=ledger, measurements=measurements, gates=gates, cleanup_result={}, orphans=[],
                corpus=progress,
            ))
        corpus_receipt = ingest_corpus(client, spec, progress=checkpoint)
        pre = runtime.disk_sample(identity, ledger.machine_id, "pre-migration"); require_disk_safety(pre)
        measurements["disk_samples"].append(asdict(pre) | {"free_percent": pre.free_percent})
        gates["store_footprint"] = store_footprint_gate(pre.used_bytes)
        baseline_counts, status_samples = query_counts(client); measurements["baseline_counts"] = baseline_counts
        gates["baseline_status"] = threshold_gate("baseline status", max(status_samples) / 1000, STATUS_LIMIT_S)
        if sum(baseline_counts.values()) != spec.count: raise RehearsalFailed("baseline vault counts differ from accepted corpus")
        terminate_proxy(proxy); proxy = None; runtime.stop_machine(identity, ledger.machine_id); runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        ledger.snapshot_id = runtime.snapshot(identity, ledger.volume_id)
        migration_started = time.monotonic(); ledger.machine_id = runtime.create_machine(identity, ledger.volume_id, CANDIDATE_IMAGE, "candidate")
        candidate_ready, migration_disks, migration_resources = runtime.migration_samples(identity, ledger.machine_id, MIGRATION_LIMIT_S)
        migration_s = time.monotonic() - migration_started
        measurements["disk_samples"].extend(asdict(sample) | {"free_percent": sample.free_percent} for sample in migration_disks)
        measurements["migration_resources"] = [asdict(sample) for sample in migration_resources]
        gates["migration_duration"] = threshold_gate("migration duration", migration_s, MIGRATION_LIMIT_S)
        readiness_started = time.monotonic(); proxy = runtime.proxy(identity, ledger.machine_id, local_port); candidate = client_factory(f"http://127.0.0.1:{local_port}/mcp", auth_value); candidate.initialize()
        _, readiness_status_ms = query_count(candidate, "stage-a-primary")
        readiness_s = time.monotonic() - readiness_started
        measurements["candidate_readiness_s"] = readiness_s
        gates["candidate_readiness"] = threshold_gate("candidate readiness after migration", readiness_s, READINESS_LIMIT_S)
        gates["candidate_status"] = threshold_gate("candidate status", readiness_status_ms / 1000, STATUS_LIMIT_S)
        migrated_counts, _ = query_counts(candidate)
        gates["count_invariance"] = Gate("PASSED" if migrated_counts == baseline_counts else "FAILED",
            f"baseline={baseline_counts} migrated={migrated_counts}", sum(migrated_counts.values()), spec.count)
        samples = run_query_probes(candidate, corpus_receipt); run_lifecycle_probes(candidate, corpus_receipt)
        gates["semantic_probes"] = Gate("PASSED", "exact-concept, entity ordering, vault isolation, collision hydration, lifecycle filtering, and fuzzy reads passed")
        measurements["latencies"] = {name: latency_summary(values) for name, values in samples.items()}
        p95 = max(summary["p95_ms"] or 0 for summary in measurements["latencies"].values() if summary["count"])
        gates["query_latency"] = threshold_gate("bounded query p95", p95, QUERY_P95_LIMIT_MS)
        post = runtime.disk_sample(identity, ledger.machine_id, "post-migration"); measurements["disk_samples"].append(asdict(post) | {"free_percent": post.free_percent})
        all_disk_samples = [pre, *migration_disks, post]; gates["disk_headroom"] = disk_gate(all_disk_samples)
        gates["resource_sampling"] = Gate("PASSED" if migration_resources else "UNKNOWN", "migration CPU and RSS samples captured", len(migration_resources))
        terminate_proxy(proxy); proxy = None; runtime.stop_machine(identity, ledger.machine_id); runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        ledger.machine_id = runtime.create_machine(identity, ledger.volume_id, CANDIDATE_IMAGE, "clean-restart"); runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
        runtime.stop_machine(identity, ledger.machine_id, force=True); runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        ledger.machine_id = runtime.create_machine(identity, ledger.volume_id, CANDIDATE_IMAGE, "crash-restart"); runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
        gates["restart_durability"] = Gate("PASSED", "clean and forced-crash restarts reached readiness")
        runtime.stop_machine(identity, ledger.machine_id); runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        hard_delete_id = corpus_receipt.retained_ids["hard_delete"][0]
        hard_delete_helper = runtime.hard_delete(identity, ledger.volume_id, CANDIDATE_IMAGE, "stage-a-primary", hard_delete_id)
        ledger.machine_id = hard_delete_helper; runtime.wait_stopped(identity, hard_delete_helper, READINESS_LIMIT_S)
        runtime.destroy_machine(identity, hard_delete_helper); ledger.machine_id = None
        ledger.machine_id = runtime.create_machine(identity, ledger.volume_id, CANDIDATE_IMAGE, "hard-delete-check"); runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
        proxy = runtime.proxy(identity, ledger.machine_id, local_port); hard_delete_client = client_factory(f"http://127.0.0.1:{local_port}/mcp", auth_value); hard_delete_client.initialize()
        deleted_concept, _ = hard_delete_client.call("muninn_find_by_concept", {"vault": "stage-a-primary", "concept": "stage-a/concept/0043", "limit": 50})
        deleted_entity, _ = hard_delete_client.call("muninn_find_by_entity", {"vault": "stage-a-primary", "entity_name": "Stage A Entity 43", "limit": 50})
        if hard_delete_id in result_ids(deleted_concept) or hard_delete_id in result_ids(deleted_entity): raise RehearsalFailed("hard-deleted record remained indexed")
        try: hard_delete_client.call("muninn_read", {"vault": "stage-a-primary", "id": hard_delete_id})
        except RehearsalFailed: pass
        else: raise RehearsalFailed("hard-deleted record remained readable")
        hard_delete_counts, _ = query_counts(hard_delete_client); terminate_proxy(proxy); proxy = None
        expected_after_delete = dict(baseline_counts); expected_after_delete["stage-a-primary"] -= 1
        if hard_delete_counts != expected_after_delete: raise RehearsalFailed("hard-delete count delta was not exactly one")
        gates["hard_delete_cleanup"] = Gate("PASSED", "offline hard delete removed primary and reverse-index reachability")
        runtime.stop_machine(identity, ledger.machine_id); runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        backup_started = time.monotonic(); ledger.backup_volume_id = runtime.create_volume(identity, identity.backup_volume_name)
        backup_helper, backup_path = runtime.create_backup(identity, ledger.volume_id, ledger.backup_volume_id, CANDIDATE_IMAGE)
        ledger.machine_id = backup_helper; runtime.wait_stopped(identity, backup_helper, RESTORE_LIMIT_S)
        measurements["backup_duration_s"] = time.monotonic() - backup_started
        runtime.destroy_machine(identity, backup_helper); ledger.machine_id = None
        restore_started = time.monotonic()
        ledger.restore_volume_id = runtime.create_volume(identity, identity.restore_volume_name)
        restore_helper = runtime.create_restore(identity, ledger.backup_volume_id, ledger.restore_volume_id, CANDIDATE_IMAGE, backup_path)
        ledger.machine_id = restore_helper; runtime.wait_stopped(identity, restore_helper, RESTORE_LIMIT_S)
        runtime.destroy_machine(identity, restore_helper); ledger.machine_id = None
        ledger.machine_id = runtime.create_machine(identity, ledger.restore_volume_id, CANDIDATE_IMAGE, "restore"); runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
        measurements["backup"] = runtime.backup_measurement(identity, ledger.machine_id)
        proxy = runtime.proxy(identity, ledger.machine_id, local_port); restore_client = client_factory(f"http://127.0.0.1:{local_port}/mcp", auth_value); restore_client.initialize()
        restored_counts, _ = query_counts(restore_client); restored_samples = run_query_probes(restore_client, corpus_receipt); terminate_proxy(proxy); proxy = None
        if restored_counts != expected_after_delete: raise RehearsalFailed("restored counts differ from backup source")
        measurements["restored_latencies"] = {name: latency_summary(values) for name, values in restored_samples.items()}
        measurements["restore_to_query_s"] = time.monotonic() - restore_started; gates["backup_restore"] = threshold_gate("restore-to-query", measurements["restore_to_query_s"], RESTORE_LIMIT_S)
        runtime.stop_machine(identity, ledger.machine_id); runtime.destroy_machine(identity, ledger.machine_id); ledger.machine_id = None
        rollback_started = time.monotonic(); ledger.rollback_volume_id = runtime.create_volume(identity, identity.rollback_volume_name, snapshot_id=ledger.snapshot_id)
        ledger.machine_id = runtime.create_machine(identity, ledger.rollback_volume_id, BASELINE_IMAGE, "rollback"); runtime.wait_ready(identity, ledger.machine_id, READINESS_LIMIT_S)
        proxy = runtime.proxy(identity, ledger.machine_id, local_port); rollback_client = client_factory(f"http://127.0.0.1:{local_port}/mcp", auth_value); rollback_client.initialize()
        rollback_counts, _ = query_counts(rollback_client); rollback_samples = run_query_probes(rollback_client, corpus_receipt); terminate_proxy(proxy); proxy = None
        if rollback_counts != baseline_counts: raise RehearsalFailed("pre-migration rollback counts differ from baseline")
        measurements["rollback_latencies"] = {name: latency_summary(values) for name, values in rollback_samples.items()}
        measurements["rollback_check_s"] = time.monotonic() - rollback_started; gates["pre_migration_rollback"] = threshold_gate("pre-migration rollback", measurements["rollback_check_s"], ROLLBACK_LIMIT_S)
        detail = "all measured Stage A phases completed"
    except RehearsalError as exc: status, exit_code, detail = exc.status, 1 if exc.status == "FAILED" else 2, safe_detail(str(exc))
    except Exception as exc: status, exit_code, detail = "UNKNOWN", 2, f"unexpected {type(exc).__name__}"
    finally:
        try: terminate_proxy(proxy)
        except RehearsalError: status, exit_code, detail = "UNKNOWN", 2, "local proxy cleanup uncertain"
        cleanup_result, orphans = cleanup(runtime, identity, ledger); computed = combine_status(gates, orphans)
        if detail == "all measured Stage A phases completed": status, exit_code = computed, 0 if computed == "PASSED" else (1 if computed == "FAILED" else 2)
        if orphans: status, exit_code, detail = "UNKNOWN", 2, "cleanup uncertainty or orphaned resources"
        write_receipt(receipt_path, receipt_document(
            identity, spec, status=status, exit_code=exit_code, detail=detail, ledger=ledger,
            measurements=measurements, gates=gates, cleanup_result=cleanup_result,
            orphans=orphans, corpus=corpus_receipt,
        ))
    return exit_code

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__); mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--execute", action="store_true")
    mode.add_argument("--calibrate", action="store_true")
    mode.add_argument("--ablate", action="store_true")
    mode.add_argument("--cleanup-only", action="store_true")
    parser.add_argument("--run-id", required=True); parser.add_argument("--confirm"); parser.add_argument("--record-count", type=int)
    parser.add_argument("--plan-mode", choices=("execute", "calibrate", "ablate"), default="execute")
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE); parser.add_argument("--payload-bytes", type=int)
    parser.add_argument("--seed", default="koala-stage-a-v1"); parser.add_argument("--receipt", type=Path, default=Path("stage-a-receipt.json")); parser.add_argument("--json", action="store_true")
    return parser

def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        identity = build_identity(args.run_id)
        calibrating = args.calibrate or args.ablate or (args.dry_run and args.plan_mode in {"calibrate", "ablate"})
        spec = CorpusSpec(
            args.record_count if args.record_count is not None else (CALIBRATION_SAMPLE_COUNT if calibrating else DEFAULT_RECORD_COUNT),
            args.batch_size,
            args.payload_bytes if args.payload_bytes is not None else (CALIBRATION_LOW_PAYLOAD_BYTES if calibrating else DEFAULT_PAYLOAD_BYTES),
            args.seed,
        )
        if not (args.execute or args.calibrate or args.ablate or args.cleanup_only):
            print(json.dumps(plan(identity, spec, mode=args.plan_mode), indent=2 if args.json else None, sort_keys=True)); return 0
        if args.confirm != identity.confirmation:
            print("REFUSED: mutating mode requires the exact run-specific confirmation", file=sys.stderr); print(f"Required confirmation: {identity.confirmation}", file=sys.stderr); return 2
        install_termination_handlers()
        if args.cleanup_only: return cleanup_only(identity, args.receipt)
        if args.calibrate: return calibrate(identity, spec, args.receipt)
        if args.ablate: return ablate(identity, spec, args.receipt)
        return execute(identity, spec, args.receipt)
    except RehearsalError as exc: print(f"Stage A refused: {safe_detail(str(exc))}", file=sys.stderr); return 2

if __name__ == "__main__": raise SystemExit(main())
