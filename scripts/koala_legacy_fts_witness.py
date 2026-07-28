#!/usr/bin/env python3
"""Measure the exact deployed legacy FTS search at the Stage A posting scale.

The witness extracts the immutable legacy source revision into a temporary
workspace, adds one package-local Go test, and runs that test as a standalone
binary. It never modifies the source checkout and never sends credentials or
network access settings to the benchmark child.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence

BASELINE_SOURCE_REVISION = "be975fb1215e75208adf4b340ba95e21415f04cb"
PRIMARY_RECORD_COUNT = 502_375
TOTAL_RECORD_COUNT = 502_385
PAYLOAD_BYTES = 4_000
TOP_K = 30
SERVER_CONTEXT_S = 30.0
QUERY_CONTEXTS = (
    "Stage A Entity 00",
    "Stage A Entity 01",
    "Stage A Entity 07",
    "Stage A Entity 42",
    "Stage A Entity 43",
    "Stage A Group 0",
    "Stage A Group 1",
    "Stage A Group 2",
)
GO_TEST_NAME = "TestKoalaLegacyFTSWitness"
GO_TEST_SOURCE = r'''package fts

import (
    "bufio"
    "context"
    "crypto/sha3"
    "encoding/binary"
    "encoding/hex"
    "encoding/json"
    "fmt"
    "math"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "testing"
    "time"

    "github.com/cockroachdb/pebble"
    "github.com/scrypster/muninndb/internal/storage"
    "github.com/scrypster/muninndb/internal/storage/keys"
)

const (
    witnessTotalRecords = 502385
    witnessPrimaryRecords = 502375
    witnessPayloadBytes = 4000
    witnessTopK = 30
    witnessSeed = "koala-stage-a-v1"
)

var witnessVocabulary = strings.Fields(
    "synthetic amber beacon calm delta ember field gentle harbor ivory " +
        "jasmine kind lantern meadow north olive plain quiet river silver " +
        "timber umber valley willow xenon yellow zenith",
)

func witnessIsolation(index int) bool {
    switch index {
    case 97, 194, 291, 388, 485, 582, 679, 776, 873, 970:
        return true
    default:
        return false
    }
}

func witnessProbe(index int) bool {
    if index < 2 || index == 43 || index == 50 || index == 51 || index == 57 {
        return true
    }
    return index%1000 == 42
}

func witnessDigest(index int) []byte {
    return sha3.SumSHAKE256([]byte("lexical:"+witnessSeed+":"+strconv.Itoa(index)), 32)
}

func witnessPayloadTokenCount(index int) int {
    digest := witnessDigest(index)
    prefix := "synthetic record" + strconv.Itoa(index) + " hash" + hex.EncodeToString(digest)[:12]
    length := len(prefix)
    tokens := 3
    cursor := 0
    for length < witnessPayloadBytes {
        word := witnessVocabulary[int(digest[cursor%len(digest)])%len(witnessVocabulary)]
        visible := witnessPayloadBytes - length - 1 // the separator consumes one byte
        if visible > len(word) {
            visible = len(word)
        }
        if visible >= 2 && !stopWords[word[:visible]] {
            tokens++
        }
        length += 1 + len(word)
        cursor++
    }
    return tokens
}

func witnessDocLen(index int) uint16 {
    // Concept contributes stage, concept/collision, and the numeric cohort.
    // JSON content contributes index, payload, schema, synthetic, true, plus
    // the numeric index when it has at least two digits. Probe tags contribute
    // koala, stage, synthetic, only, probe, and the probe kind. hard-delete is
    // the only three-token probe kind.
    count := 3 + witnessPayloadTokenCount(index) + 5
    if index >= 10 {
        count++
    }
    if witnessProbe(index) {
        count += 6
        if index == 43 {
            count++
        }
    }
    return uint16(count)
}

func witnessLexicalPayload(index int) string {
    digest := witnessDigest(index)
    var payload strings.Builder
    payload.Grow(witnessPayloadBytes + 16)
    payload.WriteString("synthetic record")
    payload.WriteString(strconv.Itoa(index))
    payload.WriteString(" hash")
    payload.WriteString(hex.EncodeToString(digest)[:12])
    cursor := 0
    for payload.Len() < witnessPayloadBytes {
        payload.WriteByte(' ')
        payload.WriteString(witnessVocabulary[int(digest[cursor%len(digest)])%len(witnessVocabulary)])
        cursor++
    }
    return payload.String()[:witnessPayloadBytes]
}

func witnessExactDocLen(index int) int {
    cohort := index % 1000
    concept := fmt.Sprintf("stage-a/concept/%04d", cohort)
    if index < 2 {
        collision := []string{"stage-a/collision/1162789", "stage-a/collision/1379192"}
        concept = collision[index]
    }
    content := fmt.Sprintf(
        "{\"index\":%d,\"payload\":%q,\"schema\":2,\"synthetic\":true}",
        index,
        witnessLexicalPayload(index),
    )
    var tags []string
    if witnessProbe(index) {
        kind := "ordering"
        switch index {
        case 0, 1:
            kind = "collision"
        case 43:
            kind = "hard-delete"
        case 50, 51, 57:
            kind = "fuzzy"
        }
        tags = []string{"koala-stage-a", "synthetic-only", "probe-" + kind}
    }
    return len(Tokenize(concept + " " + content + " " + strings.Join(tags, " ")))
}

func witnessID(index int) [16]byte {
    var id [16]byte
    binary.BigEndian.PutUint64(id[8:], uint64(index+1))
    return id
}

func witnessWriteJSON(path string, value any) error {
    data, err := json.Marshal(value)
    if err != nil {
        return err
    }
    return os.WriteFile(path, append(data, '\n'), 0o600)
}

func witnessOpenReadOnly(t *testing.T) *pebble.DB {
    t.Helper()
    db, err := pebble.Open(os.Getenv("KOALA_WITNESS_DB"), &pebble.Options{ReadOnly: true})
    if err != nil {
        t.Fatal(err)
    }
    return db
}

func witnessBuild(t *testing.T) {
    dbDir := os.Getenv("KOALA_WITNESS_DB")
    if err := os.RemoveAll(dbDir); err != nil {
        t.Fatal(err)
    }
    db, err := storage.OpenPebble(dbDir, storage.DefaultOptions())
    if err != nil {
        t.Fatal(err)
    }
    started := time.Now()
    var total uint64
    var avg float32
    batch := db.NewBatch()
    batchCount := 0
    for index := 0; index < witnessTotalRecords; index++ {
        if witnessIsolation(index) {
            continue
        }
        if exact, calculated := witnessExactDocLen(index), int(witnessDocLen(index)); exact != calculated {
            t.Fatalf("doc length mismatch at %d: exact=%d calculated=%d", index, exact, calculated)
        }
        docLen := witnessDocLen(index)
        field := FieldConcept
        // In the legacy key layout, concept and tag postings collide. The final
        // field is nondeterministic because Go map iteration chooses the last Set.
        // Digest parity supplies a deterministic, source-valid mixture for the
        // 509 enriched primary records without fabricating entity postings.
        if witnessProbe(index) && witnessDigest(index)[0]&1 == 1 {
            field = FieldTags
        }
        posting := encodePosting(PostingValue{TF: 1, Field: field, DocLen: docLen})
        if err := batch.Set(keys.FTSPostingKey([8]byte{}, "stage", witnessID(index)), posting, nil); err != nil {
            t.Fatal(err)
        }
        total++
        avg = float32((float64(total-1)*float64(avg) + float64(docLen)) / float64(total))
        batchCount++
        if batchCount == 10_000 {
            if err := batch.Commit(pebble.NoSync); err != nil {
                t.Fatal(err)
            }
            if err := batch.Close(); err != nil {
                t.Fatal(err)
            }
            batch = db.NewBatch()
            batchCount = 0
        }
    }
    if batchCount > 0 {
        if err := batch.Commit(pebble.NoSync); err != nil {
            t.Fatal(err)
        }
    }
    if err := batch.Close(); err != nil {
        t.Fatal(err)
    }
    if total != witnessPrimaryRecords {
        t.Fatalf("primary posting count=%d want=%d", total, witnessPrimaryRecords)
    }
    var termStats [8]byte
    binary.BigEndian.PutUint32(termStats[:4], uint32(total))
    if err := db.Set(keys.TermStatsKey([8]byte{}, "stage"), termStats[:], pebble.NoSync); err != nil {
        t.Fatal(err)
    }
    if err := db.Set(keys.FTSStatsKey([8]byte{}), encodeStats(FTSStats{TotalEngrams: total, AvgDocLen: avg}), pebble.Sync); err != nil {
        t.Fatal(err)
    }
    if err := db.Flush(); err != nil {
        t.Fatal(err)
    }
    if err := db.Compact([]byte{0x00}, []byte{0xff}, true); err != nil {
        t.Fatal(err)
    }
    if err := db.Close(); err != nil {
        t.Fatal(err)
    }
    if err := witnessWriteJSON(os.Getenv("KOALA_WITNESS_RESULT"), map[string]any{
        "status": "completed",
        "elapsed_s": time.Since(started).Seconds(),
        "posting_count": total,
        "avg_doc_len": avg,
        "indexed_fields": []string{"concept", "createdBy", "content", "tags"},
        "query_posting_term": "stage",
        "legacy_collision_model": "sha3-parity concept-or-tags for enriched records",
    }); err != nil {
        t.Fatal(err)
    }
}

func witnessScan(t *testing.T) {
    db := witnessOpenReadOnly(t)
    defer db.Close()
    idx := New(db)
    stats := idx.readStats([8]byte{})
    idf := idx.getIDF([8]byte{}, "stage", float64(stats.TotalEngrams))
    scores := make(map[[16]byte]float64, witnessPrimaryRecords)
    scanStarted := time.Now()
    if err := idx.searchToken(context.Background(), [8]byte{}, "stage", scores, idf, float64(stats.AvgDocLen)); err != nil {
        t.Fatal(err)
    }
    scanS := time.Since(scanStarted).Seconds()
    materializeStarted := time.Now()
    results := make([]ScoredID, 0, len(scores))
    distinct := make(map[uint64]struct{})
    for id, score := range scores {
        results = append(results, ScoredID{ID: id, Score: score})
        distinct[math.Float64bits(score)] = struct{}{}
    }
    materializeS := time.Since(materializeStarted).Seconds()
    persistStarted := time.Now()
    file, err := os.OpenFile(os.Getenv("KOALA_WITNESS_RANKING_INPUT"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
    if err != nil {
        t.Fatal(err)
    }
    writer := bufio.NewWriterSize(file, 1<<20)
    var scoreBytes [8]byte
    for _, result := range results {
        if _, err := writer.Write(result.ID[:]); err != nil {
            t.Fatal(err)
        }
        binary.BigEndian.PutUint64(scoreBytes[:], math.Float64bits(result.Score))
        if _, err := writer.Write(scoreBytes[:]); err != nil {
            t.Fatal(err)
        }
    }
    if err := writer.Flush(); err != nil {
        t.Fatal(err)
    }
    if err := file.Close(); err != nil {
        t.Fatal(err)
    }
    if err := witnessWriteJSON(os.Getenv("KOALA_WITNESS_RESULT"), map[string]any{
        "status": "completed",
        "scan_s": scanS,
        "materialize_s": materializeS,
        "persist_s": time.Since(persistStarted).Seconds(),
        "result_count": len(results),
        "distinct_scores": len(distinct),
    }); err != nil {
        t.Fatal(err)
    }
}

func witnessReadRankingInput(t *testing.T) []ScoredID {
    t.Helper()
    data, err := os.ReadFile(os.Getenv("KOALA_WITNESS_RANKING_INPUT"))
    if err != nil {
        t.Fatal(err)
    }
    if len(data)%24 != 0 {
        t.Fatalf("invalid ranking input length %d", len(data))
    }
    results := make([]ScoredID, 0, len(data)/24)
    for offset := 0; offset < len(data); offset += 24 {
        var id [16]byte
        copy(id[:], data[offset:offset+16])
        results = append(results, ScoredID{ID: id, Score: math.Float64frombits(binary.BigEndian.Uint64(data[offset+16 : offset+24]))})
    }
    return results
}

func witnessMarker(t *testing.T, name string) {
    t.Helper()
    path := os.Getenv(name)
    if path == "" {
        return
    }
    if err := os.WriteFile(path, []byte("ready\n"), 0o600); err != nil {
        t.Fatal(err)
    }
}

func witnessRank(t *testing.T) {
    results := witnessReadRankingInput(t)
    witnessMarker(t, "KOALA_WITNESS_MARKER")
    started := time.Now()
    sortScoredIDs(results)
    if err := witnessWriteJSON(os.Getenv("KOALA_WITNESS_RESULT"), map[string]any{
        "status": "completed", "elapsed_s": time.Since(started).Seconds(), "result_count": len(results),
    }); err != nil {
        t.Fatal(err)
    }
}

func witnessWhole(t *testing.T, cancellation string) {
    db := witnessOpenReadOnly(t)
    defer db.Close()
    idx := New(db)
    stats := idx.readStats([8]byte{})
    if stats.TotalEngrams != witnessPrimaryRecords {
        t.Fatalf("fixture posting count=%d want=%d", stats.TotalEngrams, witnessPrimaryRecords)
    }
    ctx := context.Background()
    var cancel context.CancelFunc
    if cancellation == "pre" || cancellation == "during" {
        ctx, cancel = context.WithCancel(ctx)
    }
    if cancellation == "pre" {
        cancel()
    }
    witnessMarker(t, "KOALA_WITNESS_MARKER")
    started := time.Now()
    if cancellation == "during" {
        go func() {
            time.Sleep(time.Millisecond)
            cancel()
            witnessMarker(t, "KOALA_WITNESS_CANCEL_MARKER")
        }()
    }
    results, err := idx.Search(ctx, [8]byte{}, "Stage A Entity 00", witnessTopK)
    receipt := map[string]any{
        "status": "completed", "elapsed_s": time.Since(started).Seconds(), "result_count": len(results), "ctx_error": "",
    }
    if err != nil {
        receipt["search_error"] = err.Error()
    }
    if ctx.Err() != nil {
        receipt["ctx_error"] = ctx.Err().Error()
    }
    if err := witnessWriteJSON(os.Getenv("KOALA_WITNESS_RESULT"), receipt); err != nil {
        t.Fatal(err)
    }
}

func TestKoalaLegacyFTSWitness(t *testing.T) {
    if filepath.Base(os.Getenv("KOALA_WITNESS_DB")) != "legacy-stage-a.db" {
        t.Fatal("invalid witness DB path")
    }
    switch os.Getenv("KOALA_WITNESS_MODE") {
    case "build":
        witnessBuild(t)
    case "scan":
        witnessScan(t)
    case "rank":
        witnessRank(t)
    case "whole":
        witnessWhole(t, "")
    case "pre-cancel":
        witnessWhole(t, "pre")
    case "mid-cancel":
        witnessWhole(t, "during")
    default:
        t.Fatal("invalid witness mode")
    }
}
'''


def sanitized_env(go_binary: Path, work_dir: Path) -> dict[str, str]:
    """Return a credential-free, offline environment for benchmark children."""
    home = Path.home()
    return {
        "PATH": f"{go_binary.parent}:/usr/bin:/bin",
        "HOME": str(home),
        "TMPDIR": str(work_dir / "tmp"),
        "GOPATH": str(home / "go"),
        "GOMODCACHE": str(home / "go" / "pkg" / "mod"),
        "GOCACHE": str(home / ".cache" / "go-build"),
        "GOTOOLCHAIN": "local",
        "GOPROXY": "off",
        "GOENV": "off",
        "GOWORK": "off",
    }


def find_go(explicit: str | None) -> Path:
    if explicit:
        candidate = Path(explicit).resolve()
    elif shutil.which("go"):
        candidate = Path(shutil.which("go") or "").resolve()
    else:
        candidates = sorted((Path.home() / "go" / "pkg" / "mod").glob("golang.org/toolchain@*/bin/go"))
        if not candidates:
            raise RuntimeError("Go toolchain not found; pass --go")
        candidate = candidates[-1].resolve()
    if not candidate.is_file() or not os.access(candidate, os.X_OK):
        raise RuntimeError(f"Go toolchain is not executable: {candidate}")
    return candidate


def run_checked(command: Sequence[str], *, cwd: Path, env: dict[str, str], timeout: float) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        list(command), cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, check=False,
    )
    if result.returncode:
        detail = (result.stdout + "\n" + result.stderr)[-4_000:]
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}\n{detail}")
    return result


def extract_revision(
    repo: Path,
    destination: Path,
    env: dict[str, str],
    patch: Path | None = None,
) -> None:
    run_checked(["git", "cat-file", "-e", f"{BASELINE_SOURCE_REVISION}^{{commit}}"], cwd=repo, env=env, timeout=30)
    archive = destination.parent / "legacy-source.tar"
    result = subprocess.run(
        ["git", "archive", "--format=tar", "--output", str(archive), BASELINE_SOURCE_REVISION],
        cwd=repo, env=env, text=True, capture_output=True, timeout=120, check=False,
    )
    if result.returncode:
        raise RuntimeError(f"git archive failed: {result.stderr[-2_000:]}")
    destination.mkdir(parents=True)
    with tarfile.open(archive) as bundle:
        bundle.extractall(destination, filter="data")
    if patch is not None:
        patch = patch.resolve()
        if not patch.is_file():
            raise RuntimeError(f"legacy patch not found: {patch}")
        run_checked(["git", "apply", "--check", str(patch)], cwd=destination, env=env, timeout=30)
        run_checked(["git", "apply", str(patch)], cwd=destination, env=env, timeout=30)


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text())


def run_phase(
    binary: Path,
    source_dir: Path,
    base_env: dict[str, str],
    work_dir: Path,
    mode: str,
    *,
    budget_s: float,
    marker_required: bool = False,
) -> dict[str, Any]:
    result_path = work_dir / f"{mode}-result.json"
    marker = work_dir / f"{mode}-ready"
    cancel_marker = work_dir / f"{mode}-cancelled"
    for path in (result_path, marker, cancel_marker):
        path.unlink(missing_ok=True)
    env = dict(base_env)
    env.update({
        "KOALA_WITNESS_MODE": mode,
        "KOALA_WITNESS_DB": str(work_dir / "legacy-stage-a.db"),
        "KOALA_WITNESS_RESULT": str(result_path),
        "KOALA_WITNESS_RANKING_INPUT": str(work_dir / "ranking-input.bin"),
        "KOALA_WITNESS_MARKER": str(marker),
        "KOALA_WITNESS_CANCEL_MARKER": str(cancel_marker),
    })
    process = subprocess.Popen(
        [str(binary), f"-test.run=^{GO_TEST_NAME}$", "-test.v"],
        cwd=source_dir,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    marker_deadline = time.monotonic() + 120
    if marker_required:
        while not marker.exists() and process.poll() is None and time.monotonic() < marker_deadline:
            time.sleep(0.01)
        if not marker.exists():
            output = process.communicate(timeout=5)[0] if process.poll() is not None else ""
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                output += process.communicate()[0]
            raise RuntimeError(f"{mode} did not reach measured section: {output[-2_000:]}")
    measured_started = time.monotonic()
    try:
        output = process.communicate(timeout=budget_s)[0]
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        output = process.communicate()[0]
        return {
            "status": "timeout",
            "budget_s": budget_s,
            "elapsed_s": time.monotonic() - measured_started,
            "process_returncode": process.returncode,
            "output_tail": output[-1_000:],
        }
    if process.returncode:
        raise RuntimeError(f"{mode} failed ({process.returncode}): {output[-2_000:]}")
    if not result_path.exists():
        raise RuntimeError(f"{mode} completed without a result")
    receipt = load_json(result_path)
    receipt["process_returncode"] = process.returncode
    return receipt


def classify(phases: dict[str, dict[str, Any]]) -> dict[str, Any]:
    scans = [phases[name]["scan_s"] for name in ("scan_first", "scan_warm")]
    scan_max = max(scans)
    rank = phases["rank"]
    if scan_max >= SERVER_CONTEXT_S:
        bottleneck = "posting-scan"
    elif rank["status"] == "timeout" and rank["budget_s"] >= SERVER_CONTEXT_S:
        bottleneck = "ranking"
    elif rank["status"] == "completed" and rank.get("elapsed_s", 0) > scan_max:
        bottleneck = "ranking"
    else:
        bottleneck = "unresolved"
    return {
        "bottleneck": bottleneck,
        "posting_scan_exceeds_server_context": scan_max >= SERVER_CONTEXT_S,
        "ranking_exceeds_server_context": (
            rank["status"] == "timeout" and rank["budget_s"] >= SERVER_CONTEXT_S
        ) or (
            rank["status"] == "completed" and rank.get("elapsed_s", 0) >= SERVER_CONTEXT_S
        ),
        "whole_search_exceeds_server_context": any(
            phases[name]["status"] == "timeout"
            or phases[name].get("elapsed_s", 0) >= SERVER_CONTEXT_S
            for name in ("whole_first", "whole_warm")
        ),
        "pre_cancel_returned_within_2s": (
            phases["pre-cancel"]["status"] == "completed"
            and phases["pre-cancel"].get("elapsed_s", float("inf")) < 2
            and phases["pre-cancel"].get("search_error") == "context canceled"
            and phases["pre-cancel"].get("ctx_error") == "context canceled"
        ),
        "mid_scan_cancel_returned_within_2s": (
            phases["mid-cancel"]["status"] == "completed"
            and phases["mid-cancel"].get("elapsed_s", float("inf")) < 2
            and phases["mid-cancel"].get("search_error") == "context canceled"
            and phases["mid-cancel"].get("ctx_error") == "context canceled"
        ),
    }


def directory_bytes(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def execute(
    repo: Path,
    go_binary: Path,
    output: Path,
    keep_workdir: bool,
    patch: Path | None = None,
) -> dict[str, Any]:
    owner = tempfile.mkdtemp(prefix="koala-legacy-fts-witness-")
    work_dir = Path(owner)
    (work_dir / "tmp").mkdir()
    source_dir = work_dir / "source"
    env = sanitized_env(go_binary, work_dir)
    try:
        extract_revision(repo, source_dir, env, patch)
        test_path = source_dir / "internal" / "index" / "fts" / "koala_legacy_witness_test.go"
        test_path.write_text(GO_TEST_SOURCE)
        binary = work_dir / "legacy-fts-witness.test"
        run_checked(
            [str(go_binary), "test", "-c", "-o", str(binary), "./internal/index/fts"],
            cwd=source_dir,
            env=env,
            timeout=300,
        )
        phases: dict[str, dict[str, Any]] = {}
        phases["build"] = run_phase(binary, source_dir, env, work_dir, "build", budget_s=1_200)
        if phases["build"]["status"] != "completed":
            raise RuntimeError(f"fixture build did not complete: {phases['build']}")
        if phases["build"].get("posting_count") != PRIMARY_RECORD_COUNT:
            raise RuntimeError(f"fixture posting count mismatch: {phases['build']}")
        phases["build"]["fixture_bytes"] = directory_bytes(work_dir / "legacy-stage-a.db")
        phases["whole_first"] = run_phase(
            binary, source_dir, env, work_dir, "whole", budget_s=SERVER_CONTEXT_S,
            marker_required=True,
        )
        phases["whole_warm"] = run_phase(
            binary, source_dir, env, work_dir, "whole", budget_s=SERVER_CONTEXT_S,
            marker_required=True,
        )
        phases["scan_first"] = run_phase(binary, source_dir, env, work_dir, "scan", budget_s=120)
        phases["scan_warm"] = run_phase(binary, source_dir, env, work_dir, "scan", budget_s=120)
        phases["rank"] = run_phase(
            binary, source_dir, env, work_dir, "rank", budget_s=SERVER_CONTEXT_S,
            marker_required=True,
        )
        phases["pre-cancel"] = run_phase(
            binary, source_dir, env, work_dir, "pre-cancel", budget_s=2,
            marker_required=True,
        )
        phases["mid-cancel"] = run_phase(
            binary, source_dir, env, work_dir, "mid-cancel", budget_s=2,
            marker_required=True,
        )
        receipt = {
            "schema_version": 1,
            "status": "MEASURED",
            "source": {
                "repository": str(repo),
                "revision": BASELINE_SOURCE_REVISION,
                "patch": str(patch.resolve()) if patch is not None else None,
                "patch_sha256": hashlib.sha256(patch.resolve().read_bytes()).hexdigest() if patch is not None else None,
                "test_injection": "temporary extracted archive only",
            },
            "corpus": {
                "total_records": TOTAL_RECORD_COUNT,
                "primary_vault_records": PRIMARY_RECORD_COUNT,
                "payload_bytes": PAYLOAD_BYTES,
                "top_k": TOP_K,
                "query_contexts": list(QUERY_CONTEXTS),
                "actual_fts_inputs": ["concept", "createdBy", "content", "tags"],
                "entity_metadata_indexed_by_fts": False,
                "shared_posting_term": "stage",
            },
            "phases": phases,
            "verdict": classify(phases),
            "limitations": [
                "The focused fixture contains the exact stage posting cardinality and score inputs, not the complete multi-term 6.5 GiB store; scan timing is therefore a lower-bound diagnostic.",
                "Legacy concept/tag key overwrite order was nondeterministic; digest parity supplies a deterministic source-valid mixture for enriched records.",
                "Synthetic IDs preserve cardinality and key order but are not the deleted run's original ULIDs.",
                "First-open and warm labels describe process and Pebble cache state; the harness does not drop host kernel caches.",
            ],
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_suffix(output.suffix + ".tmp")
        temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
        temporary.replace(output)
        if keep_workdir:
            receipt["workdir"] = str(work_dir)
        return receipt
    finally:
        if not keep_workdir:
            shutil.rmtree(work_dir, ignore_errors=True)


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[1])
    result.add_argument("--go", help="Go executable; auto-detected when omitted")
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--patch", type=Path, help="Patch to apply to the extracted exact source")
    result.add_argument("--keep-workdir", action="store_true")
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    receipt = execute(
        args.repo.resolve(),
        find_go(args.go),
        args.output.resolve(),
        args.keep_workdir,
        args.patch,
    )
    print(json.dumps({"status": receipt["status"], "verdict": receipt["verdict"], "output": str(args.output.resolve())}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
