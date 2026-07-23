#!/usr/bin/env python3
"""Qualify a digest-pinned Koala MuninnDB RC using synthetic data only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

CANDIDATE_REPOSITORY = "ghcr.io/koala-optics/muninndb"
BASELINE_REPOSITORIES = {"ghcr.io/scrypster/muninndb", CANDIDATE_REPOSITORY}
DIGEST_REF = re.compile(r"^(?P<repository>[a-z0-9./_-]+)@sha256:(?P<digest>[0-9a-f]{64})$")
PRODUCTION_ENV_KEYS = {
    "MUNINNDB_URL", "MUNINNDB_KEY", "MUNINN_MCP_TOKEN", "MUNINN_ENRICH_URL",
    "MUNINN_ANTHROPIC_KEY", "MUNINN_ENRICH_API_KEY", "MUNINN_OPENAI_KEY",
    "MUNINN_OPENAI_URL", "MUNINN_VOYAGE_KEY", "MUNINN_OLLAMA_URL",
    "ANTHROPIC_API_KEY", "OPENAI_API_KEY",
}
PRODUCTION_MARKERS = ("muninn.koalalifestyle.com", "koalalifestyle.com", "production", "prod-")
REQUIRED_TOOLS = {
    "muninn_remember", "muninn_read", "muninn_forget", "muninn_restore",
    "muninn_state", "muninn_find_by_entity", "muninn_find_by_concept",
}
REQUIRED_GATES = (
    "baseline_fixture", "migration_v4", "migration_idempotence", "exact_concept",
    "newest_first_entity", "lifecycle_filtering", "clean_restart", "crash_restart",
    "hard_delete_cleanup", "backup_restore",
)


class QualificationError(RuntimeError):
    """A deterministic RC gate failed."""


@dataclass
class Container:
    name: str
    image: str
    data_dir: Path
    network: str
    env_file: Path
    log_path: Path
    container_ip: str = field(default="", init=False)

    @property
    def mcp_url(self) -> str:
        if not self.container_ip:
            raise QualificationError(f"container {self.name} has no verified internal address")
        return f"http://{self.container_ip}:8750/mcp"

    def start(self, timeout: float = 90.0) -> None:
        run_command(build_container_command(
            name=self.name, image=self.image, data_dir=self.data_dir,
            network=self.network, env_file=self.env_file,
        ))
        network_info = json.loads(run_command([
            "docker", "network", "inspect", self.network,
        ]).stdout)[0]
        if network_info.get("Internal") is not True:
            self.capture_logs()
            self.remove(force=True)
            raise QualificationError(f"Docker network {self.network} is not internal")
        container_info = network_info.get("Containers", {}).get(
            run_command([
                "docker", "inspect", "--format", "{{.Id}}", self.name,
            ]).stdout.strip(),
            {},
        )
        self.container_ip = str(container_info.get("IPv4Address", "")).split("/", 1)[0]
        if not self.container_ip:
            self.capture_logs()
            self.remove(force=True)
            raise QualificationError(
                f"container {self.name} has no address on internal network {self.network}"
            )
        deadline = time.monotonic() + timeout
        try:
            while time.monotonic() < deadline:
                state = run_command(
                    ["docker", "inspect", "--format", "{{.State.Status}} {{.State.ExitCode}}", self.name],
                    check=False,
                ).stdout.strip()
                if state.startswith(("exited", "dead")):
                    raise QualificationError(f"container {self.name} exited before readiness: {state}")
                try:
                    with socket.create_connection((self.container_ip, 8750), timeout=1.0):
                        return
                except OSError:
                    time.sleep(0.25)
            raise QualificationError(f"container {self.name} readiness timed out after {timeout}s")
        except Exception:
            self.capture_logs()
            self.remove(force=True)
            raise

    def capture_logs(self) -> str:
        completed = run_command(["docker", "logs", self.name], check=False)
        text = completed.stdout + completed.stderr
        if completed.returncode != 0 and self.log_path.exists():
            return self.log_path.read_text(encoding="utf-8")
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.log_path.write_text(text, encoding="utf-8")
        return text

    def stop(self) -> str:
        run_command(["docker", "stop", "--time", "30", self.name])
        logs = self.capture_logs()
        self.remove()
        return logs

    def kill(self) -> str:
        run_command(["docker", "kill", "--signal", "KILL", self.name])
        logs = self.capture_logs()
        self.remove(force=True)
        return logs

    def remove(self, force: bool = False) -> None:
        command = ["docker", "rm"] + (["--force"] if force else []) + [self.name]
        run_command(command, check=False)


class MCPClient:
    def __init__(self, url: str, token: str, timeout: float, *, internal_address: str = ""):
        if not is_harness_url(url, internal_address):
            raise QualificationError(f"refusing unverified MCP URL: {url}")
        self.url, self.token, self.timeout, self.request_id = url, token, timeout, 0

    def _post(self, payload: dict[str, Any]) -> dict[str, Any]:
        request = urllib.request.Request(
            self.url, data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json", "Accept": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(
                request, timeout=self.timeout,
            ) as response:
                parsed = json.loads(response.read().decode("utf-8"))
        except (OSError, ValueError, urllib.error.URLError) as exc:
            raise QualificationError(f"MCP transport failure: {exc}") from exc
        if parsed.get("error"):
            raise QualificationError(f"MCP JSON-RPC error: {parsed['error']}")
        return parsed

    def initialize(self) -> None:
        self.request_id += 1
        self._post({"jsonrpc": "2.0", "method": "initialize", "params": {
            "protocolVersion": "2024-11-05", "capabilities": {},
            "clientInfo": {"name": "koala-rc-qualification", "version": "1"}}, "id": self.request_id})

    def list_tools(self) -> set[str]:
        self.request_id += 1
        response = self._post({"jsonrpc": "2.0", "method": "tools/list", "params": {}, "id": self.request_id})
        return {item.get("name", "") for item in response.get("result", {}).get("tools", []) if isinstance(item, dict)}

    @staticmethod
    def decode_tool_result(method: str, result: Any) -> Any:
        if isinstance(result, dict) and result.get("error"):
            raise QualificationError(f"{method} application error: {result['error']}")
        return result

    def call(self, method: str, arguments: dict[str, Any]) -> tuple[Any, float]:
        self.request_id += 1
        started = time.monotonic()
        response = self._post({"jsonrpc": "2.0", "method": "tools/call",
            "params": {"name": method, "arguments": arguments}, "id": self.request_id})
        latency_ms = (time.monotonic() - started) * 1000
        content = response.get("result", {}).get("content", [])
        if not content or not isinstance(content[0], dict) or content[0].get("text") is None:
            raise QualificationError(f"{method} returned no text MCP content")
        raw = content[0]["text"]
        try:
            result = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            result = {"raw": raw}
        return self.decode_tool_result(method, result), latency_ms


def is_harness_url(url: str, internal_address: str = "") -> bool:
    match = re.fullmatch(r"http://(?P<host>[^/:]+):(?P<port>[0-9]+)/mcp", url)
    if not match:
        return False
    host = match.group("host")
    if host in {"127.0.0.1", "localhost"}:
        return True
    return bool(internal_address) and host == internal_address and match.group("port") == "8750"


def validate_image_ref(ref: str, repositories: set[str] | None = None) -> str:
    match = DIGEST_REF.fullmatch(ref)
    if not match:
        raise QualificationError(f"image must be pinned by sha256 digest: {ref}")
    if match.group("repository") not in (repositories or {CANDIDATE_REPOSITORY}):
        raise QualificationError(f"image repository is not allowed: {match.group('repository')}")
    return ref


def docker_subprocess_environment() -> dict[str, str]:
    return {key: value for key, value in os.environ.items() if key not in PRODUCTION_ENV_KEYS}


def run_command(command: list[str], *, check: bool = True, timeout: float = 600.0) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, env=docker_subprocess_environment())
    if check and completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise QualificationError(f"command failed ({completed.returncode}): {' '.join(command)}\n{detail}")
    return completed


def build_container_command(*, name: str, image: str, data_dir: Path, network: str, env_file: Path) -> list[str]:
    validate_image_ref(image, BASELINE_REPOSITORIES)
    return [
        "docker", "run", "--detach", "--name", name, "--network", network,
        "--env-file", str(env_file.resolve()),
        "--mount", f"type=bind,src={data_dir.resolve()},dst=/data", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m", "--security-opt", "no-new-privileges:true",
        "--cap-drop", "ALL", image, "--daemon", "--data", "/data", "--listen-host", "0.0.0.0",
        "--mbp-addr", "0.0.0.0:8474", "--rest-addr", "0.0.0.0:8475",
        "--ui-addr", "0.0.0.0:8476", "--grpc-addr", "0.0.0.0:8477", "--mcp-addr", "0.0.0.0:8750",
    ]


def prepare_work_directory(path: Path | None) -> tuple[Path, bool]:
    if path is None:
        return Path(tempfile.mkdtemp(prefix="koala-muninndb-rc-")), True
    resolved = path.resolve()
    if resolved.exists() and any(resolved.iterdir()):
        raise QualificationError(f"explicit work directory must be empty: {resolved}")
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved, False


def atomic_write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def synthetic_manifest() -> list[dict[str, Any]]:
    concept, entity = "rc/synthetic/exact-concept", "RC Synthetic Entity 7F3A"
    return [{
        "key": f"item-{index}", "concept": concept,
        "content": json.dumps({"synthetic": True, "sequence": index}, sort_keys=True),
        "entities": [{"name": entity, "type": "concept"}],
        "created_at": f"2026-01-01T00:00:0{index}Z",
    } for index in range(1, 4)]


def manifest_hash(manifest: list[dict[str, Any]]) -> str:
    encoded = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def result_id(result: Any) -> str:
    if isinstance(result, dict):
        for key in ("id", "memory_id", "engram_id"):
            if result.get(key):
                return str(result[key])
    raise QualificationError(f"tool result returned no engram ID: {result}")


def result_ids(result: Any) -> list[str]:
    if not isinstance(result, dict) or not isinstance(result.get("engrams"), list):
        return []
    return [str(item["id"]) for item in result["engrams"] if isinstance(item, dict) and item.get("id")]


def assert_exact_concept_result(result: Any, concept: str, expected_ids: list[str]) -> None:
    if not isinstance(result, dict) or result.get("concept") != concept or result.get("count") != len(expected_ids):
        raise QualificationError(f"exact-concept envelope mismatch: {result}")
    actual = result_ids(result)
    if actual != expected_ids:
        raise QualificationError(f"exact-concept IDs/order mismatch: {actual} != {expected_ids}")


def assert_entity_result(result: Any, expected_ids: list[str]) -> None:
    if not isinstance(result, dict) or result.get("count") != len(expected_ids):
        raise QualificationError(f"entity result envelope mismatch: {result}")
    actual = result_ids(result)
    if actual != expected_ids:
        raise QualificationError(f"entity IDs/order mismatch: {actual} != {expected_ids}")


def remember_fixture(client: MCPClient, manifest: list[dict[str, Any]]) -> tuple[list[str], list[float]]:
    ids, latencies = [], []
    for item in manifest:
        result, latency = client.call("muninn_remember", {
            "vault": "rc-synthetic", "concept": item["concept"], "content": item["content"],
            "entities": item["entities"], "created_at": item["created_at"], "confidence": 1.0,
            "tags": ["koala-rc", "synthetic-only"], "op_id": f"koala-rc-{item['key']}",
        })
        ids.append(result_id(result))
        latencies.append(latency)
        time.sleep(0.01)
    return ids, latencies


def verify_lookup_state(client: MCPClient, *, concept: str, entity: str, expected_ids: list[str]) -> dict[str, float]:
    concept_result, concept_ms = client.call("muninn_find_by_concept", {
        "vault": "rc-synthetic", "concept": concept, "limit": 50})
    entity_result, entity_ms = client.call("muninn_find_by_entity", {
        "vault": "rc-synthetic", "entity_name": entity, "limit": 50})
    assert_exact_concept_result(concept_result, concept, expected_ids)
    assert_entity_result(entity_result, expected_ids)
    return {"concept_ms": round(concept_ms, 3), "entity_ms": round(entity_ms, 3)}


def ensure_image(ref: str, repositories: set[str]) -> dict[str, str]:
    validate_image_ref(ref, repositories)
    run_command(["docker", "pull", ref], timeout=1200)
    image_id = run_command(["docker", "image", "inspect", "--format", "{{.Id}}", ref]).stdout.strip()
    architecture = run_command(["docker", "image", "inspect", "--format", "{{.Architecture}}", ref]).stdout.strip()
    return {"ref": ref, "image_id": image_id, "architecture": architecture}


def offline_command(image: str, work_dir: Path, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    validate_image_ref(image)
    return run_command([
        "docker", "run", "--rm", "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m", "--security-opt", "no-new-privileges:true",
        "--cap-drop", "ALL", "--mount", f"type=bind,src={work_dir.resolve()},dst=/work",
        "--entrypoint", "muninndb-server", image, *arguments,
    ])


def validate_receipt(receipt: dict[str, Any]) -> None:
    if receipt.get("schema_version") != 1 or receipt.get("status") != "passed":
        raise QualificationError("receipt is not a passing schema-v1 qualification")
    isolation = receipt.get("isolation", {})
    if (
        isolation.get("synthetic_only") is not True
        or isolation.get("host_ports_published") != []
        or isolation.get("internal_network") is not True
    ):
        raise QualificationError("receipt does not prove synthetic network isolation")
    for role in ("candidate", "baseline"):
        if "@sha256:" not in receipt.get("images", {}).get(role, {}).get("ref", ""):
            raise QualificationError(f"receipt {role} image is not digest-pinned")
    missing = [name for name in REQUIRED_GATES if receipt.get("gates", {}).get(name, {}).get("passed") is not True]
    if missing:
        raise QualificationError(f"receipt gates missing or failed: {', '.join(missing)}")


def write_env_file(path: Path, token: str) -> None:
    path.write_text(
        f"MUNINN_MCP_TOKEN={token}\nMUNINN_LOCAL_EMBED=0\nMUNINN_MEM_LIMIT_GB=2\n",
        encoding="utf-8",
    )
    path.chmod(0o600)


def gate(receipt: dict[str, Any], name: str, **details: Any) -> None:
    receipt["gates"][name] = {"passed": True, **details}


def new_container(*, name: str, image: str, data_dir: Path, network: str,
                  env_file: Path, logs_dir: Path) -> Container:
    return Container(name, image, data_dir, network, env_file,
                     logs_dir / f"{name}.log")


def start_client(container: Container, token: str, args: argparse.Namespace) -> MCPClient:
    container.start(args.startup_timeout)
    client = MCPClient(
        container.mcp_url, token, args.call_timeout,
        internal_address=container.container_ip,
    )
    client.initialize()
    return client



def qualify(args: argparse.Namespace) -> dict[str, Any]:
    candidate = validate_image_ref(args.candidate_image)
    baseline = validate_image_ref(args.baseline_image, BASELINE_REPOSITORIES)
    work_dir, temporary = prepare_work_directory(args.work_dir)
    data_dir, backup_dir = work_dir / "data", work_dir / "backup"
    env_file, logs_dir = work_dir / "synthetic.env", work_dir / "logs"
    token, network = secrets.token_urlsafe(32), f"koala-rc-{secrets.token_hex(6)}"
    manifest = synthetic_manifest()
    concept, entity = manifest[0]["concept"], manifest[0]["entities"][0]["name"]
    data_dir.mkdir(mode=0o700)
    data_dir.chmod(0o777)
    logs_dir.mkdir(mode=0o700)
    write_env_file(env_file, token)
    receipt: dict[str, Any] = {
        "schema_version": 1, "status": "running",
        "source": {"commit": args.source_commit, "tag": args.source_tag},
        "images": {},
        "assets": {
            "go_version": args.go_version, "model_sha256": args.model_sha256,
            "tokenizer_sha256": args.tokenizer_sha256,
            "onnxruntime_sha256": args.onnxruntime_sha256,
        },
        "isolation": {
            "synthetic_only": True, "host_ports_published": [], "internal_network": True,
            "runner_access": "verified Docker-internal bridge address",
            "production_environment_keys_removed": sorted(PRODUCTION_ENV_KEYS),
        },
        "fixture": {"count": len(manifest), "manifest_sha256": manifest_hash(manifest)},
        "gates": {},
        "limitations": [
            "Synthetic durability qualification is not production-load qualification.",
            "No production data, credentials, URLs, volumes, backups, or retained forensic volumes were used.",
        ],
    }
    active: Container | None = None
    started = time.monotonic()
    run_command(["docker", "network", "create", "--internal", network])
    try:
        receipt["images"]["candidate"] = ensure_image(candidate, {CANDIDATE_REPOSITORY})
        receipt["images"]["baseline"] = ensure_image(baseline, BASELINE_REPOSITORIES)

        active = new_container(name="koala-rc-baseline", image=baseline, data_dir=data_dir,
            network=network, env_file=env_file, logs_dir=logs_dir)
        baseline_client = start_client(active, token, args)
        missing = sorted((REQUIRED_TOOLS - {"muninn_find_by_concept"}) - baseline_client.list_tools())
        if missing:
            raise QualificationError(f"baseline is missing tools: {', '.join(missing)}")
        ids_oldest, write_ms = remember_fixture(baseline_client, manifest)
        for memory_id in ids_oldest:
            baseline_client.call("muninn_read", {"vault": "rc-synthetic", "id": memory_id})
        active.stop()
        active = None
        gate(receipt, "baseline_fixture", ids_oldest_first=ids_oldest,
            write_samples_ms=[round(value, 3) for value in write_ms])

        expected = list(reversed(ids_oldest))
        active = new_container(name="koala-rc-migration", image=candidate, data_dir=data_dir,
            network=network, env_file=env_file, logs_dir=logs_dir)
        client = start_client(active, token, args)
        missing = sorted(REQUIRED_TOOLS - client.list_tools())
        if missing:
            raise QualificationError(f"candidate is missing tools: {', '.join(missing)}")
        timings = verify_lookup_state(client, concept=concept, entity=entity, expected_ids=expected)
        migration_logs = active.stop()
        active = None
        if "migrations applied" not in migration_logs:
            raise QualificationError("candidate startup did not report applying migration v4")
        gate(receipt, "migration_v4", backfilled_ids=expected,
            startup_log_sha256=hashlib.sha256(migration_logs.encode()).hexdigest())
        gate(receipt, "exact_concept", latency_ms=timings["concept_ms"])
        gate(receipt, "newest_first_entity", latency_ms=timings["entity_ms"])

        active = new_container(name="koala-rc-idempotent", image=candidate, data_dir=data_dir,
            network=network, env_file=env_file, logs_dir=logs_dir)
        client = start_client(active, token, args)
        verify_lookup_state(client, concept=concept, entity=entity, expected_ids=expected)
        idempotent_logs = active.stop()
        active = None
        if "migrations applied" in idempotent_logs:
            raise QualificationError("migration unexpectedly re-applied on second candidate start")
        gate(receipt, "migration_idempotence")
        gate(receipt, "clean_restart")

        active = new_container(name="koala-rc-lifecycle", image=candidate, data_dir=data_dir,
            network=network, env_file=env_file, logs_dir=logs_dir)
        client = start_client(active, token, args)
        newest, middle, oldest = expected
        client.call("muninn_state", {"vault": "rc-synthetic", "id": newest,
            "state": "archived", "reason": "synthetic RC gate"})
        verify_lookup_state(client, concept=concept, entity=entity, expected_ids=[middle, oldest])
        client.call("muninn_forget", {"vault": "rc-synthetic", "id": middle})
        verify_lookup_state(client, concept=concept, entity=entity, expected_ids=[oldest])
        restored, _ = client.call("muninn_restore", {"vault": "rc-synthetic", "id": middle})
        if not isinstance(restored, dict) or restored.get("restored") is not True:
            raise QualificationError(f"restore did not report success: {restored}")
        verify_lookup_state(client, concept=concept, entity=entity, expected_ids=[middle, oldest])
        gate(receipt, "lifecycle_filtering")
        active.kill()
        active = None

        active = new_container(name="koala-rc-crash-restart", image=candidate, data_dir=data_dir,
            network=network, env_file=env_file, logs_dir=logs_dir)
        client = start_client(active, token, args)
        verify_lookup_state(client, concept=concept, entity=entity, expected_ids=[middle, oldest])
        active.stop()
        active = None
        gate(receipt, "crash_restart")

        hard_delete = offline_command(candidate, work_dir, [
            "exec", "forget", "--data-dir", "/work/data", "--vault", "rc-synthetic", "--id", oldest])
        active = new_container(name="koala-rc-hard-delete", image=candidate, data_dir=data_dir,
            network=network, env_file=env_file, logs_dir=logs_dir)
        client = start_client(active, token, args)
        verify_lookup_state(client, concept=concept, entity=entity, expected_ids=[middle])
        active.stop()
        active = None
        gate(receipt, "hard_delete_cleanup",
            command_output_sha256=hashlib.sha256(hard_delete.stdout.encode()).hexdigest())

        backup_dir.mkdir(mode=0o700)
        backup_dir.chmod(0o777)
        backup = offline_command(candidate, work_dir, [
            "backup", "--data-dir", "/work/data", "--output", "/work/backup"])
        if not (backup_dir / "pebble").is_dir():
            raise QualificationError("offline backup did not produce a Pebble checkpoint")
        active = new_container(name="koala-rc-restore", image=candidate, data_dir=backup_dir,
            network=network, env_file=env_file, logs_dir=logs_dir)
        client = start_client(active, token, args)
        verify_lookup_state(client, concept=concept, entity=entity, expected_ids=[middle])
        read_result, _ = client.call("muninn_read", {"vault": "rc-synthetic", "id": middle})
        if result_id(read_result) != middle:
            raise QualificationError("restored read returned the wrong engram")
        active.stop()
        active = None
        gate(receipt, "backup_restore",
            backup_output_sha256=hashlib.sha256(backup.stdout.encode()).hexdigest())

        receipt["duration_seconds"] = round(time.monotonic() - started, 3)
        receipt["status"] = "passed"
        validate_receipt(receipt)
        atomic_write_json(args.output.resolve(), receipt)
        return receipt
    except Exception as exc:
        receipt["status"] = "failed"
        receipt["failure"] = {"type": type(exc).__name__, "message": str(exc)}
        receipt["duration_seconds"] = round(time.monotonic() - started, 3)
        atomic_write_json(args.output.resolve(), receipt)
        raise
    finally:
        if active is not None:
            active.capture_logs()
            active.remove(force=True)
        run_command(["docker", "network", "rm", network], check=False)
        env_file.unlink(missing_ok=True)
        if temporary and not args.keep_work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)



def sha256_arg(value: str) -> str:
    if value and (len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value)):
        raise argparse.ArgumentTypeError("must be an empty string or lowercase SHA-256 digest")
    return value


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--baseline-image", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tag", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--keep-work-dir", action="store_true")
    parser.add_argument("--startup-timeout", type=float, default=120.0)
    parser.add_argument("--call-timeout", type=float, default=30.0)
    parser.add_argument("--go-version", default="")
    parser.add_argument("--model-sha256", type=sha256_arg, default="")
    parser.add_argument("--tokenizer-sha256", type=sha256_arg, default="")
    parser.add_argument("--onnxruntime-sha256", type=sha256_arg, default="")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        receipt = qualify(args)
    except QualificationError as exc:
        print(f"RC qualification failed: {exc}", file=os.sys.stderr)
        return 1
    print(json.dumps({"status": receipt["status"], "output": str(args.output.resolve())}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
