[source-first | primary: current Fly Machine update, health-check, deployment-strategy, volume, snapshot, rollback, release-command, restart, and restart-policy documentation | cache: none | status: observed]

# Koala MuninnDB Stage B production-readiness runbook

> **NO PRODUCTION AUTHORIZATION**
>
> This document and any packet validated by `scripts/koala_stage_b_packet.py`
> are readiness artifacts only. Stage A qualified a candidate; it did not approve
> a production preflight or change. A later read-only production preflight requires
> separate authorization. Any production execution requires another, subsequent
> authorization bound to one exact target fingerprint, evidence digest, maintenance
> window, and reviewed plan. The strongest packet result is
> `READY_FOR_AUTHORIZATION`, never `AUTHORIZED` or `READY_TO_DEPLOY`.

## 1. Authority and scope

This runbook is the canonical Stage B operator contract for the Koala MuninnDB
RC2 candidate. It converts the retained Stage A evidence into a fail-closed list
of facts that must be established before a production change can even be
considered.

This runbook does **not** authorize or provide an automated path to:

- inspect Fly production or read production data;
- retrieve credentials, endpoints, secrets, or production URLs;
- create a checkpoint, snapshot, Machine, or volume;
- deploy, restart, migrate, rebuild an index, or change routing or resolvers;
- infer that a recorded app, Machine, volume, writer, or ingress path is still
  current.

The packet generator and validator are deliberately offline. The packet pins
publicly qualified Stage A artifact identities, then stores only hashes and gate
states for live production evidence. It never stores live target identifiers,
URLs, credentials, configurations, or evidence bodies. Evidence referenced by
those hashes remains private and independently reviewable.

## 2. Immutable Stage A qualification manifest

The following identities are fixed inputs. Drift is a `NO_GO`; do not substitute
a newer tag, mutable image reference, or similar-looking receipt.

| Item | Qualified identity |
|---|---|
| Candidate source commit | `acef6bedbbd839f9616415e6a7559ad149dc8bc8` |
| Candidate source tag | `koala-v0.9.0-rc.2` |
| Candidate image | `ghcr.io/koala-optics/muninndb@sha256:5cc1546b854e6b173181ceed139ade783751c1e58bea504bc57cb0a7fa4019df` |
| Rollback-rescue image | `ghcr.io/koala-optics/muninndb@sha256:52cad8cce1a0dca7b6e64f5bffafe1a0c677667c49112513cc3ad463a953594b` |
| Stage A baseline image | `registry.fly.io/koala-muninndb:deployment-01KSWRX9GKW5M94MQQCBZSJZHS` |
| Stage A baseline digest | `sha256:c06842e1452f2aab4c1f01207adf9406bfe757b4984da516568006f1f5c8ad86` |
| Harness/target merge | `880b692832ea3947b95b679839161d514f0cf883` on `koala/v0.9.0-compat` |
| Stage A workflow run | `30347311896` |
| Stage A receipt SHA-256 | `dffdfbf015a4b17ef073bb09fb8568fe4333c31ec4b4e713c18ba6f029c0f2ed` |
| Stage A cleanup SHA-256 | `46ac8f52022679f2bbcf74687a3d6b21bd79ff2827bc5d08a792834c3df32541` |
| Accepted records | `502,385` |
| Required gates passed | `16 of 16` |

Implementation receipts:

- `scripts/koala_stage_a_rehearsal.py` contains the qualified retained-Machine,
  clone-only migration, rollback-rescue, acceptance, and cleanup behavior.
- `.github/workflows/koala-stage-a-rehearse.yml` binds the executable rehearsal
  to explicit identities and confirmation.
- `scripts/patches/legacy-be975fb-rescue.Dockerfile` and
  `.github/workflows/koala-rollback-rescue-build.yml` define the immutable
  rollback-rescue artifact.

Stage A measured the synthetic 502,385-record corpus. It did not observe current
production topology, contents, writers, traffic, free space, health, configuration,
or credentials. Any production identifiers embedded in older guards are stale
hypotheses until a separately authorized live preflight observes them.

## 3. Owner-documented Fly constraints

These constraints are load-bearing:

1. A [Machine update](https://fly.io/docs/machines/flyctl/fly-machine-update/)
   merges requested configuration into the existing Machine, recreates it, and
   starts it by default. It waits for startup and configured health checks unless
   directed otherwise. An existing volume attachment cannot be added or removed
   through that update.
2. Fly [service-level health checks](https://fly.io/docs/reference/health-checks/)
   can remove a failing Machine from routing; they do not restart it. The check
   listing's last-updated time represents the last status transition, so a fresh
   execution receipt is required rather than relying on that timestamp alone.
3. The `canary` and `bluegreen` [deployment strategies](https://fly.io/docs/reference/configuration/#the-deploy-section)
   do not support attached volumes. A sole-volume stateful cutover is therefore
   not a zero-downtime or seamless-deployment claim.
4. A [release command](https://fly.io/docs/reference/configuration/#the-deploy-section)
   runs in a temporary Machine without mounted volumes. Do not use it for the
   volume migration.
5. Fly volumes are local, single-host storage and are not automatically
   replicated; application/database replication and failover remain operator
   responsibilities. See the [volume overview](https://fly.io/docs/volumes/overview/).
6. [Volume snapshots](https://fly.io/docs/volumes/snapshots/) are asynchronous.
   Restoring one creates a new equal-or-larger volume. A block snapshot is an
   additional recovery layer, not proof of an application-consistent database
   checkpoint.
7. Fly has no dedicated rollback command. Its [rollback guidance](https://fly.io/docs/blueprints/rollback-guide/)
   redeploys an older image; that does not reverse database contents, schema or
   migrations, configuration, secrets, or extra resources.
8. An operator-triggered [restart](https://fly.io/docs/apps/restart/) and a
   Machine [restart policy](https://fly.io/docs/machines/guides-examples/machine-restart-policy/)
   are different controls. A Machine restart also resets its ephemeral root
   filesystem; durable state must remain on the mounted volume.

## 4. Separately authorized read-only production preflight

No step in this section may run without explicit authorization for the read-only
preflight. Once authorized, capture primary receipts for the following. Record
only receipt hashes in the Stage B packet; keep raw evidence private at mode
`0600`.

### 4.1 Exact target binding

Bind the packet to one hashed target fingerprint and one maintenance window.
The private evidence behind the fingerprint must record:

- current app, Machine, volume, mount, and region topology;
- exact running image digest and MuninnDB version;
- guest resources, restart policy, and full Machine configuration;
- services, configured health checks, ingress, and routing path;
- mounted volume size, state, free space, and snapshot-retention posture;
- whether any unknown, orphaned, duplicate, stopped, or ambiguous resource
  exists.

A name match is not an identity match. Any missing or ambiguous relationship is
`NO_GO`.

### 4.2 MuninnDB and data fingerprints

Capture, without exposing record bodies:

- current status and version;
- logical namespace counts and an agreed count fingerprint;
- point-read witnesses selected before the change;
- semantic-query witnesses and their expected properties;
- current latency and resource baselines;
- WAL syncer and durability health;
- index/rebuild state and any outstanding migration state.

Application errors are failures, never valid empty results. Sampled evidence does
not satisfy a complete count, writer, topology, or restore gate.

### 4.3 Writers, ingress, credentials, and endpoints

Enumerate every writer and every ingress route, including scheduled jobs,
interactive clients, API services, queues, repair tools, and administrative
paths. For each writer, establish an owner and a tested freeze, queue, and replay
procedure. Prove where the write boundary is observed.

Record credential and endpoint **presence only** in packet-facing evidence.
Never print values, production URLs, headers, tokens, or connection strings.
An unknown writer, ingress path, credential owner, or replay behavior is
`NO_GO`.

### 4.4 Backup and restore capability

The required primary backup is an application-consistent Pebble checkpoint:

1. prove all writers are frozen or durably queued;
2. invoke the existing online backup surface while the server is healthy, or
   the offline backup CLI while the server is stopped;
3. require Pebble checkpoint creation and the built-in reopen/scan verification;
4. independently inventory auxiliary state required for the target, including
   WAL and `auth_secret`, and verify each required item was captured;
5. independently restore the checkpoint away from the live target;
6. open and query the restored copy, verifying counts and preselected point reads;
7. verify restored auxiliary state and authentication continuity without exposing
   secret values;
8. hash and retain the receipts.

`cmd/muninn/backup.go` provides the offline path and refuses to run against a
live server. `internal/transport/rest/admin_backup_handler.go` provides the
online checkpoint path. Both current backup paths log or print a warning, but do
not fail the backup, when copying WAL or `auth_secret` fails. Therefore their
successful completion is insufficient evidence for those auxiliary items: the
Stage B receipt must independently inventory, capture, restore, and verify every
required auxiliary item. A Fly block snapshot may supplement this evidence, but
must never replace the application checkpoint plus independent restore/query and
auxiliary-state witnesses.

## 5. Go/no-go gates

Every row must be backed by current primary evidence with a valid observation
and expiry timestamp. `UNKNOWN`, missing, failed, stale, sampled, or
self-attested evidence is `NO_GO`.

| Gate | `GO` evidence | `NO_GO` condition |
|---|---|---|
| Immutable identities | Candidate, rescue, baseline, source, Stage A receipt, and cleanup identities exactly match section 2 | Any drift or mutable substitution |
| Exact target | One complete topology and target fingerprint bound to one maintenance window | Missing, ambiguous, orphaned, or duplicate resource |
| Current baseline | Running image/version/configuration and MuninnDB fingerprints independently observed | Baseline mismatch or unexplained state |
| Writers and ingress | Complete inventory; freeze, queue, replay, and write-boundary tests passed | Unknown writer/path or unproved replay |
| Application backup | Pebble checkpoint plus required auxiliary state independently inventoried, captured, restored, queried, and authentication-continuity verified | Backup success response or Fly snapshot alone, missing auxiliary proof, unreadable restore, or uncertainty |
| Health and routing | Configured service health check plus a fresh observed check | Timestamp-only inference or absent health check |
| Capacity | Disk, placement, guest, backup, and rollback capacity measured sufficient | Threshold breach or unknown headroom |
| Rollback configuration | Exact prior Machine config/image recorded; retained-original and rescue plan verified | Image-only data reversal or no retained original |
| Acceptance | Counts, point reads, semantic probes, latency/resources, restart durability, hard delete, and health criteria defined | Missing criterion or application error |
| Ownership and credentials | Owners and presence verified without exposing values | Missing owner, missing access, or secret exposure |
| Authorization | Still `NOT_AUTHORIZED` while preparing the packet | Any inferred, stale, or packet-generated authorization |

A locally complete packet is prepared as follows:

```text
python scripts/koala_stage_b_packet.py --template /private/path/stage-b.json
# Populate gate states and primary-receipt hashes outside this tool.
# Set readiness_status to READY_FOR_AUTHORIZATION only when every gate is met.
python scripts/koala_stage_b_packet.py --validate /private/path/stage-b.json
```

The validator prints only readiness, packet SHA-256, and safe failing field paths.
It does not inspect evidence, production, credentials, or the environment. A
`READY_FOR_AUTHORIZATION` result means the packet may be presented for a new
decision; it grants nothing.

## 6. Future execution state machine

> **REQUIRES NEW AUTHORIZATION**
>
> The following is a state contract, not standing permission and not an
> executable workflow. Replace no placeholder with a live command until a
> reviewed packet has been approved in a subsequent user turn.

```text
REQUIRES NEW AUTHORIZATION

S0 AUTHORIZED_PACKET_BOUND
  Require exact target fingerprint, packet hash, maintenance window, and approval.

S1 WRITERS_FROZEN
  Freeze or durably queue every writer; prove the write boundary.
  Failure or unknown -> STOP / NO_GO.

S2 RECOVERY_PROVED
  Create and verify an application-consistent Pebble checkpoint. Independently
  prove required auxiliary state was captured, then restore/query the database,
  verify auxiliary restoration and authentication continuity, and optionally add
  a Fly block snapshot.
  Failure or uncertainty -> STOP / NO_GO.

S3 ORIGINAL_RETAINED
  Preserve the original volume and its Machine allocation using the qualified
  retained-Machine supervisor topology. Gracefully stop only MuninnDB, wait for
  the exact child PID, sync, and require the Machine allocation to remain held.
  Snapshot only after quiescence. Failure -> STOP / ROLLBACK_OR_INCIDENT.

S4 CANDIDATE_CLONE_CREATED
  Create the candidate from the preserved source without modifying the original.
  Perform all RC2 migration on the clone. Never migrate through release_command.

S5 CANDIDATE_ISOLATED
  Start without production routing. Verify exact counts, point reads, semantic
  probes, latency/resources, disk headroom, restart durability, hard-delete
  behavior, and fresh service health.
  Any failure -> return to retained original with rollback-rescue reader.

S6 READ_ONLY_SOAK
  Route reads under the approved cutover while all writers remain frozen.
  Observe for at least 30 minutes. Before any candidate write, rollback to the
  untouched original remains lossless.

S7 DISTINCT_WRITE_GO
  Require a new go decision after read-only acceptance. Reopen writers only if
  queue/replay is proved. If no replayable write capture exists, explicitly mark
  the lossless rollback window CLOSED at the first candidate write.

S8 ENHANCED_OBSERVATION
  Observe writes, reads, durability, resources, latency, and health for 24 hours.
  Apply hard rollback triggers; retain receipts and clean up only authorized,
  unambiguous temporary resources.
```

No zero-downtime claim attaches to this state machine. Writer freeze and a
stateful cutover are intentional safety properties.

## 7. Rollback state machine

### 7.1 Before any candidate write

The original volume is untouched and all writers remain frozen. The qualified
lossless path is:

1. remove or stop routing to the candidate;
2. keep the candidate isolated for evidence;
3. update the retained original Machine in place to the pinned rollback-rescue
   image;
4. verify known legacy counts, point reads, status, and health on the original;
5. restore routing only after those observations pass;
6. replay no writes because none were admitted to the candidate.

### 7.2 After any candidate write

Freeze writers first. Never deploy an older image and call that data rollback.
An older image does not reverse candidate-format data, schema changes, migration
state, or configuration.

Proceed only through the packet's already tested path:

- restore a proved application checkpoint and reconcile queued writes; or
- use a proved lossless write capture/replay mechanism to reconcile to the
  selected data state.

If neither path is proved for the actual write window, stop. This is an incident
decision, not a routine rollback. Preserve both sides and escalate rather than
inventing data reconciliation during the event.

### 7.3 Hard triggers

Any one of these triggers freezes progress and selects rollback or incident
handling according to whether candidate writes have begun:

- readiness, service-health, or routing failure;
- logical-count or point-read mismatch;
- semantic-probe failure or application error;
- unexpected write, migration, index, or format behavior;
- restart or durability failure, including WAL syncer degradation;
- latency, memory, CPU, disk, or placement threshold breach;
- backup, restore, checkpoint, replay, or rollback uncertainty;
- an unknown writer, ingress path, resource, owner, credential dependency, or
  orphaned/ambiguous topology.

## 8. Receipts, privacy, and closeout

Keep every Stage B packet and evidence body mode `0600`. The packet may contain
the pinned public Stage A identities in section 2, receipt hashes, and only the
validator's fixed public labels (`MuninnDB RC2 Stage B readiness` and `SCHEDULED`).
Do not add free-form labels, live production target identifiers, URLs, secrets,
credentials, record bodies, raw configurations, or private evidence, and do not
commit or upload the packet itself.

For any later authorized preflight or execution, retain:

- exact commands and exit codes in private evidence;
- evidence timestamps and expirations;
- packet, evidence, checkpoint, snapshot, and cleanup hashes;
- exact source and image digests;
- target and topology fingerprint;
- pre/post counts and point-read witnesses;
- timing, health, latency, and resource results;
- writer-freeze and write-boundary proof;
- backup restore/query and queue/replay proof;
- rollback-window state before and after writer reopen;
- every created resource and its verified cleanup disposition;
- final observed-live state.

Do not call a future production task complete from a command exit, commit label,
packet result, or stale health view. Re-observe the chosen live state, verify the
exact target and cleanup, and preserve that receipt. Qualification, readiness,
authorization, execution, and observed completion remain distinct states.
