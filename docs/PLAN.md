# DOTS 2.0 Phase 1 Plan

Branch per milestone, one PR per milestone. Each PR leaves `main`/`master` green.

## Milestone 1: Repo cleanup and architecture (this PR)

- [x] Remove the vendored Kamailio 5.1.1, PJSIP 2.7.1 and Bitcoin Core trees (no history rewrite).
- [x] Move the 2018 paper to `docs/2018-paper.md`, with a historical-document banner.
- [x] New `README.md` for DOTS 2.0.
- [x] `CLAUDE.md` project brief.
- [x] `docs/ARCHITECTURE.md`: diagrams, receipt, log and settlement data model, and Kamailio design choices.
- [x] `.gitignore` covering keys, certs and `.env`.
- [x] Decisions recorded (see Decisions log); `LICENSE` (Apache-2.0) and `NOTICE` added.

## Milestone 2: Receipt service (no SIP yet) — done

1. `services/common`: JCS wrapper, domain-separated Ed25519 sign/verify, `key_id`, X25519 + HKDF pair keys and dest-hash HMAC, Pydantic v2 models with `extra="forbid"`.
2. RFC 9162 Merkle library: MTH, inclusion and consistency proof generation and verification. Tests include known-answer vectors cross-checked against an independent implementation, plus hypothesis property tests (every inclusion proof verifies for all `(m, n)` up to 512, and every consistency proof verifies; tampered proofs fail).
3. `services/receipts`:
   - Postgres schema (Alembic) with append-only triggers.
   - `/internal/call-end`, the proposal/countersignature flow, and the dispute rules with tolerances.
   - Idempotency on `(orig_node, call_id, from_tag)`.
   - STH publisher, peer monitor (consistency, inclusion, gossip) and `acc` reconciler.
4. Tests:
   - Unit tests.
   - An in-process two-node test, with two apps and two Postgres instances via testcontainers or a compose profile, covering: happy path, each dispute kind, replay, a wrong mTLS identity, and log tampering detected by the peer monitor.
5. `pyproject.toml` (uv workspace), ruff, mypy `--strict`, `.env.example`.

## Milestone 3: Kamailio nodes and the 3-node lab — done

1. Kamailio 6.1.4 image: Debian bookworm with the `kamailio61` repo, including `kamailio-secsipid-modules`. Verify that secsipid loads first; it determines the image choice.
2. `node/kamailio/` config, rendered per node: TLS peering with fingerprint check, registrar, `dmq_usrloc` inside node-a's cluster, DMQ `htable` reachability index across operators, `dialog`, `acc` to Postgres, `secsipid` sign/verify, `rtpengine`, `http_async_client` call-end events.
3. rtpengine mr26.2.1.2 image. Verify the flag set for SRTP passthrough (§8.2) and record the result in ARCHITECTURE.md.
4. `lab/bootstrap`: lab CA, STI-CA, node certs, Ed25519/X25519 keys, `peers.json`, rate table signed by both peers.
5. `docker-compose.yml` and SIPp `normal` scenario. Assertions:
   - every call yields one dual-signed receipt, identical in both logs;
   - inclusion proofs verify against each peer's STH;
   - consistency holds across STH refreshes;
   - the Identity header is verified with the expected attestation;
   - registration on node-a1 is reachable via node-a2 (`dmq_usrloc`).

## Milestone 4: Settlement, fraud gate and payouts — done

1. Rate tables, Decimal netting, interval rounding, cutoff and grace, late adjustments.
2. `FraudGate` protocol with `local_rules` (six rules), the `ovs` stub (config keys, `NotImplementedError`, fail-closed) and verdict composition.
3. Statement JSON and HTML. Engine signature plus peer recompute-and-countersign.
4. Payout: `fiat_stub`, and `stablecoin_testnet` (testnet chain-id allow-list; tested against anvil with a mock USDC in CI; manual Base Sepolia target).
5. SIPp `short_burst` (held) and `duration_mismatch` (disputed) scenarios. `make test` asserts statement totals against values precomputed from the scenario files.

## Milestone 5: MCP server and CI — done

1. `services/mcp` on `mcp` 2.3.0 (`MCPServer`) with read-only tools: `list_peers`, `get_receipt`, `verify_inclusion`, `get_settlement`, `list_disputes`.
2. GitHub Actions: ruff, mypy, pytest, then the lab job (compose up, `make test`, compose down) on `ubuntu-latest`. Kamailio and rtpengine images are built in CI with layer caching.

## Phase 2

Milestones in priority order. Each lands as its own PR with CI green (lint, types, unit, lab).

| # | Milestone | Status |
|---|---|---|
| M6 | Durable call-end spool and reconciler (recover events lost while a receipt service is down) | done |
| M7 | Signed peer registry: each operator signs its own entry; registry = set of signed entries | done |
| M8 | Bind the TLS client certificate to the node identity in the receipt service | done |
| M9 | Per-route fraud baselines (done); Open Voice Shield client (waiting on the OVS webhook/API spec) | in progress |
| M10 | Dispute resolution: re-proposal or adjudication, logged as new entries | done |
| M11 | SRTP end to end: SRTP-capable test agent, pinned rtpengine passthrough flags | |
| M12 | Transit (A→B→C): per-hop receipts chained by a shared reference | |
| M13 | Kamailio 6.1 once `deb.kamailio.org` is reachable from CI | |

### M6: Durable call-end spool — done

- Kamailio writes every call-end event to `call_end_spool` (own database, insert-only role) with `sql_query_async`; the JSON is base64-encoded so no SIP value is quoted into SQL.
- The receipt service reconciles with a cursor; ingestion stays idempotent; malformed rows are skipped and logged by id only.
- Chosen over `acc` CDRs: identical payload to the HTTP event (ms timestamps, attestation, media), so recovered calls bill exactly like delivered ones.
- Tests: reconciler integration tests (recovery, idempotency with HTTP, bad rows, spool unavailable). New lab scenario `recovery` (orig receipt service down for 3 calls, then restarted: normal receipts). The `outage` scenario still yields disputes.

### M7: Signed peer registry — done

- `dots_common.registry`: self-signed entries plus endorsements; membership anchored on the founders' keys and grown by majority endorsement; content changes need a majority of the other members; the newest *qualifying* version wins.
- All services load the registry through verification; a receipt service will not start if its own entry is rejected; `dots-registry verify` CLI.
- The lab bootstrap writes a genesis registry (founders sign and endorse each other) and `anchors.json`.
- Tests: genesis, tampering, unendorsed and singly-endorsed updates, majority-endorsed update, fake member ring, new member admission, role entries, foreign endorsement keys, imposter with the anchored name, unsigned registry refused. Lab: forgeries appended to the live registry change nothing.
- Not yet: signed revocation of members and anchor rotation.

### M8: TLS certificate bound to the signer — done

- `dots_receipts.tlsbind.PeerCertH11Protocol` puts the verified client certificate into the ASGI TLS extension (`client_cert_chain`) for every request on the connection.
- `authenticate()` checks the Ed25519 request signature, then requires the presented certificate's SHA-256 to equal the signer's `tls_cert_sha256` in the signed registry. Mismatch or absence is a 403; TLS without a client certificate fails at the handshake.
- The bootstrap records every member's certificate fingerprint in its signed registry entry.
- Tests over a real TLS socket (uvicorn in-process): matching certificate accepted, another node's certificate refused, no certificate refused, binding switchable. Lab: the observer's certificate carrying node-a's signature is refused by node-b.

### M9: Fraud baselines — done; OVS client — blocked on the API spec

- Per-route daily metrics in the engine store; trailing 7-day baselines (minimum 3 days of history).
- `acd_anomaly` and `asr_anomaly` compare against the route's own history when it exists. The new `volume_spike` rule catches traffic surges. Absolute thresholds remain the fallback.
- Tests: baseline-driven ACD, ASR and volume rules; the minimum-history fallback; the trailing-window maths and idempotent re-recording.
- Open Voice Shield: OVS analyses calls that traverse its own SIP hop and reports verdicts per call by signed webhook. It is not a request/response scoring API, so the brief's "HTTP client" becomes a webhook receiver. What is confirmed so far: the event is `call.analyzed`; the body is signed with HMAC-SHA256 in `X-OVS-Signature`, using a secret set in the OVS portal; and the analysis carries probability, category, recommendation, red flags and a route alert. Still needed: the exact payload field names, how the Call-ID is carried, and the signature's canonical input. Those are in `/api/openapi.json` on `ovs.telecomsxchange.com`, which this environment cannot reach. The stub adapter (config keys, fail-closed) stays until then.

### M10: Dispute resolution — done

- A dispute is settled by re-proposal. The result is an ordinary dual-signed receipt carrying `resolves: <dispute leaf hash>` under the terminating node's signature, logged by both nodes next to the dispute (ARCHITECTURE.md §5.7). The field is omitted on ordinary receipts, so their bytes are unchanged.
- Whoever would lose authorizes. The originator re-proposes (internal API). The terminator countersigns at once only when it concedes nothing (same destination and rate, agreed duration not below its own beyond tolerance). Otherwise its operator approves first. There is one resolution per call, and an existing countersignature is reused, never doubled.
- Settlement: supplementary statements for periods already settled (scheduler and `POST /v1/supplementary`), a `resolved` count, and a one-paid-receipt-per-call guard (`duplicate_call` exclusion).
- Third-party adjudication is not a protocol role: any ruling still has to end in the two parties' signatures, which is what re-proposal produces.
- Tests: protocol unit tests (signed bytes unchanged, `resolves` bound by signature, concession rules, window and call checks); service tests (approval flow, no-concession path, missing terminating CDR, reuse of an existing countersignature, refusals and window expiry); engine tests (supplementary statement, open-period deferral, duplicate-call guard within and across statements). Lab: one A→C duration-mismatch dispute is resolved by the operators (approval required, since C measured 15 s more), the receipt is checked in both logs with inclusion proofs, and a final supplementary statement pays exactly that call.

## Follow-up work (known gaps)

| Gap | Why it matters | Plan |
|---|---|---|
| SRTP passthrough verification | The lab uses plain RTP; `media.e2e` is always false | SRTP-capable test agent; pin rtpengine flags |
| Registry revocation | Members can be added by majority but not removed; anchors cannot rotate | Signed revocation objects endorsed by a majority; anchor rotation by majority |
| Transit (A→B→C) | Phase 1 refuses numbers outside the terminating node's own ranges | Per-hop receipts chained by a shared reference |
| Open Voice Shield | Adapter is a stub (config keys, fail-closed) | Webhook receiver for `call.analyzed` (HMAC-SHA256 `X-OVS-Signature`), verdicts keyed by Call-ID into the gate |

## Corrections to the brief (proposed; details in ARCHITECTURE.md)

| # | Brief says | Problem | Proposal | Ref |
|---|---|---|---|---|
| 1 | Ed25519 keypair per node | SHAKEN mandates ES256, TLS needs X.509, and per-pair hashing needs key agreement | Four keys per node: Ed25519 signing, X25519 agreement, P-256 TLS, P-256 STIR | §4 |
| 2 | Hash the full number with a per-period salt | E.164 space is small: anyone with the salt can brute-force it | HMAC with a per-pair, per-period key derived from X25519; crypto-shred after the dispute window | §5.3 |
| 3 | Receipt contains `billed_seconds`, signed by both | Each node measures its own duration, so they can't both sign one number they didn't both see | A signs its proposal; B signs proposal + its own measurement + `agreed = min(...)`; one round trip | §5.4 |
| 4 | `score(receipt)` | Bursts and ASR/ACD need aggregates | `score(receipt, ctx)` with per-period context | §7.3 |
| 5 | Settlement engine signs statements | A single engine becomes a trusted third party | Engine signs; both peers recompute and countersign; final only with all three | §7.4 |
| 6 | `dmq_usrloc` replication between peers | Leaks subscribers across operators, lets peers bypass the home node (no receipt), and breaks behind NAT | `dmq_usrloc` within an operator's cluster; across operators only a DMQ `htable` AOR/prefix → home-node index | §8.1 |
| 7 | rtpengine + SRTP end to end | Anchoring with SRTP translation means rtpengine holds the keys | rtpengine as a relay that does not touch crypto when both ends do SRTP; bridged calls flagged non-E2E | §8.2 |
| 8 | Call-end event over HTTP | Fire-and-forget loses events when the receiver is down | `http_async_client` fast path + `acc` CDRs in Postgres as the durable backstop, reconciled every 60 s | §8.3 |
| 9 | Kamailio "official images" | Docker Hub images stop at 5.5.2; `secsipid` is packaged for Debian | Image built from `deb.kamailio.org/kamailio61` | §8 |

## Decisions needed from AJ

Brief's open questions:

1. **License** for the new code. Options: Apache-2.0 (patent grant, friendly to carriers embedding it), AGPL-3.0 (keeps hosted forks open), or MIT. No license file is added until you choose.
2. **Settlement period and tolerances.** Proposed: daily (UTC), grace 6 h, `tol_abs = 2 s`, `tol_rel = 1%`, `tol_skew = 2 s`, dispute window 30 days.
3. **Testnet.** Proposed: Base Sepolia (chain id 84532) with Circle testnet USDC. CI uses a local anvil chain.
4. **Repo home.** Stay at `ajamous/dots`, or move under the TCXC org.

Raised by the design:

5. Accept corrections 1–9 above, in particular #6 (DMQ scope) and #5 (peer countersignature on statements).
6. `agreed_billed_seconds = min(orig, term)`, or the terminating side's value.
7. Lab adds a fourth Kamailio container (`node-a2`) to demonstrate `dmq_usrloc` inside one operator.
8. Default branch is `master`. Rename it to `main`?

## Decisions log

AJ delegated all open questions on 2026-10-04 ("decide for me"). The decisions below were made on that basis and can be revisited.

| # | Date | Decision |
|---|---|---|
| D1 | 2026-10-04 | **License: Apache-2.0.** Carriers and voice-agent vendors can embed it, and it carries an explicit patent grant. `LICENSE` + `NOTICE` added. |
| D2 | 2026-10-04 | **Settlement:** daily UTC periods, 6 h grace, `tol_abs = 2 s`, `tol_rel = 1%`, `tol_skew = 2 s`, dispute window and dest-hash key retention 30 days after period end. |
| D3 | 2026-10-04 | **Testnet: Base Sepolia** (chain id 84532), Circle testnet USDC. CI and the lab use a local EVM; the public testnet is a manual target only. |
| D4 | 2026-10-04 | **Repo stays at `ajamous/dots`.** Moving to the TCXC org is a one-click transfer later, and GitHub redirects the old URL. |
| D5 | 2026-10-04 | **Corrections 1–9 accepted.** |
| D6 | 2026-10-04 | **`agreed_billed_seconds = min(orig, term)`.** |
| D7 | 2026-10-04 | **Lab includes `node-a2`** (a second instance of operator A) to demonstrate `dmq_usrloc`. |
| D8 | 2026-10-04 | **Default branch stays `master`.** A rename breaks existing clones and links, for no functional gain. |
| D9 | 2026-10-04 | **Images are built on Ubuntu 26.04 LTS from the Ubuntu archive: Kamailio 6.0.5 (with `kamailio-secsipid-modules`), rtpengine mr13.5.1.4, SIPp 3.7.7.** This deviates from "latest 6.x" (6.1.4). Reasons: distro-maintained LTS security updates, and `deb.kamailio.org` was unreachable from the build environment. The routing config sticks to features common to 6.0 and 6.1. The Kamailio Dockerfile takes `KAMAILIO_REPO=kamailio61` to build from `deb.kamailio.org` instead, so moving up is a build arg. |
| D10 | 2026-10-04 | **Language:** Python 3.12 for all services, per the brief. Kamailio and rtpengine stay as the SIP and media layer. |
