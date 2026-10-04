# DOTS 2.0 — Brief for Claude

You are working on `ajamous/dots`, owned by AJ (Ameed Jamous), founder of TelecomsXchange (TCXC), a wholesale telecom marketplace and clearing house. AJ is a deep VoIP/SIP engineer (Kamailio, Sippy, SMPP, RADIUS, MySQL). Write for that audience: no hand-holding on SIP, full rigor on crypto and settlement.

## 1. Background

In 2018 AJ published the D.O.T.S paper: a decentralized telecom network of replicated SIP registrars, peer-to-peer SRTP media, and a blockchain/ICO that pays nodes per completed call minute. Paper: https://www.telecomsxchange.com/blog/decentralized-telecom-networks-d-o-t-s-project

### What is in the repo today
Nothing original except `README.md` (the paper). Everything else is vendored upstream code, unmodified:
- `SIP_Server_kamailio-5.1.1/` — Kamailio 5.1.1 source; `etc/kamailio.cfg` is the stock sample config.
- `SIP_Clients_pjsip-2.7.1/` — PJSIP 2.7.1 source.
- `RewardSystem_bitcoin/` — a Bitcoin Core snapshot.
All three are 7+ years stale with known CVEs. Treat the repo as a greenfield project.

### Why the 2018 design is being changed
- Consumer privacy is solved for free by E2EE apps (Signal protocol in WhatsApp etc.). Not a market.
- Paying per minute invites traffic pumping, IRSF and false answer supervision. Any reward must be gated by fraud scoring.
- A blockchain is the wrong store for presence (changes per second; consensus latency). Use SIP-native replication (Kamailio DMQ) or a DHT.
- E.164 numbers can't be decentralized; PSTN-bridging nodes carry licensing and lawful-intercept duties.
- ICOs/tokens are dead as a funding or incentive model. No token.
- What worked in the market (e.g. Helium): decentralized supply, accountable operators, partnership with incumbents, real revenue.

## 2. The new direction

**DOTS 2.0 is an open, verifiable call-settlement and trust layer for federated SIP operators and AI voice agents.**

Independent operators (carriers, PBX owners, voice-agent platforms) run a DOTS node. Nodes peer with each other over SIP. Every call produces a receipt signed by both the originating and terminating node. Receipts go into an append-only, tamper-evident log. A settlement engine nets receipts per period, drops or holds those flagged by fraud scoring, and produces statements that can be paid in fiat or stablecoin.

The ledger proves *what was exchanged and agreed*. It does not route calls, hold presence, or mint anything.

## 3. Phase 1 scope (build this first)

A working 3-node lab that runs end to end with `docker compose up` and an automated test.

### 3.1 Repo hygiene
- On a branch, remove the three vendored trees. Do not rewrite history.
- Move the 2018 paper to `docs/2018-paper.md`. Write a new `README.md` describing DOTS 2.0 and linking the old paper as history.
- Add `docs/ARCHITECTURE.md` with a diagram (Mermaid) and the receipt/log/settlement data model.
- Depend on upstream projects through packages or container images, never vendored source.

### 3.2 Node (SIP)
- Kamailio latest stable 6.x (verify the current version) from official images or packages.
- Config in `node/kamailio/`, templated per node.
- Registrar replication between peers with `dmq` + `dmq_usrloc`.
- TLS between nodes; mutual auth by node certificate.
- STIR/SHAKEN: sign and verify the Identity header with the `secsipid` module (verify module status in 6.x). Use test certs in the lab.
- Media: rtpengine; SRTP end to end where endpoints support it.
- On every call end, emit an event (CDR fields + Call-ID + node id) to the local receipt service over HTTP. Use the `http_async_client` module or an `evapi` bridge, whichever is cleaner; justify the choice in ARCHITECTURE.md.

### 3.3 Receipt service (`services/receipts/`)
- Python 3.12, FastAPI, Pydantic v2. Postgres for storage.
- Node identity: Ed25519 keypair per node.
- Receipt = canonical JSON (RFC 8785 JCS) of: call_id, orig_node, term_node, start_ts, answer_ts, end_ts, billed_seconds, destination prefix (not full number; hash the full number with a per-period salt), rate_id, Identity-header attestation level.
- Flow: the originating node signs and sends to the terminating node; the terminating node verifies, countersigns, and both store the dual-signed receipt. Mismatches (duration delta beyond a tolerance, missing countersignature) become disputes, not receipts.
- Append receipts to a Merkle log (Certificate Transparency style: RFC 9162 structure, inclusion and consistency proofs). Each node keeps its own log and publishes signed tree heads. Peers fetch and verify each other's tree heads.
- Optional and off by default: anchor the signed tree head hash to a public chain or OpenTimestamps. Behind an interface; no chain dependency in the core.

### 3.4 Settlement engine (`services/settlement/`)
- Bilateral netting per period (default daily) from dual-signed receipts and a shared rate table.
- Fraud gate interface: `score(receipt) -> {pass | hold | reject, reasons}`. Ship a local rules implementation (short-duration bursts, ASR/ACD anomalies, high-risk prefixes, duration mismatches) and a stub adapter for Open Voice Shield (TCXC's fraud product; leave the HTTP client unimplemented with a TODO and config keys).
- Output: signed settlement statement (JSON + human-readable PDF or HTML) per peer pair per period.
- Payout interface with two adapters: `fiat_stub` (writes an invoice record) and `stablecoin_testnet` (USDC on a public testnet, e.g. Base Sepolia). Never mainnet, never real keys in the repo.

### 3.5 Agent interface (`services/mcp/`)
- An MCP server (official Python MCP SDK) exposing read tools: `list_peers`, `get_receipt`, `verify_inclusion`, `get_settlement`, `list_disputes`. No write or payout tools in phase 1.

### 3.6 Lab and tests
- `docker-compose.yml`: 3 nodes (Kamailio + rtpengine + receipt service + Postgres each), 1 settlement engine, 1 MCP server.
- SIPp scenarios in `lab/sipp/`: normal calls, short-duration burst (should be held by the fraud gate), duration mismatch (should become a dispute).
- `make test` runs unit tests (pytest), then the lab, then asserts: receipts dual-signed, inclusion proofs verify, settlement totals match expected values, fraud scenarios held.
- CI: GitHub Actions running lint (ruff), type check (mypy), unit tests, and the lab test.

## 4. Non-goals (do not build)
- Any token, ICO, mining, staking, or proof-of-work.
- Presence or registration stored on a blockchain.
- A consumer softphone or app. PJSIP is not needed in phase 1.
- E.164 number issuance or portability.
- Paying for raw minutes without the fraud gate.
- Mainnet payments or custody of funds.

## 5. Working rules
- Work on a feature branch; small, reviewable commits with clear messages. Open a PR per milestone below.
- Before writing code, produce `docs/ARCHITECTURE.md` and a short plan; stop and show AJ before building past it.
- Verify current versions and module names (Kamailio, secsipid, rtpengine, MCP SDK) against upstream docs rather than memory.
- Security: no secrets in git; `.env.example` only. Lab certs and keys generated at startup.
- Privacy: receipts never contain full phone numbers in clear.
- Licensing: ask AJ before choosing a license (the vendored trees were GPL/MIT; the new code can choose freely once they are removed).
- If something in this brief is wrong or unworkable, say so and propose the fix instead of working around it silently.
- No Claude branding in commit messages, commit authorship, or PR titles/bodies.

## 6. Milestones
1. Repo cleanup + README + ARCHITECTURE.md + plan (stop for review).
2. Receipt service with signing, countersigning, Merkle log, proofs, and unit tests.
3. Kamailio node config, DMQ replication, STIR/SHAKEN, call-end events into the receipt service; 3-node lab passing normal calls.
4. Settlement engine, fraud gate, payout adapters; fraud and dispute scenarios passing.
5. MCP server + CI green.

## 7. Open questions for AJ
- License for the new code.
- Default settlement period and duration-mismatch tolerance.
- Which public testnet for the stablecoin adapter.
- Whether the repo should move under the TCXC GitHub org.

## 8. Decisions log
Answers to the open questions and design decisions agreed with AJ are recorded in `docs/PLAN.md` §Decisions.
