# DOTS 2.0

**An open, verifiable call-settlement and trust layer for federated SIP operators and AI voice agents.**

Independent operators (carriers, PBX owners, voice-agent platforms) run a DOTS node and peer with each other over SIP/TLS. Every call between two nodes produces a **receipt signed by both the originating and the terminating node**. Each node appends receipts to its own **append-only Merkle log** (Certificate Transparency style, RFC 9162 structure) and publishes signed tree heads, which peers fetch and check for consistency. A **settlement engine** nets dual-signed receipts per peer pair per period, applies a **fraud gate** that holds or rejects suspect traffic, and emits a **signed settlement statement** that can be paid in fiat or (testnet) stablecoin.

The ledger proves *what was exchanged and agreed*. It does not route calls, hold presence, or mint anything. There is no token.

> **Status:** Phase 1 complete; Phase 2 in progress (see [`docs/PLAN.md`](docs/PLAN.md#phase-2)). The 3-operator lab runs end to end: SIP calls through Kamailio with STIR/SHAKEN, dual-signed receipts in RFC 9162 logs, fraud-gated settlement countersigned by both peers, payouts (fiat invoice, testnet USDC), and a read-only MCP server for agents. Known gaps are listed in [`docs/PLAN.md`](docs/PLAN.md#follow-up-work-known-gaps).
> See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design, [`docs/PLAN.md`](docs/PLAN.md) for the build plan and [`docs/QA.md`](docs/QA.md) for test evidence.

<p align="center">
  <img src="docs/images/qa-e2e.png" alt="End-to-end lab run: 81 SIP calls across 3 operators, 18 assertions passing" width="900">
</p>

## What a node is

| Component | Role |
|---|---|
| Kamailio 6.x | SIP proxy/registrar, mutual-TLS peering, DMQ replication, STIR/SHAKEN Identity sign/verify, call-end events |
| rtpengine | Media relay / NAT traversal; SRTP preserved where endpoints negotiate it |
| Receipt service | Ed25519 node identity, receipt signing and countersigning, disputes, Merkle log, signed tree heads |
| Postgres | Receipt, dispute and log storage |

Shared across the federation (one instance in the lab): the **settlement engine** and a read-only **MCP server** that lets AI agents query peers, receipts, inclusion proofs, settlements and disputes.

## Why not the 2018 design

DOTS started in 2018 as a paper proposing replicated SIP registrars plus a blockchain/ICO paying nodes per minute ([`docs/2018-paper.md`](docs/2018-paper.md)). DOTS 2.0 keeps the federated-operator idea and drops the rest:

- **Per-minute rewards invite fraud.** Traffic pumping, IRSF and false answer supervision are the business model of anyone paid for raw minutes. Nothing is paid without passing a fraud gate.
- **Presence does not belong on a chain.** It changes every second; consensus latency is fatal. Replication is SIP-native (Kamailio DMQ).
- **Consumer privacy is already solved** by E2EE messaging apps. The unsolved problem is trust and settlement *between operators*.
- **E.164 cannot be decentralized**, and PSTN-bridging nodes carry licensing and lawful-intercept duties. DOTS nodes are accountable, identified operators.
- **No token, no ICO.** Settlement is in fiat or an existing stablecoin.

## Repository layout

```
node/kamailio/        Kamailio 6.x routing script, entrypoint, image
node/rtpengine/       rtpengine image
services/common/      Shared primitives: JCS, Ed25519, RFC 9162 Merkle, protocol, netting
services/receipts/    Receipt service (FastAPI, Postgres)
services/settlement/  Settlement engine, fraud gate, payout adapters
services/mcp/         Read-only MCP server
lab/                  Topology, bootstrap, SIPp scenarios, end-to-end tests
docker-compose.yml    The lab
docs/                 Architecture, plan, 2018 paper
```

## What the lab demonstrates

| | |
|---|---|
| Federation | 3 operators, 4 Kamailio instances, SIP over mutual TLS, peer identity from certificate CN |
| STIR/SHAKEN | Identity signed by the originating node and verified by the terminating node (x5u fetch, lab STI-CA) |
| Replication | `dmq_usrloc` inside operator A's two-instance cluster; every inbound call to A depends on it |
| Receipts | 84 real calls with G.711 RTP: 76 dual-signed receipts and 8 disputes, each byte-identical in both parties' logs; no full numbers in any receipt or log |
| Integrity | Inclusion and consistency proofs, peer monitoring, equivocation detection through STH gossip |
| Disputes | Injected 15 s duration skew becomes `duration_mismatch` disputes, excluded from settlement. One is then resolved by the operators (re-proposal, approval of the concession): the resolution receipt lands in both logs and a supplementary statement pays exactly that call |
| Resilience | Kamailio spools every call-end event durably: a receipt service down for a short while recovers its calls and they settle normally; a longer outage still yields signed `missing_countersignature` disputes; all receipt services restart with their logs intact |
| Fraud gate | A 40-call short-duration burst is held (`short_burst`, `acd_anomaly`) |
| Settlement | Per-pair daily statements, recomputed and countersigned by both peers; totals match values computed independently from the scenario file |
| Payouts | Invoice records and signed (not broadcast) Base Sepolia USDC transfers |
| Agents | MCP tools `list_peers`, `get_receipt`, `verify_inclusion`, `get_settlement`, `list_disputes` |

Upstream projects (Kamailio, rtpengine, SIPp, Postgres) are consumed as packages or container images, never vendored.

## Evidence from the lab

Captured during an end-to-end run. Raw logs and data are in [`docs/qa/`](docs/qa/); the walkthrough is in [`docs/QA.md`](docs/QA.md).

**STIR/SHAKEN across the federation.** A live INVITE at operator B's PBX after the mutual-TLS hop from operator A: node-a's PASSporT, verified by node-b, recorded in a receipt that carries only the rate prefix.

![SIP INVITE with Identity header and decoded PASSporT](docs/images/qa-sip-identity.png)

**A receipt in two logs.** Signed by both operators, byte-identical in both logs, with RFC 9162 inclusion proofs recomputed independently.

![Dual-signed receipt and inclusion proofs](docs/images/qa-receipt.png)

<table>
<tr>
<td width="50%"><b>Settlement statement</b>, countersigned by both peers. 40 burst calls held by the fraud gate.<br><img src="docs/images/qa-statement.png" alt="Settlement statement"></td>
<td width="50%"><b>Agents over MCP</b>, read-only tools, every badge verified locally.<br><img src="docs/images/qa-mcp.png" alt="MCP tools"></td>
</tr>
</table>

![Static checks, tests and CI](docs/images/qa-checks.png)

## Quick start

Requirements: Docker with Compose v2, Python 3.12 and [uv](https://docs.astral.sh/uv/).

```sh
make check        # ruff, mypy --strict
make unit         # unit + integration tests (starts a throwaway Postgres)
make lab-up       # build images, start 3 operators (4 Kamailio instances)
make lab-e2e      # drive SIPp scenarios, assert receipts, proofs, disputes
make lab-down
make test         # all of the above, on a fresh lab
```

Behind a TLS-intercepting proxy, set `EXTRA_CA=/path/to/ca-bundle.pem` for image builds.

With the lab up, AI agents can query it through MCP at `http://127.0.0.1:8000/mcp`:

```sh
claude mcp add --transport http dots http://127.0.0.1:8000/mcp
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
