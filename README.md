# DOTS 2.0

**An open, verifiable call-settlement and trust layer for federated SIP operators and AI voice agents.**

Independent operators (carriers, PBX owners, voice-agent platforms) run a DOTS node and peer with each other over SIP/TLS. Every call between two nodes produces a **receipt signed by both the originating and the terminating node**. Each node appends receipts to its own **append-only Merkle log** (Certificate Transparency style, RFC 9162 structure) and publishes signed tree heads, which peers fetch and check for consistency. A **settlement engine** nets dual-signed receipts per peer pair per period, applies a **fraud gate** that holds or rejects suspect traffic, and emits a **signed settlement statement** that can be paid in fiat or (testnet) stablecoin.

The ledger proves *what was exchanged and agreed*. It does not route calls, hold presence, or mint anything. There is no token.

> **Status:** Phase 1, Milestone 1 (repo cleanup and architecture). No service code yet.
> See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the design and [`docs/PLAN.md`](docs/PLAN.md) for the build plan.

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

## Repository layout (target for Phase 1)

```
node/kamailio/        Kamailio config templates, per-node rendering
node/rtpengine/       rtpengine config
services/receipts/    Receipt service (FastAPI, Postgres)
services/settlement/  Settlement engine, fraud gate, payout adapters
services/mcp/         Read-only MCP server
lab/                  docker compose lab, SIPp scenarios, cert/key bootstrap
docs/                 Architecture, plan, 2018 paper
```

Upstream projects (Kamailio, rtpengine, SIPp, Postgres) are consumed as packages or container images, never vendored.

## Quick start

Not yet available. The lab arrives in Milestone 3:

```sh
docker compose up        # 3 nodes + settlement + MCP
make test                # unit tests, then end-to-end lab assertions
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
