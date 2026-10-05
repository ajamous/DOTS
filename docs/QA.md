# QA evidence

Evidence from end-to-end runs of the lab, each captured from a fresh `make lab-up` and `python3 lab/run_e2e.py --verbose`. Section 1 and the checks image are from the final Phase 2 run (2026-10-05). Sections 2–5 are from the Phase 1 run (2026-10-04); the mechanisms they show are unchanged. Every image is rendered from the raw captured output in [`docs/qa/`](qa/), which is committed next to it.

| Raw evidence | What it is |
|---|---|
| [`qa/e2e-run.log`](qa/e2e-run.log) | Full transcript of the final Phase 2 run: scenarios, log sizes, spool recovery, outage, dispute resolution, 22 + 4 assertions |
| [`qa/invite-at-pbx-b.txt`](qa/invite-at-pbx-b.txt) | `tcpdump -A` of one INVITE arriving at operator B's PBX |
| [`qa/evidence.json`](qa/evidence.json) | A receipt as logged, each node's signed tree head, alarms, statements, and the raw output of every MCP tool call |
| [`qa/statement-node-a-node-b.html`](qa/statement-node-a-node-b.html) | The settlement statement exactly as the engine rendered it |
| [`qa/checks.log`](qa/checks.log) | `make check && make unit` summary |

## 1. End-to-end run

92 SIP calls across three operators: G.711 RTP and SDES-SRTP, direct and in transit (A→B→C). Log sizes match the scenario file exactly:
- **After the main groups:** node-a 74, node-b 79, node-c 27. The transit calls appear in node-b's log twice, once per hop.
- **Recovery:** receipts-c is down for 5 s. Its 3 calls come back from Kamailio's durable spool, and node-b and node-c reach 82 and 30.
- **Outage:** receipts-c is down for 35 s. node-b logs its own `missing_countersignature` disputes (85), and node-c reaches 33 once it is back and has received them. The sizes stay unchanged across a restart of every receipt service.
- **Resolution:** the operators resolve one A→C duration-mismatch dispute. node-c's approval is required because it measured 15 s more. The resolution receipt adds one entry to each of node-a and node-c, and a final supplementary statement pays exactly that call.

![End-to-end run](images/qa-e2e.png)

## 2. STIR/SHAKEN across the federation

This INVITE was captured at operator B's PBX for a call originated by operator A's customer:
- The two `transport=tls` Record-Routes and the TLS Via are the node-a1 → node-b1 hop over mutual TLS.
- The `Identity` header is node-a's PASSporT (ES256, attestation A).
- `c=` points at rtpengine-b.

node-b1 verified the PASSporT through the x5u certificate and the lab STI-CA. The receipt for this exact Call-ID records `term_attestation_verified: "A"`, holds only the rate prefix `4420`, and has identical bytes in both operators' logs.

![SIP INVITE with Identity header](images/qa-sip-identity.png)

## 3. A dual-signed receipt and its inclusion proofs

The receipt is shown as logged by both nodes, with long values shortened. On the right, the MCP server's `verify_inclusion` result. It fetched each log's signed tree head, verified the Ed25519 signature, fetched the RFC 9162 audit path and recomputed both roots locally.

![Receipt and inclusion proofs](images/qa-receipt.png)

## 4. Settlement statement

The statement for node-a / node-b, as the engine rendered it (cropped; the full page lists all 40 held receipts, the evidence log references and all three signatures). Its totals match values computed independently from `lab/scenarios.json` and `lab/topology.json`:
- A→B 15 calls = 0.10 USD
- B→A 4 calls = 0.02 USD
- net 0.08 USD, paid by node-a

The 40-call short-duration burst (0.12 USD) is held by the fraud gate.

![Settlement statement](images/qa-statement.png)

## 5. Agent view over MCP

The five read-only MCP tools, called over streamable HTTP against the live lab. Every "verified" badge is a check the MCP server ran itself.

![MCP tools](images/qa-mcp.png)

## 6. Static checks, unit tests and CI

![Checks and CI](images/qa-checks.png)

## Reproduce

```sh
make lab-up
python3 lab/run_e2e.py --verbose
make lab-down
```
