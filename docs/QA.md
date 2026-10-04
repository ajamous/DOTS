# QA evidence

Evidence from one end-to-end run of the lab on 2026-10-04, captured from a fresh `make lab-up` and `python3 lab/run_e2e.py --verbose`. Every image below is rendered from the raw captured output in [`docs/qa/`](qa/), which is committed next to it.

| Raw evidence | What it is |
|---|---|
| [`qa/e2e-run.log`](qa/e2e-run.log) | Full transcript of the end-to-end run: scenarios, log sizes, outage, 18 assertions |
| [`qa/invite-at-pbx-b.txt`](qa/invite-at-pbx-b.txt) | `tcpdump -A` of one INVITE arriving at operator B's PBX |
| [`qa/evidence.json`](qa/evidence.json) | A receipt as logged, each node's signed tree head, alarms, statements, and the raw output of every MCP tool call |
| [`qa/statement-node-a-node-b.html`](qa/statement-node-a-node-b.html) | The settlement statement exactly as the engine rendered it |
| [`qa/checks.log`](qa/checks.log) | `make check && make unit` summary |

## 1. End-to-end run

81 SIP calls with G.711 RTP across three operators. Log sizes match the scenario file exactly: node-a 70, node-b 67, node-c 19 after the main groups. During the outage, node-b grows to 70 with its own `missing_countersignature` disputes, and node-c reaches 22 once it is back and has received them. The sizes stay unchanged across a restart of every receipt service.

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
