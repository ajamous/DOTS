"""Human-readable statement (HTML; prints to PDF from any browser)."""

from html import escape

from dots_common.settlement import SignedStatement, statement_id

CSS = """
body{font:14px/1.45 system-ui,sans-serif;margin:32px auto;max-width:860px;color:#1b1f24;
background:#fff}h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:24px 0 8px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #d8dee4;padding:6px 8px;
text-align:left}th{background:#f6f8fa}td.n{text-align:right;font-variant-numeric:tabular-nums}
code{font-size:12px;word-break:break-all}.final{color:#1a7f37}.pending{color:#9a6700}
.net{font-size:18px;margin:12px 0}@media print{body{margin:0}}
"""


def render_html(ss: SignedStatement) -> str:
    st = ss.statement
    e = escape
    status = (
        '<span class="final">FINAL: countersigned by both peers</span>'
        if ss.final
        else '<span class="pending">PENDING peer countersignature</span>'
    )
    rows = "".join(
        f"<tr><td>{e(d.payer)} &rarr; {e(d.payee)}</td><td class=n>{d.calls}</td>"
        f"<td class=n>{d.seconds}</td><td class=n>{e(d.gross)}</td>"
        f"<td class=n>{d.held_calls}</td><td class=n>{e(d.held_amount)}</td></tr>"
        for d in st.directions
    )
    net = (
        f"{e(st.net.payer or '')} pays {e(st.net.payee or '')} "
        f"<b>{e(st.net.amount)} {e(st.currency)}</b>"
        if st.net.payer
        else f"Balanced: nothing to pay ({e(st.net.amount)} {e(st.currency)})"
    )
    held = (
        "".join(
            f"<tr><td><code>{e(h.leaf_hash)}</code></td><td>{e(h.verdict)}</td>"
            f"<td>{e(', '.join(h.reasons))}</td></tr>"
            for h in st.held
        )
        or '<tr><td colspan="3">None</td></tr>'
    )
    refs = "".join(
        f"<tr><td>{e(n)}</td><td class=n>{r.tree_size}</td><td><code>{e(r.root_hash)}</code></td>"
        f"</tr>"
        for n, r in st.log_refs.items()
    )
    counts = ", ".join(f"{e(k)}: {v}" for k, v in sorted(st.counts.items()))
    sigs = "".join(
        f"<tr><td>{e(n)}</td><td><code>{e(s)}</code></td></tr>" for n, s in ss.acks.items()
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>DOTS statement {e(st.pair[0])} / {e(st.pair[1])} {e(st.period)}</title>
<style>{CSS}</style></head><body>
<h1>Settlement statement: {e(st.pair[0])} / {e(st.pair[1])}</h1>
<div>Period {e(st.period)} (UTC) &middot; {status}</div>
<div class="net">{net}</div>
<h2>Traffic</h2>
<table><tr><th>Direction</th><th>Calls</th><th>Seconds</th><th>Gross ({e(st.currency)})</th>
<th>Held calls</th><th>Held amount</th></tr>{rows}</table>
<p>Counts: {counts}</p>
<h2>Held or rejected by the fraud gate</h2>
<table><tr><th>Receipt leaf</th><th>Verdict</th><th>Reasons</th></tr>{held}</table>
<h2>Evidence</h2>
<table><tr><th>Log</th><th>Tree size</th><th>Root hash</th></tr>{refs}</table>
<p>Settled receipts root <code>{e(st.receipts_root)}</code><br>
Held receipts root <code>{e(st.held_root)}</code><br>
Rate tables {", ".join(f"<code>{e(t)}</code>" for t in st.rate_tables)}<br>
Statement id <code>{e(statement_id(st))}</code><br>
Engine {e(st.engine)}, key <code>{e(st.engine_key_id)}</code></p>
<h2>Signatures</h2>
<table><tr><th>Signer</th><th>Ed25519 signature</th></tr>
<tr><td>settlement engine</td><td><code>{e(ss.sig_engine)}</code></td></tr>{sigs}</table>
</body></html>
"""
