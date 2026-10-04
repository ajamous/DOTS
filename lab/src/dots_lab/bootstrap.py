"""Generate every key, certificate and config file the lab needs.

Runs once, as the first container of the compose project, writing to the
shared ``/state`` volume. Nothing produced here is ever committed: it is lab
material generated fresh for each new volume. Re-running is a no-op unless
``--force`` is given.

Layout:
    ca/ca.pem                lab TLS CA (SIP mTLS and receipt-service HTTPS)
    stir/ca.pem              lab STI-CA (STIR/SHAKEN certificates)
    peers.json               peer registry: node keys, URLs, number ranges
    rates/<a>--<b>.json      rate tables signed by both operators
    <node>/keys/             Ed25519 signing + X25519 agreement keys
    <node>/tls/              TLS certificate and key (CN = node id)
    <node>/stir/             ES256 STIR/SHAKEN certificate and key
    <node>/token             bearer token for Kamailio -> receipt service
    <node>/kamailio/node.cfg Kamailio defines and generated routes
    settlement/, observer/   identities for the settlement engine and MCP server
"""

import argparse
import datetime as dt
import ipaddress
import json
import os
import secrets
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from dots_common.identity import NodeIdentity
from dots_common.models import PeerRegistry, RateTable, SignedRateTable, body
from dots_common.signing import Context

SERVICE_UID = 10001
VALID_DAYS = 365


def _write(path: Path, data: bytes | str, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data.encode() if isinstance(data, str) else data)
    path.chmod(mode)


def _pem_key(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _name(cn: str, org: str = "DOTS lab") -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ]
    )


def make_ca(cn: str) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=VALID_DAYS * 2))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue(
    ca_key: ec.EllipticCurvePrivateKey,
    ca_cert: x509.Certificate,
    cn: str,
    dns: list[str],
    *,
    tls: bool = True,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    )
    if tls:
        sans: list[x509.GeneralName] = [x509.DNSName(d) for d in dns]
        sans.append(x509.IPAddress(ipaddress.ip_address("127.0.0.1")))
        builder = builder.add_extension(x509.SubjectAlternativeName(sans), critical=False)
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    return key, builder.sign(ca_key, hashes.SHA256())


def _save_pair(directory: Path, key: ec.EllipticCurvePrivateKey, cert: x509.Certificate) -> None:
    _write(directory / "key.pem", _pem_key(key), 0o600)
    _write(directory / "cert.pem", cert.public_bytes(serialization.Encoding.PEM))


def kamailio_node_cfg(node: str, topo: dict[str, Any]) -> str:
    """Per-node Kamailio defines and the generated routing tables."""
    nodes: dict[str, Any] = topo["nodes"]
    lines = [
        f"# Generated by dots_lab.bootstrap for {node}. Do not edit.",
        f'#!substdef "!DOTS_NODE_ID!{node}!g"',
        f'#!substdef "!DOTS_STIR_KEY!/state/{node}/stir/key.pem!g"',
        f'#!substdef "!DOTS_STIR_X5U!http://{node}:8088/stir/cert.pem!g"',
        "",
        "# Longest-prefix match of $var(num) (E.164 digits) to its home node.",
        "route[DOTS_RANGES] {",
        '\t$var(home) = "";',
    ]
    ranges = sorted(
        ((r, n) for n, spec in nodes.items() for r in spec["ranges"]),
        key=lambda x: (-len(x[0]), x[0]),
    )
    for i, (prefix, owner) in enumerate(ranges):
        kw = "if" if i == 0 else "} else if"
        lines.append(f'\t{kw} ($var(num) =~ "^{prefix}") {{')
        lines.append(f'\t\t$var(home) = "{owner}";')
    if ranges:
        lines.append("\t}")
    lines += [
        "}",
        "",
        "# Federation peers: $var(peer) -> $var(peer_uri), $var(peer_ok).",
        "route[DOTS_PEER] {",
        "\t$var(peer_ok) = 0;",
    ]
    for other in nodes:
        if other == node:
            continue
        lines.append(f'\tif ($var(peer) == "{other}") {{')
        lines.append(f'\t\t$var(peer_uri) = "sip:{other}:5061;transport=tls";')
        lines.append("\t\t$var(peer_ok) = 1;")
        lines.append("\t}")
    lines.append("}")
    return "\n".join(lines) + "\n"


def bootstrap(state: Path, topo: dict[str, Any], force: bool = False) -> bool:
    marker = state / "bootstrap.done"
    if marker.exists() and not force:
        return False
    state.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = make_ca("DOTS lab TLS CA")
    _write(state / "ca/ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM))
    sti_key, sti_cert = make_ca("DOTS lab STI-CA")
    _write(state / "stir/ca.pem", sti_cert.public_bytes(serialization.Encoding.PEM))

    idents: dict[str, NodeIdentity] = {}
    peers = []
    for node, spec in topo["nodes"].items():
        d = state / node
        ident = NodeIdentity.generate(node, d / "keys")
        idents[node] = ident
        letter = node.split("-")[-1]
        dns = [node, *spec["instances"], f"receipts-{letter}"]
        _save_pair(d / "tls", *issue(ca_key, ca_cert, node, dns))
        _save_pair(d / "stir", *issue(sti_key, sti_cert, f"SHAKEN {node}", [], tls=False))
        _write(d / "token", secrets.token_urlsafe(32), 0o600)
        _write(d / "kamailio/node.cfg", kamailio_node_cfg(node, topo))
        peers.append(
            ident.peer_entry(
                operator=spec["operator"],
                receipts_url=f"https://receipts-{letter}:8443",
                sip_uri=f"sip:{node}:5061;transport=tls",
                stir_x5u=f"http://{node}:8088/stir/cert.pem",
                ranges=spec["ranges"],
            )
        )
    for role in ("settlement", "observer"):
        d = state / role
        ident = NodeIdentity.generate(role, d / "keys")
        _save_pair(d / "tls", *issue(ca_key, ca_cert, role, [role, "mcp"]))
        peers.append(ident.peer_entry(operator="DOTS lab", role=role))
    registry = PeerRegistry(peers=peers)
    _write(state / "peers.json", json.dumps(body(registry), indent=2))

    pairs: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for r in topo["rates"]:
        a, b = sorted((r["payer"], r["payee"]))
        pairs.setdefault((a, b), []).append(r)
    for (a, b), entries in sorted(pairs.items()):
        table = RateTable.model_validate(
            {
                "table_id": f"{a}--{b}--lab",
                "pair": [a, b],
                "currency": topo["currency"],
                "minor_units": 2,
                "effective_from": "2020-01-01",
                "entries": entries,
            }
        )
        t = body(table)
        signed = SignedRateTable(
            table=table,
            sigs={n: idents[n].signing.sign(Context.RATE_TABLE, t) for n in (a, b)},
        )
        _write(state / f"rates/{a}--{b}.json", json.dumps(body(signed), indent=2))

    # Services run as an unprivileged user; Kamailio runs as root and reads anyway.
    if os.geteuid() == 0:
        for p in state.rglob("*"):
            os.chown(p, SERVICE_UID, SERVICE_UID)
    marker.write_text(dt.datetime.now(dt.UTC).isoformat())
    return True


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--state", type=Path, default=Path("/state"))
    ap.add_argument("--topology", type=Path, default=Path("/app/lab/topology.json"))
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    topo = json.loads(args.topology.read_text())
    made = bootstrap(args.state, topo, args.force)
    print("bootstrap: generated lab state" if made else "bootstrap: state already present")


if __name__ == "__main__":
    main()
