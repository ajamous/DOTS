import json
from pathlib import Path

from cryptography import x509

from dots_common.identity import Keyring
from dots_common.models import SignedRateTable
from dots_common.protocol import verify_rate_table
from dots_lab.bootstrap import bootstrap

TOPO = json.loads((Path(__file__).resolve().parents[1] / "topology.json").read_text())


def test_bootstrap_generates_consistent_state(tmp_path: Path) -> None:
    assert bootstrap(tmp_path, TOPO)
    assert not bootstrap(tmp_path, TOPO)  # idempotent
    keyring = Keyring.load(tmp_path / "peers.json")
    nodes = [p for p in keyring.registry.peers if p.role == "node"]
    assert {p.node_id for p in nodes} == set(TOPO["nodes"])
    assert {p.node_id for p in keyring.registry.peers if p.role != "node"} == {
        "settlement",
        "observer",
    }
    for f in sorted((tmp_path / "rates").glob("*.json")):
        t = SignedRateTable.model_validate(json.loads(f.read_text()))
        assert verify_rate_table(keyring, t), f.name
    ca = x509.load_pem_x509_certificate((tmp_path / "ca/ca.pem").read_bytes())
    for p in nodes:
        cert = x509.load_pem_x509_certificate((tmp_path / p.node_id / "tls/cert.pem").read_bytes())
        assert cert.issuer == ca.subject
        cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        assert cn == p.node_id
        cfg = (tmp_path / p.node_id / "kamailio/node.cfg").read_text()
        assert f"!DOTS_NODE_ID!{p.node_id}!" in cfg
        assert f'$var(peer) == "{p.node_id}"' not in cfg  # never its own peer
        assert (tmp_path / p.node_id / "keys/signing.pem").stat().st_mode & 0o077 == 0


def test_longest_prefix_first(tmp_path: Path) -> None:
    topo = {
        **TOPO,
        "nodes": {
            "node-a": {"operator": "A", "instances": ["node-a1"], "ranges": ["44"]},
            "node-b": {"operator": "B", "instances": ["node-b1"], "ranges": ["4477"]},
        },
        "rates": [],
    }
    bootstrap(tmp_path, topo)
    cfg = (tmp_path / "node-a/kamailio/node.cfg").read_text()
    assert cfg.index('"^4477"') < cfg.index('"^44"')
