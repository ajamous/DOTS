import json
from pathlib import Path

import httpx
import pytest
from eth_account import Account
from settlement_fixtures import World

from dots_common.settlement import Net, SignedStatement, StatementBody
from dots_settlement.payout import (
    USDC_BASE_SEPOLIA,
    FiatStub,
    PayoutError,
    StablecoinConfig,
    StablecoinTestnet,
    transfer_calldata,
)


def statement(world: World, amount: str = "25.35", final: bool = True) -> SignedStatement:
    st = StatementBody(
        pair=["node-a", "node-b"],
        period="2026-01-01",
        currency="USD",
        minor_units=2,
        rate_tables=[],
        log_refs={},
        receipts_root="AA",
        held_root="AA",
        counts={},
        directions=[],
        held=[],
        excluded=[],
        net=Net(payer="node-a", payee="node-b", amount=amount),
        engine="t",
        engine_key_id=world.engine.signing.key_id,
        generated_ts=1,
    )
    acks = {"node-a": "AA", "node-b": "AA"} if final else {}
    return SignedStatement(statement=st, sig_engine="AA", acks=acks)


def test_fiat_invoice(world: World, tmp_path: Path) -> None:
    rec = FiatStub(tmp_path).pay(statement(world))
    assert rec["bill_to"] == "node-a"
    assert rec["issuer"] == "node-b"
    assert rec["amount"] == "25.35"
    assert json.loads((tmp_path / f"{rec['invoice_id']}.json").read_text()) == rec


def test_non_final_never_paid(world: World, tmp_path: Path) -> None:
    with pytest.raises(PayoutError):
        FiatStub(tmp_path).pay(statement(world, final=False))


def test_mainnet_refused() -> None:
    with pytest.raises(PayoutError):
        StablecoinTestnet(StablecoinConfig(chain_id=8453), "0x" + "11" * 32, {})
    with pytest.raises(PayoutError):
        StablecoinTestnet(StablecoinConfig(chain_id=1), "0x" + "11" * 32, {})


def test_calldata() -> None:
    to = "0x" + "ab" * 20
    data = transfer_calldata(to, 25_350_000)
    assert data[:4].hex() == "a9059cbb"
    assert data[4:36] == bytes(12) + bytes.fromhex("ab" * 20)
    assert int.from_bytes(data[36:], "big") == 25_350_000


def test_dry_run_signs_a_testnet_usdc_transfer(world: World) -> None:
    payer = Account.create()
    payee = Account.create().address
    rec = StablecoinTestnet(
        StablecoinConfig(), "0x" + bytes(payer.key).hex(), {"node-b": payee}
    ).pay(statement(world))
    assert rec["broadcast"] is False
    assert rec["chain_id"] == 84532
    assert rec["token"] == USDC_BASE_SEPOLIA
    assert rec["amount_units"] == 25_350_000
    assert Account.recover_transaction(rec["raw_tx"]) == payer.address


def test_broadcast_checks_remote_chain(world: World) -> None:
    def handler(req: httpx.Request) -> httpx.Response:
        method = json.loads(req.content)["method"]
        result = {"eth_chainId": hex(8453)}.get(method, "0x0")
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    payer = Account.create()
    p = StablecoinTestnet(
        StablecoinConfig(rpc_url="http://rpc", dry_run=False),
        "0x" + bytes(payer.key).hex(),
        {"node-b": Account.create().address},
        http=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    with pytest.raises(PayoutError, match="expected 84532"):
        p.pay(statement(world))


def test_broadcast(world: World) -> None:
    sent = []

    def handler(req: httpx.Request) -> httpx.Response:
        m = json.loads(req.content)
        sent.append(m["method"])
        result = {
            "eth_chainId": hex(84532),
            "eth_getTransactionCount": "0x7",
            "eth_sendRawTransaction": "0x" + "00" * 32,
        }[m["method"]]
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": result})

    payer = Account.create()
    rec = StablecoinTestnet(
        StablecoinConfig(rpc_url="http://rpc", dry_run=False),
        "0x" + bytes(payer.key).hex(),
        {"node-b": Account.create().address},
        http=httpx.Client(transport=httpx.MockTransport(handler)),
    ).pay(statement(world))
    assert rec["broadcast"] is True
    assert sent == ["eth_chainId", "eth_getTransactionCount", "eth_sendRawTransaction"]
