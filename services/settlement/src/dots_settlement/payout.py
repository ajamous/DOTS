"""Payout adapters (ARCHITECTURE.md §7.5). Only final statements are paid.

* ``fiat_stub`` writes an invoice record.
* ``stablecoin_testnet`` builds and signs an ERC-20 ``transfer`` of testnet
  USDC from the payer's testnet wallet. It refuses any chain id that is not
  an allow-listed testnet, checks the RPC endpoint's chain id before sending,
  and runs in dry-run mode (sign, do not broadcast) unless told otherwise.
"""

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import httpx
from eth_account import Account

from dots_common.settlement import SignedStatement, statement_id, to_minor_units

# Public testnets only. Mainnet chain ids are never accepted.
TESTNETS: dict[int, str] = {
    84532: "Base Sepolia",
    11155111: "Ethereum Sepolia",
    421614: "Arbitrum Sepolia",
    11155420: "OP Sepolia",
}
# Circle testnet USDC (decision D3). Re-verify before use.
USDC_BASE_SEPOLIA = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
TRANSFER_SELECTOR = bytes.fromhex("a9059cbb")  # transfer(address,uint256)


class PayoutError(Exception):
    pass


class Payout(Protocol):
    name: str

    def pay(self, ss: SignedStatement) -> dict[str, Any]: ...


def _payable(ss: SignedStatement) -> None:
    if not ss.final:
        raise PayoutError("statement is not final (missing peer countersignatures)")
    if ss.statement.net.payer is None:
        raise PayoutError("nothing to pay")


class FiatStub:
    name = "fiat_stub"

    def __init__(self, directory: Path, terms_days: int = 30) -> None:
        self.dir = directory
        self.terms_days = terms_days

    def pay(self, ss: SignedStatement) -> dict[str, Any]:
        _payable(ss)
        st = ss.statement
        sid = statement_id(st)
        now = int(time.time())
        record = {
            "type": "invoice",
            "invoice_id": f"DOTS-{st.period}-{sid[:12]}",
            "statement_id": sid,
            "period": st.period,
            "issuer": st.net.payee,
            "bill_to": st.net.payer,
            "amount": st.net.amount,
            "currency": st.currency,
            "issued_ts": now,
            "due_ts": now + self.terms_days * 86_400,
        }
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / f"{record['invoice_id']}.json").write_text(json.dumps(record, indent=2))
        return record


@dataclass(frozen=True)
class StablecoinConfig:
    chain_id: int = 84532
    token: str = USDC_BASE_SEPOLIA
    decimals: int = 6
    rpc_url: str = ""
    dry_run: bool = True
    gas_limit: int = 100_000
    max_fee_wei: int = 2_000_000_000
    priority_fee_wei: int = 1_000_000


def transfer_calldata(to: str, amount: int) -> bytes:
    addr = bytes.fromhex(to.removeprefix("0x"))
    if len(addr) != 20:
        raise PayoutError("bad address")
    if not 0 < amount < 2**256:
        raise PayoutError("bad amount")
    return TRANSFER_SELECTOR + addr.rjust(32, b"\0") + amount.to_bytes(32, "big")


class StablecoinTestnet:
    name = "stablecoin_testnet"

    def __init__(
        self,
        cfg: StablecoinConfig,
        payer_key_hex: str,
        addresses: dict[str, str],
        http: httpx.Client | None = None,
    ) -> None:
        if cfg.chain_id not in TESTNETS:
            raise PayoutError(f"chain id {cfg.chain_id} is not an allow-listed testnet")
        self.cfg = cfg
        self.account = Account.from_key(payer_key_hex)
        self.addresses = addresses
        self.http = http or httpx.Client(timeout=10)

    def _rpc(self, method: str, params: list[Any]) -> Any:
        r = self.http.post(
            self.cfg.rpc_url, json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        )
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise PayoutError(f"{method}: {data['error']}")
        return data["result"]

    def pay(self, ss: SignedStatement) -> dict[str, Any]:
        _payable(ss)
        st = ss.statement
        if st.currency != "USD":
            raise PayoutError("USDC payouts settle USD statements only")
        payee = self.addresses.get(st.net.payee or "")
        if payee is None:
            raise PayoutError(f"no testnet address for {st.net.payee}")
        amount = to_minor_units(st.net.amount, self.cfg.decimals)
        nonce = 0
        if not self.cfg.dry_run:
            if not self.cfg.rpc_url:
                raise PayoutError("rpc_url required to broadcast")
            remote = int(self._rpc("eth_chainId", []), 16)
            if remote != self.cfg.chain_id:
                raise PayoutError(f"RPC is chain {remote}, expected {self.cfg.chain_id}")
            nonce = int(self._rpc("eth_getTransactionCount", [self.account.address, "pending"]), 16)
        tx = {
            "type": 2,
            "chainId": self.cfg.chain_id,
            "nonce": nonce,
            "to": self.cfg.token,
            "value": 0,
            "data": "0x" + transfer_calldata(payee, amount).hex(),
            "gas": self.cfg.gas_limit,
            "maxFeePerGas": self.cfg.max_fee_wei,
            "maxPriorityFeePerGas": self.cfg.priority_fee_wei,
        }
        signed = Account.sign_transaction(tx, self.account.key)
        raw = "0x" + bytes(signed.raw_transaction).hex()
        record: dict[str, Any] = {
            "type": "erc20_transfer",
            "network": TESTNETS[self.cfg.chain_id],
            "chain_id": self.cfg.chain_id,
            "token": self.cfg.token,
            "from": self.account.address,
            "to": payee,
            "amount_units": amount,
            "amount": st.net.amount,
            "statement_id": statement_id(st),
            "tx_hash": "0x" + bytes(signed.hash).hex(),
            "raw_tx": raw,
            "broadcast": False,
        }
        if not self.cfg.dry_run:
            self._rpc("eth_sendRawTransaction", [raw])
            record["broadcast"] = True
        return record
