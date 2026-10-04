from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DOTS_", extra="ignore")

    state: Path = Path("/state")
    data_dir: Path = Path("/data")
    identity: str = "settlement"
    listen_host: str = "0.0.0.0"  # noqa: S104 - containerized service
    listen_port: int = 8090

    # Periods and scheduling (decision D2)
    grace_hours: int = 6
    schedule_interval_s: int = 900

    # Fraud gate: local rules are always on; Open Voice Shield is opt-in.
    ovs_enabled: bool = False
    ovs_base_url: str = ""
    ovs_api_key: str = ""
    ovs_timeout_ms: int = 2000
    ovs_fail_mode: Literal["pass", "hold", "reject"] = "hold"

    # Payouts
    payout_adapters: str = "fiat_stub"
    stablecoin_chain_id: int = 84532
    stablecoin_rpc_url: str = ""
    stablecoin_dry_run: bool = True

    lab_mode: bool = False
