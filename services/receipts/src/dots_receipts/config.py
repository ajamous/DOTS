from pathlib import Path

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DOTS_", extra="ignore")

    node_id: str
    database_url: str
    key_dir: Path
    peers_file: Path
    rate_tables_dir: Path
    internal_token: str = ""
    internal_token_file: Path | None = None

    # Tolerances (decision D2)
    tol_abs_seconds: int = 2
    tol_rel_permille: int = 10
    tol_skew_ms: int = 2000

    # Windows, seconds
    match_window_s: int = 60
    proposal_window_s: int = 120
    countersig_window_s: int = 300
    retry_interval_s: float = 2.0

    # Log publication and monitoring
    sth_interval_s: float = 10.0
    sth_max_age_s: float = 300.0
    monitor_interval_s: float = 10.0
    mmd_s: int = 60

    # Outbound HTTPS to peers (lab CA and this node's client certificate)
    tls_ca: Path | None = None
    tls_cert: Path | None = None
    tls_key: Path | None = None

    # Inbound
    listen_host: str = "0.0.0.0"  # noqa: S104 - containerized service
    listen_port: int = 8443
    internal_port: int = 8080

    # Lab-only fault injection: "node-a:15" adds 15 s to this node's measured
    # duration for calls originated by node-a. Ignored unless lab_mode is set.
    lab_mode: bool = False
    lab_skew: str = ""

    @model_validator(mode="after")
    def _token(self) -> "Settings":
        if not self.internal_token and self.internal_token_file is not None:
            self.internal_token = self.internal_token_file.read_text().strip()
        if not self.internal_token:
            raise ValueError("DOTS_INTERNAL_TOKEN or DOTS_INTERNAL_TOKEN_FILE is required")
        return self
