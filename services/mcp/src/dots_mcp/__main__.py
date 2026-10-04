"""Run the DOTS MCP server (stdio by default; streamable HTTP for the lab)."""

import logging
from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict

from dots_common.client import DotsClient

from .reader import DotsReader
from .server import build_server


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DOTS_MCP_", extra="ignore")

    state: Path = Path("/state")
    identity: str = "observer"
    settlement_url: str = "http://settlement:8090"
    transport: Literal["stdio", "streamable-http"] = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000


def main() -> None:
    s = Settings()
    logging.basicConfig(level=logging.INFO)
    reader = DotsReader(DotsClient.from_state(s.identity, s.state), s.settlement_url)
    server = build_server(reader)
    if s.transport == "stdio":
        server.run("stdio")
    else:
        server.run("streamable-http", host=s.host, port=s.port)


if __name__ == "__main__":
    main()
