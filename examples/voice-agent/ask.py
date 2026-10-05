"""What a voice agent (or its orchestrator) asks DOTS after a call, over MCP.

    uv run python examples/voice-agent/ask.py <call_id> <from_tag>

Same tools any MCP client gets (Claude Code: `claude mcp add --transport http
dots http://127.0.0.1:8000/mcp`): was this call receipted by both operators,
for how many billed seconds, is it provably in both logs, and what does the
period's settlement say.
"""

import asyncio
import json
import sys
from typing import Any

from mcp.client import Client

URL = "http://127.0.0.1:8000/mcp"


async def tool(c: Client, name: str, **args: Any) -> dict[str, Any]:
    r = await c.call_tool(name, args)
    if getattr(r, "structured_content", None):
        data = dict(r.structured_content)
    else:
        data = json.loads(r.content[0].text)
    return dict(data.get("result", data))


async def main(call_id: str, from_tag: str, carrier: str = "node-b", me: str = "node-c") -> None:
    async with Client(URL) as s:
        rc = await tool(
            s, "get_receipt", node_id=me, orig_node=carrier, call_id=call_id, from_tag=from_tag
        )
        print("get_receipt:", json.dumps(rc, indent=2))
        proof = await tool(s, "verify_inclusion", call_key=rc["call_key"])
        print("verify_inclusion:", json.dumps(proof, indent=2))


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:3]))
