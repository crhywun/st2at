"""Minimal library usage: ST from the environment, AT to stdout."""

import asyncio
import os

from st2at import ST2ATClient


async def main() -> None:
    st = os.environ["ST2AT_SESSION_TOKEN"]
    client = ST2ATClient(proxy=os.getenv("ST2AT_PROXY") or None)
    result = await client.refresh(st, workspace_id=os.getenv("ST2AT_WORKSPACE_ID"))
    print(result.access_token)


if __name__ == "__main__":
    asyncio.run(main())
