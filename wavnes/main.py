import asyncio
from .websocket import start_websocket_server


async def main():
    await start_websocket_server()
