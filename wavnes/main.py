import asyncio
from .websocket import start_websocket_server


async def main():
    # 웹소켓 서버 시작
    server_task = asyncio.create_task(start_websocket_server())

    # 서버 종료 대기
    await server_task
