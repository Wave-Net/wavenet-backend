import asyncio
import websockets
from .websocket_handler import websocket_handler


async def start_websocket_server():
    print("Starting WebSocket server...")
    server = await websockets.serve(websocket_handler, "localhost", 8765)
    print("WebSocket server started")
    await server.wait_closed()  # 서버 종료 대기
    print("WebSocket server stopped")
