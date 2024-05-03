import asyncio
import websockets
from wavnes.websocket.websocket_handler import websocket_handler


async def start_websocket_server():
    print("Starting WebSocket server...")
    async with websockets.serve(websocket_handler, "localhost", 8765):
        print("WebSocket server started")
        await asyncio.Future()  # 서버 실행 유지
