import asyncio
import json
from ..capture import start_sniffer


async def websocket_handler(websocket, path):
    client_addr = websocket.remote_address

    print(f"Client connected from {client_addr}")

    try:
        async for message in websocket:
            print(f"Received message from client: {message}")
            data = json.loads(message)
            if data.get("type") == "start_capture":
                print("Starting packet capture...")
                # MQTT 패킷 스니퍼 시작
                sniffer_task = asyncio.create_task(start_sniffer(websocket))
                try:
                    await sniffer_task
                finally:
                    # 클라이언트 연결 종료 시 태스크 취소
                    print("Stop packet capture...")
                    sniffer_task.cancel()

    finally:
        print(f"Client disconnected from {client_addr}")
