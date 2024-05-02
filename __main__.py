import os
import sys

# mqtt 디렉토리 경로를 Python 경로에 추가
sys.path.append(os.path.join(os.path.dirname(__file__), 'mqtt'))

import asyncio
import websockets
from mqtt_sniffer import start_mqtt_sniffer

# 클라이언트 연결 핸들러
async def websocket_handler(websocket, path):
    client_addr = websocket.remote_address

    print(f"Client connected from {client_addr}")
    print("Starting packet capture...")

    # MQTT 패킷 스니퍼 시작
    sniffer_task = asyncio.create_task(start_mqtt_sniffer(websocket))

    try:
        await sniffer_task
    finally:
        # 클라이언트 연결 종료 시 태스크 취소
        sniffer_task.cancel()
        print(f"Client disconnected from {client_addr}")

# 웹소켓 서버 시작 함수
async def start_websocket_server():
    print("Starting WebSocket server...")
    async with websockets.serve(websocket_handler, "localhost", 8765):
        print("WebSocket server started")
        await asyncio.Future()  # 서버 실행 유지

# 메인 함수
async def main():
    # 웹소켓 서버 시작
    server_task = asyncio.create_task(start_websocket_server())

    # 서버 종료 대기
    await server_task

if __name__ == "__main__":
    asyncio.run(main())