import os
import sys

# mqtt 디렉토리 경로를 Python 경로에 추가
sys.path.append(os.path.join(os.path.dirname(__file__), 'mqtt'))

import asyncio
import websockets
from mqtt_sniffer import start_mqtt_sniffer, send_packet_info

# 클라이언트 연결 핸들러
async def websocket_handler(websocket, path):
    print(f"Client connected from {websocket.remote_address}")
    
    # MQTT 패킷 정보 전송 태스크 생성
    packet_info_task = asyncio.create_task(send_packet_info(websocket, path))

    try:
        await packet_info_task
    finally:
        # 클라이언트 연결 종료 시 태스크 취소
        packet_info_task.cancel()
        print(f"Client disconnected from {websocket.remote_address}")

# 웹소켓 서버 시작 함수
async def start_websocket_server():
    print("Starting WebSocket server...")
    try:
        server = await websockets.serve(websocket_handler, "localhost", 8765)
        print(f"WebSocket server started at ws://{server.sockets[0].getsockname()}")
    except Exception as e:
        print(f"Error starting WebSocket server: {e}")
    return server

# 메인 함수
async def main():
    # 웹소켓 서버 시작
    server_task = asyncio.create_task(start_websocket_server())
    
    # MQTT 패킷 스니퍼 시작
    sniffer_task = asyncio.create_task(start_mqtt_sniffer())

    # 스니퍼 태스크 및 서버 태스크 완료 대기
    await asyncio.gather(server_task, sniffer_task)

if __name__ == "__main__":
    asyncio.run(main())