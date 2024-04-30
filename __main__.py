# __main__.py
import os
import sys

# mqtt 디렉토리 경로를 Python 경로에 추가
sys.path.append(os.path.join(os.path.dirname(__file__), 'mqtt'))

import asyncio
import websockets
from mqtt_sniffer import start_mqtt_sniffer

# 웹소켓 서버 시작
async def start_websocket_server():
    async with websockets.serve(mqtt_packet_handler, "localhost", 8765):
        await asyncio.Future()  # 서버 실행 유지

# 클라이언트 연결 핸들러
async def mqtt_packet_handler(websocket, path):
    # MQTT 패킷 캡처 스니퍼 실행
    asyncio.create_task(start_mqtt_sniffer(websocket))

    try:
        async for message in websocket:
            # 클라이언트로부터 메시지 수신 시 처리 로직 추가
            pass
    finally:
        # 클라이언트 연결 종료 시 처리 로직 추가
        pass

# 메인 함수
async def main():
    await start_websocket_server()

if __name__ == "__main__":
    asyncio.run(main())