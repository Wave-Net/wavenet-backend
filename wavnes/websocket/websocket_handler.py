import asyncio
from wavnes.sniffer import start_mqtt_sniffer


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
