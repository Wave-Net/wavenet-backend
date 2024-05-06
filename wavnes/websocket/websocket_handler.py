import json
from ..capture import SnifferManager


async def websocket_handler(websocket, path):
    client_addr = websocket.remote_address
    sniffer_manager = SnifferManager(websocket)

    print(f"Client connected from {client_addr}")

    try:
        async for message in websocket:
            print(f"Received message from client: {message}")
            data = json.loads(message)
            if data.get("type") == "start_capture":
                print("Starting packet capture...")
                await sniffer_manager.start_sniffer()

            elif data.get("type") == "stop_capture":
                sniffer_manager.stop_sniffer()
                print("Stoppppp packet capture...")

    finally:
        print(f"Client disconnected from {client_addr}")
