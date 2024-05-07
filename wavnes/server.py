import websockets
import json
from wavnes.sniffer import Sniffer


async def _websocket_handler(websocket, path):
    client_addr = websocket.remote_address
    sniffer = Sniffer(websocket)

    print(f"Client connected from {client_addr}")

    try:
        async for message in websocket:
            print(f"Received message from client: {message}")
            data = json.loads(message)
            if data.get("type") == "start_capture":
                print("Starting packet capture...")
                await sniffer.start_sniff()

            elif data.get("type") == "stop_capture":
                sniffer.stop_sniff()
                print("Stoppppp packet capture...")

    finally:
        print(f"Client disconnected from {client_addr}")


async def start_server(host, port):
    print("Starting WebSocket server...")
    server = await websockets.serve(_websocket_handler, host, port)
    print("WebSocket server started")
    await server.wait_closed()
    print("WebSocket server stopped")
