import asyncio
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from wavnes.network_monitor import NetworkMonitor
from wavnes.packet_stats_monitor import PacketStatsMonitor
from wavnes.packet_capturer import PacketCapturer

app = FastAPI()


network_monitor = NetworkMonitor('en0')


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        loop = asyncio.get_event_loop()
        stats_monitor = PacketStatsMonitor(network_monitor, websocket)
        packet_capturer = PacketCapturer(network_monitor, websocket, loop)

        await stats_monitor.start()

        while True:
            message = await websocket.receive_text()
            data = json.loads(message)
            if data["type"] == "start_capture":
                device_ip = data["device_ip"]
                device = network_monitor.get_device_by_ip(device_ip)
                packet_capturer.start(device)
            elif data["type"] == "stop_capture":
                packet_capturer.stop()

    except WebSocketDisconnect:
        packet_capturer.stop()
        await stats_monitor.stop()

    except Exception as e:
        print(f"Error: {e}")
