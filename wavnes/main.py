import asyncio
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from wavnes.network_monitor import NetworkMonitor

app = FastAPI()


network_monitor = NetworkMonitor('en0')


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    try:
        while True:
            devices = network_monitor.get_devices()
            for device_info in devices:
                await websocket.send_json(device_info)
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"Error: {e}")
