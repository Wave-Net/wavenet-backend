import asyncio
import json
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from contextlib import asynccontextmanager
from wavnes.network_monitor import NetworkMonitor
from wavnes.monitoring_data_sender import MonitoringDataSender
from wavnes.packet_data_sender import PacketDataSender


network_monitor = NetworkMonitor('en0')


@asynccontextmanager
async def lifespan(app: FastAPI):
    await network_monitor.start()
    try:
        yield
    finally:
        pass


app = FastAPI(lifespan=lifespan)


@app.websocket("/capture")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        loop = asyncio.get_event_loop()
        sender = PacketDataSender(network_monitor, websocket, loop)

        device_ip = '192.168.55.30'
        device = network_monitor.get_device_by_ip(device_ip)
        print(device.ip)

        await sender.start(device)

        while True:
            message = await websocket.receive_text()
            # data = json.loads(message)
            # if data["type"] == "start_capture":
            #     device_ip = data["device_ip"]
            #     device = network_monitor.get_device_by_ip(device_ip)
            #     await sender.start(device)
            # elif data["type"] == "stop_capture":
            #     await sender.stop()

    except WebSocketDisconnect:
        await sender.stop()

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await sender.stop()


@app.websocket("/monitor")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        sender = MonitoringDataSender(network_monitor, websocket)
        await sender.start()

        while True:
            message = await websocket.receive_text()
            data = json.loads(message)

    except WebSocketDisconnect:
        await sender.stop()

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await sender.stop()
