import asyncio
import json
import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from wavnes.network_monitor import NetworkMonitor
from wavnes.monitoring_data_sender import MonitoringDataSender
from wavnes.packet_data_sender import PacketDataSender
from wavnes.config import PCAP_DIRECTORY, CSV_DIRECTORY, JSON_DIRECTORY, NETWORK_INTERFACE
from wavnes.utils import *


network_monitor = NetworkMonitor(NETWORK_INTERFACE)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await network_monitor.start()
    try:
        yield
    finally:
        pass


app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET"],
)


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


@app.websocket("/capture")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()

    try:
        loop = asyncio.get_event_loop()
        sender = PacketDataSender(network_monitor, websocket, loop)

        while True:
            message = await websocket.receive_text()
            data = json.loads(message)
            if data["type"] == "start_capture":
                device_ip = data["data"]
                device = network_monitor.get_device_by_ip(device_ip)
                await sender.start(device)
            elif data["type"] == "stop_capture":
                await sender.stop()

    except WebSocketDisconnect:
        await sender.stop()

    except Exception as e:
        print(f"Error: {e}")

    finally:
        await sender.stop()


@app.get("/download/pcap")
def download_pcap_endpoint(device_ip: str = Query(..., description="Target device IP")):
    pcap_path = device_ip_to_file_path(PCAP_DIRECTORY, device_ip, 'pcap')
    if not os.path.isfile(pcap_path):
        raise HTTPException(
            status_code=404, detail="File not found or access denied")
    return FileResponse(pcap_path,
                        media_type='application/vnd.tcpdump.pcap',
                        filename=os.path.basename(pcap_path))


@app.get("/download/csv")
def download_csv_endpoint(device_ip: str = Query(..., description="Target device IP")):
    pcap_path = device_ip_to_file_path(PCAP_DIRECTORY, device_ip, 'pcap')
    if not os.path.isfile(pcap_path):
        raise HTTPException(
            status_code=404, detail="File not found or access denied")
    csv_path = device_ip_to_file_path(CSV_DIRECTORY, device_ip, 'csv')
    make_csv_from_pcap(pcap_path, csv_path)
    return FileResponse(csv_path,
                        media_type='text/csv',
                        filename=os.path.basename(csv_path))


@app.get("/download/json")
def download_csv_endpoint(device_ip: str = Query(..., description="Target device IP")):
    pcap_path = device_ip_to_file_path(PCAP_DIRECTORY, device_ip, 'pcap')
    if not os.path.isfile(pcap_path):
        raise HTTPException(
            status_code=404, detail="File not found or access denied")
    json_path = device_ip_to_file_path(JSON_DIRECTORY, device_ip, 'json')
    make_json_from_pcap(pcap_path, json_path)
    return FileResponse(json_path,
                        media_type='application/json',
                        filename=os.path.basename(json_path))
