import websockets
import subprocess  # 테스트용
import asyncio
import json
from wavnes.sniffer import Sniffer, IoT


def _get_network_info(interface="en0"):  # 테스트용 mac, ip, hostname
    try:
        output = subprocess.check_output(
            ["ifconfig", interface]).decode("utf-8")
        lines = output.split("\n")

        for line in lines:
            if "inet " in line:
                ip = line.split("inet ")[1].split(" ")[0]
            elif "ether " in line:
                mac = line.split("ether ")[1].split(" ")[0]
            elif "inet6 " in line and "%en0" in line:
                hostname = line.split("%")[0].split(" ")[1]

        return mac, ip, hostname
    except Exception as e:
        print("네트워크 정보를 가져올 수 없습니다:", e)
        return None, None, None


async def _websocket_handler(websocket, path):
    client_addr = websocket.remote_address
    print(f"Client connected from {client_addr}")

    mac, ip, hostname = _get_network_info()
    if not all([mac, ip, hostname]):
        print("네트워크 정보를 가져올 수 없어 종료합니다.")
        return

    iot = IoT(mac, ip, hostname)
    sniffer = Sniffer(iot)
    loop = asyncio.get_running_loop()

    try:
        async for message in websocket:
            print(f"Received message from client: {message}")
            data = json.loads(message)
            if data.get("type") == "start_capture":
                print("Starting packet capture...")
                sniffer.start(websocket, loop)
            elif data.get("type") == "stop_capture":
                print("Stopping packet capture...")
                sniffer.stop()
    except json.JSONDecodeError:
        print('Json parsing error')
        pass
    except websockets.exceptions.ConnectionClosedError:
        print("Client closed the connection.")
    finally:
        sniffer.stop()


async def start_server(host, port):
    print("Starting WebSocket server...")
    server = await websockets.serve(_websocket_handler, host, port)
    print("WebSocket server started")
    await server.wait_closed()
    print("WebSocket server stopped")
