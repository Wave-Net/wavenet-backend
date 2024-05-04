import json
import asyncio
from scapy.all import *
from scapy.contrib.mqtt import *
from .handlers import *

start_time = None
previous_timestamp = None


def _get_packet_time(packet):
    global start_time, previous_timestamp
    if start_time is None:
        start_time = packet.time

    if previous_timestamp is None:
        seconds_since_previous = 0.0
    else:
        seconds_since_previous = float(packet.time - previous_timestamp)

    return {
        'timestamp': '{:.6f}'.format(packet.time),
        'time_of_day': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time)),
        'seconds_since_beginning': '{:.6f}'.format(float(packet.time - start_time)),
        'seconds_since_previous': '{:.6f}'.format(seconds_since_previous),
    }


def _select_packet_handler(packet):
    if MQTT in packet:
        return MQTTHandler()
    return None


def _packet_callback(packet, websocket, loop):
    global start_time, previous_timestamp

    handler = _select_packet_handler(packet)
    if handler == None:
        return

    packet_info = handler.process_packet(packet)
    packet_info.update(_get_packet_time(packet))
    previous_timestamp = packet.time

    json_data = json.dumps(packet_info)
    asyncio.run_coroutine_threadsafe(websocket.send(json_data), loop)


# 패킷 스니핑 시작
async def start_sniffer(websocket):
   loop = asyncio.get_running_loop()
   await asyncio.to_thread(sniff, prn=lambda packet: _packet_callback(packet, websocket, loop), store=0)
