import json
import asyncio
import threading
import time
from scapy.all import *
from scapy.contrib.mqtt import *
from .handlers import *

start_time = None
previous_timestamp = None

class SnifferManager:
    def __init__(self, websocket):
        self.websocket = websocket
        self.sniffer_thread = None
        self.lock = threading.Lock()
        self.is_running_sniffer = False


    def _get_packet_time(self, packet):
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


    def _select_packet_handler(self, packet):
        if MQTT in packet:
            return MQTTHandler()
        return None


    def _packet_callback(self, packet, websocket, loop):
        global start_time, previous_timestamp

        handler = self._select_packet_handler(packet)
        if handler is None:
            return
        
        print("Capturing packet_info")
        packet_info = handler.process_packet(packet)
        packet_info.update(self._get_packet_time(packet))
        previous_timestamp = packet.time

        json_data = json.dumps(packet_info)
        asyncio.run_coroutine_threadsafe(websocket.send(json_data), loop)

    async def start_sniffer(self):
        loop = asyncio.get_running_loop()

        def sniff_thread():
            def stop_sniff(packet):
                with self.lock:
                    return not self.is_running_sniffer

            with self.lock:
                self.is_running_sniffer = True

            sniff(prn=lambda packet: self._packet_callback(packet, self.websocket, loop),
                  stop_filter=stop_sniff)

            with self.lock:
                self.is_running_sniffer = False

        self.sniffer_thread = threading.Thread(target=sniff_thread)
        self.sniffer_thread.start()

    def stop_sniffer(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            with self.lock:
                self.is_running_sniffer = False
            self.sniffer_thread.join()