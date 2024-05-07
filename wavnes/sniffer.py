import json
import asyncio
import threading
from scapy.all import *
from scapy.contrib.mqtt import *
from wavnes.packet_handlers import MQTTHandler, packet_time_info


def _select_packet_handler(packet):
    if MQTT in packet:
        return MQTTHandler(packet)
    return None


class Sniffer:
    def __init__(self, websocket):
        self.websocket = websocket
        self.start_time = None
        self.previous_time = 0.0
        self.sniffer_thread = None
        self.lock = threading.Lock()
        self.is_running = False

    def _update_previous_time(self, packet):
        self.previous_time = packet.time

    def _packet_callback(self, packet, websocket, loop):
        handler = _select_packet_handler(packet)
        if handler is None:
            return

        print("Capturing packet_info")
        packet_info = handler.process_packet(packet)
        packet_info.update(packet_time_info(
            self.start_time, self.previous_time, packet))
        self._update_previous_time(packet)

        json_data = json.dumps(packet_info)
        asyncio.run_coroutine_threadsafe(websocket.send(json_data), loop)

    async def start_sniff(self):
        loop = asyncio.get_running_loop()

        self.start_time = time.time()

        def sniff_thread():
            def stop_filter(packet):
                with self.lock:
                    return not self.is_running
            with self.lock:
                self.is_running = True
            sniff(prn=lambda packet: self._packet_callback(packet, self.websocket, loop),
                  stop_filter=stop_filter)
            with self.lock:
                self.is_running = False

        self.sniffer_thread = threading.Thread(target=sniff_thread)
        self.sniffer_thread.start()

    def stop_sniff(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            with self.lock:
                self.is_running = False
            self.sniffer_thread.join()
