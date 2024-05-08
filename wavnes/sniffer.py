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
        self.target_ip = '137.135.83.217'
        self.packet_statics = {
            'send_pkt': 0,
            'recv_pkt': 0,
            'send_data': 0,
            'recv_data': 0,
        }
        self.previous_statics = None
        self.statics_task = None
        self.index = 0
        
    def _init_data(self):
        self.start_time = time.time()
        self.previous_time = 0.0
        self.packet_statics = {
            'send_pkt': 0,
            'recv_pkt': 0,
            'send_data': 0,
            'recv_data': 0,
        }
        self.index = 0
        self.previous_statics = None

    def _update_previous_time(self, packet):
        self.previous_time = packet.time
        
    def _update_index(self):
        self.index += 1

    def _update_packet_statics(self, packet_info):
        with self.lock:
            if packet_info.get('source_ip') == self.target_ip:
                self.packet_statics['send_pkt'] += 1
                self.packet_statics['send_data'] += packet_info.get(
                    'length', 0)
            elif packet_info.get('destination_ip') == self.target_ip:
                self.packet_statics['recv_pkt'] += 1
                self.packet_statics['recv_data'] += packet_info.get(
                    'length', 0)

    def _packet_callback(self, packet, websocket, loop):
        handler = _select_packet_handler(packet)
        if handler is None:
            return

        print("Capturing packet_info")
        packet_info = {'index': self.index}
        packet_info.update(handler.process_packet(packet))
        packet_info.update(packet_time_info(
            self.start_time, self.previous_time, packet))
        self._update_previous_time(packet)
        self._update_packet_statics(packet_info)
        self._update_index()

        json_data = json.dumps(packet_info)
        asyncio.run_coroutine_threadsafe(websocket.send(json_data), loop)

    async def start_sniff(self):
        loop = asyncio.get_running_loop()

        self._init_data()

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

        self.previous_statics = self.packet_statics.copy()
        self.statics_task = asyncio.create_task(self.send_packet_statics())

    def stop_sniff(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            with self.lock:
                self.is_running = False
            self.sniffer_thread.join()
        if self.statics_task:
            self.statics_task.cancel()

    async def send_packet_statics(self):
        while True:
            await asyncio.sleep(1)
            with self.lock:
                total_statics = self.packet_statics.copy()
                if self.previous_statics:
                    statics_delta = {
                        'send_pkt': total_statics['send_pkt'] - self.previous_statics['send_pkt'],
                        'recv_pkt': total_statics['recv_pkt'] - self.previous_statics['recv_pkt'],
                        'send_data': total_statics['send_data'] - self.previous_statics['send_data'],
                        'recv_data': total_statics['recv_data'] - self.previous_statics['recv_data'],
                    }
                    self.previous_statics = total_statics.copy()
                else:
                    statics_delta = total_statics

                await self.websocket.send(json.dumps({
                    'total_statics': total_statics,
                    'statics_delta': statics_delta
                }))
