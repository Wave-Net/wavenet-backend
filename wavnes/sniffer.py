import json
import asyncio
import threading
import time
from scapy.all import *
from scapy.contrib.mqtt import *
from wavnes.packet_handlers import MQTTHandler, packet_time_info


class SnifferStatistics:
    def __init__(self):
        self.reset()

    def reset(self):
        self.send_pkt = 0
        self.recv_pkt = 0
        self.send_data = 0
        self.recv_data = 0

    def update(self, packet_info, my_ip):
        if packet_info.get('source_ip') == my_ip:
            self.send_pkt += 1
            self.send_data += packet_info.get('length', 0)
        elif packet_info.get('destination_ip') == my_ip:
            self.recv_pkt += 1
            self.recv_data += packet_info.get('length', 0)

    def get_delta(self, previous_statics):
        if previous_statics is None:
            return self.get_total()

        return {
            'send_pkt': self.send_pkt - previous_statics.send_pkt,
            'recv_pkt': self.recv_pkt - previous_statics.recv_pkt,
            'send_data': self.send_data - previous_statics.send_data,
            'recv_data': self.recv_data - previous_statics.recv_data,
        }

    def get_total(self):
        return {
            'send_pkt': self.send_pkt,
            'recv_pkt': self.recv_pkt,
            'send_data': self.send_data,
            'recv_data': self.recv_data,
        }


class Sniffer:
    def __init__(self, websocket):
        self.websocket = websocket
        self.my_ip = '137.135.83.217'
        self.start_time = None
        self.previous_time = 0.0
        self.sniffer_thread = None
        self.lock = threading.Lock()
        self.is_running = False
        self.statics = SnifferStatistics()
        self.packet_queue = queue.Queue()
        self.index = 0
        
    def _init_data(self):
        self.start_time = time.time()
        self.statics.reset()
        self.index = 0
        
    def _update_index(self):
        self.index += 1

    def _packet_callback(self, packet):
        handler = self._select_packet_handler(packet)
        if handler is None:
            return

        print('Capture handling...')
        packet_info = {'index': self.index}
        packet_info.update(handler.process_packet(packet))
        packet_info.update(packet_time_info(
            self.start_time, self.previous_time, packet))
        self.statics.update(packet_info, self.my_ip)
        self._update_index()

        self.packet_queue.put(packet_info)

    def _select_packet_handler(self, packet):
        if MQTT in packet:
            return MQTTHandler(packet)
        return None

    def _sniff_thread(self):
        def stop_filter(packet):
            with self.lock:
                return not self.is_running

        with self.lock:
            self.is_running = True

        try:
            sniff(prn=self._packet_callback, stop_filter=stop_filter)
        except Exception as e:
            print(f"Error in sniff: {e}")
        finally:
            with self.lock:
                self.is_running = False

    async def start_sniff(self):
        self._init_data()

        self.sniffer_thread = threading.Thread(target=self._sniff_thread)
        self.sniffer_thread.start()

        self.previous_statics = self.statics
        self.statics_task = asyncio.create_task(self.send_packet_statics())
        self.packet_task = asyncio.create_task(self.send_packets())

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
                statics_delta = self.statics.get_delta(self.previous_statics)
                self.previous_statics = self.statics
                await self.websocket.send(json.dumps({
                    'total_statics': self.statics.get_total(),
                    'statics_delta': statics_delta
                }))

    async def send_packets(self):
        while True:
            try:
                packet_info = self.packet_queue.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.01)
                continue

            json_data = json.dumps(packet_info)
            await self.websocket.send(json_data)
