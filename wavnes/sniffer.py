import json
import asyncio
import threading
from scapy.all import *
from scapy.contrib.mqtt import *
from wavnes.packet_handlers import MQTTHandler
from wavnes.info import PacketStatInfo, PacketTimeInfo


class Sniffer:
    def __init__(self, websocket):
        self.is_running = False
        self.websocket = websocket
        self.target_ip = '137.135.83.217'
        self.time_info = PacketTimeInfo()
        self.stat_info = PacketStatInfo(self.target_ip)
        self.handler = None
        self.sniffer_thread = None
        self.lock = threading.Lock()
        self.packet_queue = queue.Queue()

    def reset(self):
        self.time_info.reset()
        self.stat_info.reset()
        self.handler = None
        self.packet_info = {}

    def _set_packet_hadnler(self, packet):
        if MQTT in packet:
            self.handler = MQTTHandler(packet)
            return
        self.handler = None

    def _packet_callback(self, packet):
        self._set_packet_hadnler(packet)
        if self.handler == None:
            return

        print('Capture handling...')
        self.time_info.update(packet)
        self.handler.process_packet(packet)

        packet_info = {}
        packet_info.update(self.time_info.get_time_info())
        packet_info.update(self.handler.get_packet_info())

        self.stat_info.update(packet[IP].src, packet[IP].dst, packet[MQTT].len)

        self.packet_queue.put(packet_info)

    def _sniff_thread(self):
        def stop_filter(packet):
            with self.lock:
                return not self.is_running

        with self.lock:
            self.is_running = True

        try:
            sniff(prn=self._packet_callback, stop_filter=stop_filter, store=False)
        except Exception as e:
            print(f"Error in sniff: {e}")
        finally:
            with self.lock:
                self.is_running = False

    async def start_sniff(self):
        self.reset()

        self.sniffer_thread = threading.Thread(target=self._sniff_thread)
        self.sniffer_thread.start()

        self.stat_task = asyncio.create_task(self.send_packet_statistics())
        self.packet_task = asyncio.create_task(self.send_packets())

    def stop_sniff(self):
        if self.sniffer_thread and self.sniffer_thread.is_alive():
            with self.lock:
                self.is_running = False
            self.sniffer_thread.join()

        if self.stat_task:
            self.stat_task.cancel()

        if self.packet_task:
            self.packet_task.cancel()

    async def send_packet_statistics(self):
        while True:
            await asyncio.sleep(1)
            with self.lock:
                stat_data = {'message_type': 'stat'}
                stat_data.update({
                    'total_statistics': self.stat_info.get_total(),
                    'statistics_delta': self.stat_info.get_delta()
                })
                await self.websocket.send(json.dumps(stat_data))

    async def send_packets(self):
        while True:
            try:
                packet_info = self.packet_queue.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.01)
                continue

            packet_data = {'message_type': 'packet'}
            packet_data.update(packet_info)
            await self.websocket.send(json.dumps(packet_data))
