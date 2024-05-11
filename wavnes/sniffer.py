import json
import asyncio
import threading
import time
from scapy.all import *
from scapy.contrib.mqtt import *
from wavnes.packet_handlers import MQTTHandler


class PacketTimeInfo():
    def __init__(self):
        self.reset()

    def reset(self):
        self.index = 0
        self.start_time = time.time()
        self.previous_time = 0.0
        self.current_time = 0.0

    def update(self, packet):
        self.index += 1
        self.previous_time = self.current_time
        self.current_time = packet.time

    def get_time_info(self):
        return {
            'index': self.index,
            'timestamp': '{:.6f}'.format(self.current_time),
            'time_of_day': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(self.current_time)),
            'seconds_since_beginning': '{:.6f}'.format(float(self.current_time - self.start_time)),
            'seconds_since_previous': '{:.6f}'.format(float(self.current_time - self.previous_time)),
        }


class PacketStatistics:
    def __init__(self, target_ip):
        self.reset()
        self.target_ip = target_ip

    def reset(self):
        self.send_pkt = 0
        self.recv_pkt = 0
        self.send_data = 0
        self.recv_data = 0

    def update(self, packet):
        if packet['IP'].src == self.target_ip:
            self.send_pkt += 1
            self.send_data += int(packet.len)
        elif packet['IP'].dst == self.target_ip:
            self.recv_pkt += 1
            self.recv_data += int(packet.len)

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
        self.is_running = False
        self.websocket = websocket
        self.target_ip = '137.135.83.217'
        self.time_info = PacketTimeInfo()
        self.prev_stat = None
        self.stat = PacketStatistics(self.target_ip)
        self.handler = None
        self.sniffer_thread = None
        self.lock = threading.Lock()
        self.packet_queue = queue.Queue()

    def reset(self):
        self.time_info.reset()
        self.stat.reset()
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

        self.stat.update(packet)

        self.packet_queue.put(packet_info)

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
                stat_delta = self.stat.get_delta(self.prev_stat)
                self.prev_stat = self.stat
                stat_data = {'message_type': 'stat'}
                stat_data.update({
                    'total_statistics': self.stat.get_total(),
                    'statistics_delta': stat_delta
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
