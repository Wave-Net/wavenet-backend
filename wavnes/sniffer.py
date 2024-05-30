import threading
import asyncio
import os
from scapy.all import *
from scapy.contrib.mqtt import *
from scapy.contrib.coap import *
from scapy.utils import wrpcap
from wavnes.packet_handlers import get_packet_handler
from wavnes.info import PacketTimeInfo
from wavnes.config import PCAP_DIRECTORY


class Sniffer(threading.Thread):
    def __init__(self, device):
        super().__init__()
        self.device = device
        self.websocket = None
        self.loop = None
        self.time_info = PacketTimeInfo()
        self.packet_send_event = threading.Event()
        self.stop_event = threading.Event()
        self.packets = []

    def reset(self):
        self.time_info.reset()
        self.packets = []

    def run(self):
        filter_expr = f"ip and (ip src {self.device.ip} or ip dst {self.device.ip})"
        while not self.stop_event.is_set():
            sniff(prn=lambda packet: self._packet_callback(packet),
                  filter=filter_expr,
                  timeout=1, store=False)

    def stop(self):
        self.stop_event.set()
        self.join()

    def _update_stat_info(self, src, dst, data):
        self.device.stat_info.update(src, dst, data)

    def _make_packet_info(self, handler, packet):
        self.time_info.update(packet)
        handler.process_packet(packet)
        packet_info = {'type': 'packet',
                       'data': {}}
        packet_info['data'].update(self.time_info.get_time_info())
        packet_info['data'].update(handler.get_packet_info())
        return packet_info

    async def _send_packet_info(self, packet_info, websocket):
        try:
            await websocket.send_json(packet_info)
        except Exception as e:
            print(f"Error sending packet info: {e}")

    def _packet_callback(self, packet):
        handler = get_packet_handler(packet)
        if handler is None:
            return
        self._update_stat_info(
            handler.src, handler.dst, handler.packet.len)

        if self.packet_send_event.is_set():
            self.packets.append(packet)
            packet_info = self._make_packet_info(handler, packet)
            asyncio.run_coroutine_threadsafe(self._send_packet_info(
                packet_info, self.websocket), self.loop)

    def start_packet_send(self, websocket, loop):
        self.websocket = websocket
        self.loop = loop
        self.packet_send_event.set()
        self.reset()

    def stop_packet_send(self):
        self.packet_send_event.clear()
        self.websocket = None
        self.loop = None
        self._make_pcap_file()

    def _make_pcap_file(self):
        sanitized_ip = self.device.ip.replace('.', '_')
        pcap_file = os.path.join(PCAP_DIRECTORY, f"{sanitized_ip}.pcap")
        if os.path.exists(pcap_file):
            os.remove(pcap_file)
        if self.packets:
            wrpcap(pcap_file, self.packets)
