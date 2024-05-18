import threading
import asyncio
import json
from scapy.all import *
from scapy.contrib.mqtt import *
from scapy.contrib.coap import *
from wavnes.packet_handlers import get_packet_handler
from wavnes.info import PacketStatInfo, PacketTimeInfo


class IoT:
    def __init__(self, mac, ip, hostname):
        self.mac = mac
        self.ip = ip
        self.hostname = hostname


class Sniffer:
    def __init__(self, iot: IoT):
        self.iot = iot
        self.thread = None
        self.time_info = None
        self.stat_info = None
        self.stop_event = threading.Event()

    def reset(self):
        self.time_info = PacketTimeInfo()
        self.stat_info = PacketStatInfo(self.iot.ip)

    def start(self, websocket, loop):
        self.reset()
        self.thread = threading.Thread(
            target=self._sniff, args=(websocket, loop))
        self.thread.start()

    def stop(self):
        if self.thread:
            self.stop_event.set()
            self.thread.join()
            self.thread = None
            self.stop_event.clear()

    def _update_stat_info(self, src, dst, data):
        self.stat_info.update(src, dst, data)

    def _make_packet_info(self, handler, packet):
        self.time_info.update(packet)
        handler.process_packet(packet)
        packet_info = {'message_type': 'packet'}
        packet_info.update(self.time_info.get_time_info())
        packet_info.update(handler.get_packet_info())
        return packet_info

    def _send_packet_info(self, packet_info, websocket, loop):
        try:
            asyncio.run_coroutine_threadsafe(
                websocket.send(json.dumps(packet_info)), loop)
        except Exception as e:
            print(f"Error sending packet info: {e}")

    def _packet_callback(self, packet, websocket, loop):
        handler = get_packet_handler(packet)
        if handler is None:
            return
        self._update_stat_info(
            handler.src, handler.dst, handler.packet.len)
        packet_info = self._make_packet_info(handler, packet)
        self._send_packet_info(packet_info, websocket, loop)

    def _sniff(self, websocket, loop):
        filter_expr = f"ip and (ip src {self.iot.ip} or ip dst {self.iot.ip})"
        while not self.stop_event.is_set():
            sniff(prn=lambda packet: self._packet_callback(packet, websocket, loop),
                  filter=filter_expr,
                  timeout=1, store=False)
