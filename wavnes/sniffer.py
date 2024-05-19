import threading
import asyncio
from scapy.all import *
from scapy.contrib.mqtt import *
from scapy.contrib.coap import *
from wavnes.packet_handlers import get_packet_handler
from wavnes.info import PacketStatInfo, PacketTimeInfo


class Device:
    def __init__(self, mac, ip, hostname):
        self.mac = mac
        self.ip = ip
        self.hostname = hostname
        self.stat_info = PacketStatInfo(ip)

    def get_device_info(self):
        return {
            'mac': self.mac,
            'ip': self.ip,
            'hostname': self.hostname,
            'stat_info': self.stat_info.get_total()
        }

    def update_packet_stats(self, src, dst, data):
        self.stat_info.update(src, dst, data)


class Sniffer(threading.Thread):
    def __init__(self, device: Device, websocket, loop):
        super().__init__()
        self.device = device
        self.websocket = websocket
        self.loop = loop
        self.time_info = PacketTimeInfo()
        self.stop_event = threading.Event()

    def reset(self):
        self.device.stat_info.reset()
        self.time_info.reset()

    def run(self):
        self.reset()
        filter_expr = f"ip and (ip src {self.iot.ip} or ip dst {self.iot.ip})"
        while not self.stop_event.is_set():
            sniff(prn=lambda packet: self._packet_callback(packet),
                  filter=filter_expr,
                  timeout=1, store=False)

    def stop(self):
        self.stop_event.set()

    def _update_stat_info(self, src, dst, data):
        self.stat_info.update(src, dst, data)

    def _make_packet_info(self, handler, packet):
        self.time_info.update(packet)
        handler.process_packet(packet)
        packet_info = {'message_type': 'packet'}
        packet_info.update(self.time_info.get_time_info())
        packet_info.update(handler.get_packet_info())
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
        packet_info = self._make_packet_info(handler, packet)
        asyncio.run_coroutine_threadsafe(self._send_packet_info(
            packet_info, self.websocket), self.loop)
