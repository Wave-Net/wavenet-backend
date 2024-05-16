import threading
import queue
from scapy.all import *
from scapy.contrib.mqtt import *
from wavnes.packet_handlers import MQTTHandler
from wavnes.info import PacketStatInfo, PacketTimeInfo


class IoT:
    def __init__(self, mac, ip, hostname):
        self.mac = mac
        self.ip = ip
        self.hostname = hostname


class Sniffer:
    def __init__(self, iot: IoT):
        self.iot = iot
        self.queue = queue.Queue()
        self.thread = None
        self.stop_event = threading.Event()

    def reset(self):
        self.time_info = None
        self.stat_info = None

    def start(self):
        self.time_info = PacketTimeInfo()
        self.stat_info = PacketStatInfo(self.iot.ip)
        self.thread = threading.Thread(target=self._sniff)
        self.thread.start()

    def stop(self):
        if self.thread:
            self.reset()
            self.stop_event.set()
            self.thread.join()
            self.thread = None
            self.stop_event.clear()

    def _get_packet_handler(self, packet):
        if MQTT in packet:
            return MQTTHandler(packet)
        return None

    def _update_stat_info(self, src, dst, data):
        self.stat_info.update(src, dst, data)

    def _make_packet_info(self, handler, packet):
        self.time_info.update(packet)
        handler.process_packet(packet)
        packet_info = {'message_type': 'packet'}
        packet_info.update(self.time_info.get_time_info())
        packet_info.update(handler.get_packet_info())
        return packet_info

    def _packet_callback(self, packet):
        handler = self._get_packet_handler(packet)
        if handler is None:
            return
        self._update_stat_info(
            packet[IP].src, packet[IP].dst, packet[MQTT].len)
        self.queue.put(self._make_packet_info(handler, packet))

    def _sniff(self):
        filter_expr = f"ip and (ip src {self.iot.ip} or ip dst {self.iot.ip})"
        while not self.stop_event.is_set():
            packets = sniff(count=1, filter=filter_expr,
                            timeout=0.1)
            if self.stop_event.is_set():
                break
            for packet in packets:
                self._packet_callback(packet)
