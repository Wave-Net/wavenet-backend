import threading
import asyncio
from pyshark import LiveCapture
from pyshark.packet.packet import Packet
from wavnes.utils import device_ip_to_file_path, make_packet_info
from wavnes.info import PacketTimeInfo
from wavnes.pcap_file_generator import PcapFileGenerator
from wavnes.config import PCAP_DIRECTORY, NETWORK_INTERFACE
from wavnes.logging_config import logger


class Sniffer(threading.Thread):
    def __init__(self, device):
        super().__init__()
        self.device = device
        self.websocket = None
        self.loop = None
        self.time_info = PacketTimeInfo()
        self.packet_send_event = threading.Event()
        self.stop_event = threading.Event()
        self.pcap_generator = None

    def reset(self):
        self.time_info.reset()

    def run(self):
        filter_expr = (
            f"ip and (ip src {self.device.ip} or ip dst {self.device.ip}) "
        )
        self.pcap_generator = PcapFileGenerator(
            interface=NETWORK_INTERFACE, bpf_filter=filter_expr)
        capture = LiveCapture(interface=NETWORK_INTERFACE,
                              bpf_filter=filter_expr,)
        try:
            capture.apply_on_packets(callback=self._packet_callback)
        except asyncio.CancelledError:
            pass
        capture.close()

    def stop(self):
        self.stop_event.set()

    def _update_stat_info(self, src, dst, data):
        self.device.stat_info.update(src, dst, data)

    async def _send_packet_info(self, packet_info, websocket):
        try:
            await websocket.send_json(packet_info)
        except Exception as e:
            print(f"Error sending packet info: {e}")

    def _get_pcap_path(self):
        return device_ip_to_file_path(PCAP_DIRECTORY, self.device.ip, 'pcap')

    def _packet_callback(self, packet: Packet):
        if self.stop_event.is_set():
            raise asyncio.CancelledError
        if not 'mqtt' in packet and not 'coap' in packet:
            return

        self._update_stat_info(
            packet.ip.src, packet.ip.dst, int(packet.length))

        if self.packet_send_event.is_set():
            packet_info = make_packet_info(self.time_info, packet)
            asyncio.run_coroutine_threadsafe(self._send_packet_info(
                packet_info, self.websocket), self.loop)

    def start_packet_send(self, websocket, loop):
        self.websocket = websocket
        self.loop = loop
        self.packet_send_event.set()
        self.pcap_generator.start_capture_for_pcap()
        self.reset()

    def stop_packet_send(self):
        self.packet_send_event.clear()
        self.websocket = None
        self.loop = None
        self.pcap_generator.stop_and_save_pcap(self._get_pcap_path())
