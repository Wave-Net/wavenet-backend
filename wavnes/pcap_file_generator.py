import scapy.all as scapy
import threading
import os
from scapy.contrib.mqtt import MQTT
from scapy.contrib.coap import CoAP


class PcapFileGenerator:
    def __init__(self, interface, bpf_filter):
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.stop_event = threading.Event()
        self.packets = None
        self.capture_thread = None

    def start_capture_for_pcap(self):
        self.packets = []
        self.capture_thread = threading.Thread(
            target=self._capture_and_store_packets)
        self.stop_event.clear()
        self.capture_thread.start()

    def stop_and_save_pcap(self, pcap_path):
        self.stop_event.set()
        self.capture_thread.join()
        if os.path.exists(pcap_path):
            os.remove(pcap_path)
        if self.packets:
            pcap_dir = os.path.dirname(pcap_path)
            os.makedirs(pcap_dir, exist_ok=True)
            scapy.wrpcap(pcap_path, self.packets)

    def _capture_and_store_packets(self):
        scapy.sniff(iface=self.interface, prn=self._handle_packet,
                    filter=self.bpf_filter, stop_filter=self._stop_condition)

    def _handle_packet(self, packet):
        if MQTT in packet or CoAP in packet:
            self.packets.append(packet)

    def _stop_condition(self, packet):
        return self.stop_event.is_set()
