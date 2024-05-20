from wavnes.info import PacketStatInfo
from wavnes.sniffer import Sniffer


class Device:
    def __init__(self, mac, ip, hostname):
        self.mac = mac
        self.ip = ip
        self.hostname = hostname
        self.stat_info = PacketStatInfo(ip)
        self.sniffer = None

    def get_device_info(self):
        return {
            'mac': self.mac,
            'ip': self.ip,
            'hostname': self.hostname,
            'stat_info': self.stat_info.get_total()
        }

    def is_sniffer_alive(self):
        return self.sniffer.is_alive()

    def start_sniffer(self):
        self.sniffer = Sniffer(self)
        self.sniffer.start()

    def stop_sniffer(self):
        self.sniffer.stop()
        self.sniffer.join()
        self.stat_info.reset()
        self.sniffer = None

    def start_packet_send(self, websocket, loop):
        if not self.is_sniffer_alive():
            raise RuntimeError("Sniffer thread is not running")
        self.sniffer.start_packet_send(websocket, loop)

    def stop_packet_send(self):
        if not self.is_sniffer_alive():
            raise RuntimeError("Sniffer thread is not running")
        self.sniffer.stop_packet_send()
