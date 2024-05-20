import netifaces
import socket
from wavnes.device import Device


class NetworkMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.devices = {}

    def _get_device(self, ip):
        if ip in self.devices:
            return self.devices[ip]
        else:
            return None

    def reset(self):
        for device in self.devices.values():
            device.stop_sniffer()
        self.devices = {}

    def _add_device(self, ip):
        try:
            mac = self._get_mac_by_ip(ip)
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            mac = 'Unknown'
            hostname = 'Unknown'

        if ip not in self.devices:
            device = Device(mac, ip, hostname)
            device.start_sniffer()
            self.devices[ip] = device

    def _remove_device(self, ip):
        device = self._get_device(ip)
        if device:
            device.stop_sniffer()
            del self.devices[ip]

    def update_devices(self):
        current_ips = set()
        for addr in netifaces.ifaddresses(self.interface)[netifaces.AF_INET]:
            ip = addr['addr']
            current_ips.add(ip)
            if ip not in self.devices:
                self._add_device(ip)

        for ip in list(self.devices.keys()):
            if ip not in current_ips:
                self._remove_device(ip)

    def get_devices(self):
        self.update_devices()
        return list(self.devices.values())
