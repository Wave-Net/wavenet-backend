import netifaces
import socket
from wavnes.device import Device


class NetworkMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.devices = {}

    def _get_device(self, mac):
        if mac in self.devices:
            return self.devices[mac]
        else:
            return None

    def _add_device(self, ip):
        mac = netifaces.ifaddresses(self.interface)[
            netifaces.AF_LINK][0]['addr']
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = 'Unknown'

        if mac not in self.devices:
            device = Device(mac, ip, hostname)
            self.devices[mac] = device

    def _remove_device(self, mac):
        device = self._get_device(mac)
        if device:
            device.stop_sniffer()
            del self.devices[mac]

    def update_devices(self):
        for addr in netifaces.ifaddresses(self.interface)[netifaces.AF_INET]:
            ip = addr['addr']
            mac = netifaces.ifaddresses(self.interface)[
                netifaces.AF_LINK][0]['addr']
            if mac not in self.devices:
                self._add_device(ip)

        for mac in list(self.devices.keys()):
            device = self.devices[mac]
            if device.ip not in [addr['addr'] for addr in netifaces.ifaddresses(self.interface)[netifaces.AF_INET]]:
                self._remove_device(mac)

    def get_devices(self):
        self.update_devices()
        return list(self.devices.values())

    def start_sniffers(self):
        for device in self.devices.values():
            if not device.is_alive():
                device.start_sniffer()

    def stop_sniffers(self):
        for device in self.devices.values():
            if device.is_alive():
                device.stop_sniffer()
