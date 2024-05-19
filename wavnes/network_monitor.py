import netifaces
import socket
from wavnes.sniffer import Device


class NetworkMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.devices = {}

    def update_devices(self):
        devices_new = {}
        for addr in netifaces.ifaddresses(self.interface)[netifaces.AF_INET]:
            ip = addr['addr']
            mac = netifaces.ifaddresses(self.interface)[
                netifaces.AF_LINK][0]['addr']
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except:
                hostname = 'Unknown'

            if mac not in self.devices:
                devices_new[mac] = Device(mac, ip, hostname)
            else:
                devices_new[mac] = self.devices[mac]

        for mac in list(self.devices.keys()):
            if mac not in devices_new:
                del self.devices[mac]

        self.devices = devices_new

    def get_devices(self):
        self.update_devices()
        return [device.get_device_info() for device in self.devices.values()]
