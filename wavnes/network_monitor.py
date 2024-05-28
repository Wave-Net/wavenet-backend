import netifaces
import socket
import asyncio
from wavnes.device import Device


class NetworkMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.devices = {}
        self.update_interval = 1
        self.monitoring_task = None
        
    async def start(self):
        self.monitoring_task = asyncio.create_task(self._monitoring_loop())

    async def stop(self):
        if self.monitoring_task:
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
            self.monitoring_task = None
            
    async def _monitoring_loop(self):
        while True:
            self.update_devices()
            await asyncio.sleep(self.update_interval)

    def get_device_by_ip(self, ip):
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
        return list(self.devices.values())
