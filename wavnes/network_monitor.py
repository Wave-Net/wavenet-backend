import subprocess
import asyncio
from wavnes.device import Device
from wavnes.utils import get_mac_by_ip, get_hostname_by_ip, get_vendor_by_mac
from wavnes.logging_config import logger


class NetworkMonitor:
    def __init__(self, interface):
        self.interface = interface
        self.devices = {}
        self.update_interval = 1
        self.monitoring_task = None

    async def add_connected_devices(self):
        result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
        output = result.stdout

        for line in output.split('\n'):
            if self.interface in line:
                parts = line.split()
                if len(parts) >= 4:
                    ip = parts[1].strip("()")
                    mac = parts[3]
                    try:
                        hostname = get_hostname_by_ip(ip)
                        vendor = await get_vendor_by_mac(mac)
                    except:
                        hostname = 'Unknown'
                        vendor = 'Unknown'
                    device = Device(mac, ip, hostname, vendor)
                    device.start_sniffer()
                    self.devices[ip] = device

    async def start(self):
        await self.add_connected_devices()
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

    async def _add_device(self, ip):
        try:
            mac = get_mac_by_ip(ip)
            hostname = get_hostname_by_ip(ip)
            vendor = await get_vendor_by_mac(mac)
        except:
            mac = 'Unknown'
            hostname = 'Unknown'
            vendor = 'Unknown'

        if ip not in self.devices:
            device = Device(mac, ip, hostname, vendor)
            device.start_sniffer()
            self.devices[ip] = device

    def _remove_device(self, ip):
        device = self._get_device(ip)
        if device:
            device.stop_sniffer()
            del self.devices[ip]

    def get_devices(self):
        return list(self.devices.values())
