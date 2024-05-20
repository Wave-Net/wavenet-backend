import asyncio


class PacketStatsMonitor:
    def __init__(self, network_monitor, websocket):
        self.network_monitor = network_monitor
        self.websocket = websocket
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
        self.network_monitor.reset()

    async def _monitoring_loop(self):
        while True:
            devices = self.network_monitor.get_devices()
            try:
                await self.send_device_stats(devices)
            except Exception as e:
                print(f"Error sending device stats: {e}")
                break
            await asyncio.sleep(self.update_interval)

    async def send_device_stats(self, devices):
        stats_data = []
        for device in devices:
            stats = device.stat_info.get_total()
            stats_data.append({
                'ip': device.ip,
                'stats': stats
            })
        await self.websocket.send_json({
            'type': 'stats',
            'data': stats_data
        })
