import asyncio


class PacketStatsSender:
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
        stat_data = []
        for device in devices:
            device_info = device.get_device_info()
            stat_info = device.get_stat_info()
            stat_data.append({
                'device': device_info,
                'stat': stat_info
            })
        await self.websocket.send_json({
            'type': 'stats',
            'data': stat_data
        })
