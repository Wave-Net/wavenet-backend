import asyncio


class PacketDataSender:
    def __init__(self, network_monitor, websocket, loop):
        self.network_monitor = network_monitor
        self.websocket = websocket
        self.loop = loop
        self.selected_device = None
        self.prev_stat_info = None
        self.stat_send_interval = 1
        self.stat_sender_task = None
        
    def reset(self):
        if self.selected_device:
            self.selected_device.sniffer.stop_packet_send()
            self.selected_device = None
        self.prev_stat_info = None

    async def start(self, device):
        self.reset()
        self.selected_device = device

        self.selected_device.sniffer.start_packet_send(
            self.websocket, self.loop)
        self.stat_sender_task = asyncio.create_task(self._stat_send_loop())

    async def stop(self):
        if self.stat_sender_task:
            self.stat_sender_task.cancel()
            try:
                await self.stat_sender_task
            except asyncio.CancelledError:
                pass
            self.stat_sender_task = None

        if self.selected_device:
            self.selected_device.sniffer.stop_packet_send()
            self.selected_device = None

    async def _stat_send_loop(self):
        while True:
            try:
                await self.send_packet_stat()
            except Exception as e:
                print(f"Error sending packet stat: {e}")
                break
            await asyncio.sleep(self.stat_send_interval)

    def _calc_stat_diff(self, cur_stat_info):
        prev_stat_info = self.prev_stat_info
        stat_diff = {
            'send_pkt': cur_stat_info['send_pkt'] - prev_stat_info['send_pkt'],
            'recv_pkt': cur_stat_info['recv_pkt'] - prev_stat_info['recv_pkt'],
            'send_data': cur_stat_info['send_data'] - prev_stat_info['send_data'],
            'recv_data': cur_stat_info['recv_data'] - prev_stat_info['recv_data'],
        }
        return stat_diff

    async def send_packet_stat(self):
        cur_stat_info = self.selected_device.get_stat_info()
        if self.prev_stat_info == None:
            self.prev_stat_info = cur_stat_info
        stat_diff = self._calc_stat_diff(cur_stat_info)
        await self.websocket.send_json({
            'type': 'stat',
            'data': stat_diff
        })
        self.prev_stat_info = cur_stat_info
