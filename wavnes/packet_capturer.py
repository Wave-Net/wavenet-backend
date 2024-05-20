class PacketCapturer:
    def __init__(self, network_monitor, websocket, loop):
        self.network_monitor = network_monitor
        self.websocket = websocket
        self.loop = loop
        self.selected_device = None

    def start(self, device):
        if self.selected_device:
            self.selected_device.sniffer.stop_packet_send()
        self.selected_device = device
        self.selected_device.sniffer.start_packet_send(
            self.websocket, self.loop)

    def stop(self):
        if self.selected_device:
            self.selected_device.sniffer.stop_packet_send()
            self.selected_device.sniffer.reset_time_info()
            self.selected_device = None
