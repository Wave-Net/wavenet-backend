from scapy.all import *
from scapy.contrib.mqtt import *
from .handler import PacketHandler


class MQTTHandler(PacketHandler):
    def process_packet(self, packet):
        mqtt_packet = packet[MQTT]

        packet_info = {
            'protocol': 'MQTT',
            'type': str(type(mqtt_packet).__name__),
            'qos': int(mqtt_packet.QOS),
            'length': int(mqtt_packet.len)
        }

        if hasattr(mqtt_packet, 'flags'):
            packet_info['flags'] = int(mqtt_packet.flags)

        if hasattr(mqtt_packet, 'topic'):
            packet_info['topic'] = str(mqtt_packet.topic)

        if hasattr(mqtt_packet, 'value'):
            packet_info['value'] = mqtt_packet.value.decode('utf-8')

        return packet_info
