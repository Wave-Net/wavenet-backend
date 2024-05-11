from abc import ABC, abstractmethod
import time
from scapy.all import *
from scapy.contrib.mqtt import *


class PacketHandler(ABC):
    def __init__(self, packet):
        self.packet_info = {
            'source_ip': str(packet[IP].src),
            'destination_ip': str(packet[IP].dst),
            'source_port': int(packet[TCP].sport),
            'destination_port': int(packet[TCP].dport),
            'length': int(packet.len)
        }

    @abstractmethod
    def process_packet(self, packet):
        pass

    @abstractmethod
    def get_packet_info(self, packet):
        pass


class MQTTHandler(PacketHandler):
    def process_packet(self, packet):
        mqtt_packet = packet[MQTT]
        packet_type = CONTROL_PACKET_TYPE.get(mqtt_packet.type, 'Unknown')

        self.packet_info.update({
            'name': 'MQTT',
            'header': {
                'msg_len': str(len(mqtt_packet)),
                'dup': str(mqtt_packet.DUP),
                'qos': str(mqtt_packet.QOS),
                'retain': str(mqtt_packet.RETAIN),
            },
            'type': packet_type,
        })

        if packet_type == 'CONNECT':
            self.packet_info['connect'] = {
                'proto_name': str(mqtt_packet.protoname),
                'mqtt_level': str(PROTOCOL_LEVEL.get(mqtt_packet.protolevel, "Unknown")),
                'usernameflag': str(mqtt_packet.usernameflag),
                'passwordflag': str(mqtt_packet.passwordflag),
                'willretainflag': str(mqtt_packet.willretainflag),
                'willQOSflag': str(mqtt_packet.willQOSflag),
                'willflag': str(mqtt_packet.willflag),
                'cleansession': str(mqtt_packet.cleansess),
                'reserved': str(mqtt_packet.reserved),
                'keep_alive': str(mqtt_packet.klive),
                'clientId': str(mqtt_packet.clientId),
            }
            if mqtt_packet.willflag:
                self.packet_info['connect']['willtopic'] = str(mqtt_packet.willtopic)
                self.packet_info['connect']['willmsg'] = str(mqtt_packet.willmsg)
            if mqtt_packet.usernameflag:
                self.packet_info['connect']['username'] = str(mqtt_packet.username)
            if mqtt_packet.passwordflag:
                self.packet_info['connect']['password'] = str(mqtt_packet.password)

        elif packet_type == 'CONNACK':
            self.packet_info['connack'] = {
                'ackflag': str(mqtt_packet.sessPresentFlag),
                'return_code': str(mqtt_packet.retcode),
            }

        elif packet_type == 'PUBLISH':
            self.packet_info['publish'] = {
                'topic': str(mqtt_packet.topic),
                'msgid': str(mqtt_packet.msgid),
                'msgvalue': str(mqtt_packet.value),
            }

        elif packet_type in ['PUBACK', 'PUBREC', 'PUBREL', 'PUBCOMP']:
            self.packet_info[packet_type.lower()] = {
                'msgid': str(mqtt_packet.msgid),
            }

        elif packet_type == 'SUBSCRIBE':
            topic_filters = []
            for topic_filter in mqtt_packet.topics:
                topic_filters.append({
                    'topic': topic_filter.topic.decode('utf-8'),
                    'qos': str(topic_filter.QOS),
                })
            self.packet_info['subscribe'] = {
                'msgid': str(mqtt_packet.msgid),
                'topic_filters': topic_filters,
            }

        elif packet_type == 'SUBACK':
            self.packet_info['suback'] = {
                'msgid': str(mqtt_packet.msgid),
                'return_code': str(mqtt_packet.retcode),
            }

        elif packet_type == 'UNSUBSCRIBE':
            topic_filters = [topic_filter.decode('utf-8') for topic_filter in mqtt_packet.topics]
            self.packet_info['unsubscribe'] = {
                'msgid': str(mqtt_packet.msgid),
                'topic_filters': topic_filters,
            }

        elif packet_type == 'UNSUBACK':
            self.packet_info['unsuback'] = {
                'msgid': str(mqtt_packet.msgid),
            }

    def get_packet_info(self):
        return self.packet_info
