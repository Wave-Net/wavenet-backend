from abc import ABC, abstractmethod
from scapy.all import *
from scapy.contrib.mqtt import *


class PacketHandler(ABC):
    def __init__(self, packet):
        self.packet_info = {
            'source_ip': self._get_source_ip(packet),
            'destination_ip': self._get_destination_ip(packet),
            'length': len(packet),
        }

    @staticmethod
    def _get_source_ip(packet):
        if IP in packet:
            return packet[IP].src
        elif IPv6 in packet:
            return packet[IPv6].src
        elif ARP in packet:
            return packet[ARP].psrc
        elif DHCP in packet:
            return packet[DHCP].ciaddr
        else:
            return None

    @staticmethod
    def _get_destination_ip(packet):
        if IP in packet:
            return packet[IP].dst
        elif IPv6 in packet:
            return packet[IPv6].dst
        elif ARP in packet:
            return packet[ARP].pdst
        elif DHCP in packet:
            return packet[DHCP].siaddr
        else:
            return None

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
                'msg_len': int(mqtt_packet.len),
                'dup': str(mqtt_packet.DUP),
                'qos': str(mqtt_packet.QOS),
                'retain': str(mqtt_packet.RETAIN),
            },
            'type': packet_type,
        })

        if packet_type == 'CONNECT':
            connect_info = {
                'proto_name': str(mqtt_packet.protoname),
                'mqtt_level': str(PROTOCOL_LEVEL.get(mqtt_packet.protolevel, "Unknown")),
                'usernameflag': int(mqtt_packet.usernameflag),
                'passwordflag': int(mqtt_packet.passwordflag),
                'willretainflag': int(mqtt_packet.willretainflag),
                'willQOSflag': int(mqtt_packet.willQOSflag),
                'willflag': int(mqtt_packet.willflag),
                'cleansession': int(mqtt_packet.cleansess),
                'reserved': int(mqtt_packet.reserved),
                'clientId': str(mqtt_packet.clientId),
            }
            if mqtt_packet.klive is not None:
                connect_info['keep_alive'] = int(mqtt_packet.klive)
            if mqtt_packet.willflag and mqtt_packet.willtopic:
                connect_info['willtopic'] = str(mqtt_packet.willtopic)
            if mqtt_packet.willflag and mqtt_packet.willmsg:
                connect_info['willmsg'] = str(mqtt_packet.willmsg)
            if mqtt_packet.usernameflag and mqtt_packet.username:
                connect_info['username'] = str(mqtt_packet.username)
            if mqtt_packet.passwordflag and mqtt_packet.password:
                connect_info['password'] = str(mqtt_packet.password)
            self.packet_info['connect'] = connect_info

        elif packet_type == 'CONNACK':
            connack_info = {
                'ackflag': int(mqtt_packet.sessPresentFlag),
            }
            if mqtt_packet.retcode is not None:
                connack_info['return_code'] = str(RETURN_CODE.get(mqtt_packet.retcode))
            self.packet_info['connack'] = connack_info

        elif packet_type == 'PUBLISH':
            publish_info = {
                'topic': str(mqtt_packet.topic),
                'msgvalue': str(mqtt_packet.value),
            }
            if mqtt_packet.msgid is not None:
                publish_info['msgid'] = int(mqtt_packet.msgid)
            self.packet_info['publish'] = publish_info

        elif packet_type in ['PUBACK', 'PUBREC', 'PUBREL', 'PUBCOMP']:
            self.packet_info[packet_type.lower()] = {
                'msgid': int(mqtt_packet.msgid),
            }

        elif packet_type == 'SUBSCRIBE':
            topic_filters = []
            for topic_filter in mqtt_packet.topics:
                topic_filters.append({
                    'topic': topic_filter.topic.decode('utf-8'),
                    'qos': topic_filter.QOS,
                })
            self.packet_info['subscribe'] = {
                'msgid': int(mqtt_packet.msgid),
                'topic_filters': topic_filters,
            }

        elif packet_type == 'SUBACK':
            self.packet_info['suback'] = {
                'msgid': int(mqtt_packet.msgid),
                'return_code': str(RETURN_CODE.get(mqtt_packet.retcode)),
            }

        elif packet_type == 'UNSUBSCRIBE':
            topic_filters = [topic_filter.decode(
                'utf-8') for topic_filter in mqtt_packet.topics]
            self.packet_info['unsubscribe'] = {
                'msgid': int(mqtt_packet.msgid),
                'topic_filters': topic_filters,
            }

        elif packet_type == 'UNSUBACK':
            self.packet_info['unsuback'] = {
                'msgid': int(mqtt_packet.msgid),
            }

    def get_packet_info(self):
        return self.packet_info
