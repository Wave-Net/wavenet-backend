from abc import ABC, abstractmethod
import time
from scapy.all import *
from scapy.contrib.mqtt import *


def packet_time_info(start_time, previous_time, packet):
    seconds_since_previous = float(packet.time - previous_time)
    return {
        'timestamp': '{:.6f}'.format(packet.time),
        'time_of_day': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time)),
        'seconds_since_beginning': '{:.6f}'.format(float(packet.time - start_time)),
        'seconds_since_previous': '{:.6f}'.format(seconds_since_previous),
    }


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


class MQTTHandler(PacketHandler):
    def process_packet(self, packet):
        mqtt_packet = packet[MQTT]
        packet_type = CONTROL_PACKET_TYPE.get(mqtt_packet.type, 'Unknown')

        self.packet_info.update({
            'name': 'MQTT',
            'mqtt_type': packet_type,
            'mqtt_dup': int(mqtt_packet.DUP),
            'mqtt_qos': int(mqtt_packet.QOS),
            'mqtt_retain': int(mqtt_packet.RETAIN),
            'mqtt_msg_len': len(mqtt_packet)
        })

        if packet_type == 'CONNECT':
            self.packet_info.update({
                'connect_proto_name': str(mqtt_packet.protoname),
                'connect_mqtt_level': str(PROTOCOL_LEVEL.get(mqtt_packet.protolevel, "Unknown")),
                'connect_usernameflag': int(mqtt_packet.usernameflag),
                'connect_passwordflag': int(mqtt_packet.passwordflag),
                'connect_willretainflag': int(mqtt_packet.willretainflag),
                'connect_willQOSflag': int(mqtt_packet.willQOSflag),
                'connect_willflag': int(mqtt_packet.willflag),
                'connect_cleansession': int(mqtt_packet.cleansess),
                'connect_reserved': int(mqtt_packet.reserved),
                'connect_keep_alive': int(mqtt_packet.klive),
                'connect_clientId': str(mqtt_packet.clientId),
            })
            if mqtt_packet.willflag:
                self.packet_info['connect_willtopic'] = str(
                    mqtt_packet.willtopic)
                self.packet_info['connect_willmsg'] = str(mqtt_packet.willmsg)
            if mqtt_packet.usernameflag:
                self.packet_info['connect_username'] = str(
                    mqtt_packet.username)
            if mqtt_packet.passwordflag:
                self.packet_info['connect_password'] = str(
                    mqtt_packet.password)

        elif packet_type == 'CONNACK':
            self.packet_info.update({
                'connack_ackflag': int(mqtt_packet.sessPresentFlag),
                'connack_return_code': str(mqtt_packet.retcode),
            })

        elif packet_type == 'PUBLISH':
            self.packet_info.update({
                'publish_topic': str(mqtt_packet.topic),
                'publish_msgid': str(mqtt_packet.msgid),
                'publish_msgvalue': str(mqtt_packet.value),
            })

        elif packet_type == 'PUBACK':
            self.packet_info['puback_msgid'] = str(mqtt_packet.msgid)

        elif packet_type == 'PUBREC':
            self.packet_info['pubrec_msgid'] = str(mqtt_packet.msgid)

        elif packet_type == 'PUBREL':
            self.packet_info['pubrel_msgid'] = str(mqtt_packet.msgid)

        elif packet_type == 'PUBCOMP':
            self.packet_info['pubcomp_msgid'] = str(mqtt_packet.msgid)

        return self.packet_info
