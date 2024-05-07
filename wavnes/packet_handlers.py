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

        self.packet_info.update({
            'name': 'MQTT',
            'mqtt_type': str(type(mqtt_packet).__name__),
            'mqtt_dup': int(mqtt_packet.DUP),
            'mqtt_qos': int(mqtt_packet.QOS),
            'mqtt_retain': int(mqtt_packet.RETAIN),
        })

        if isinstance(mqtt_packet, MQTTConnect):
            self.packet_info.update({
                'connect_proto_name': str(mqtt_packet.protoname),
                'connect_mqtt_level': f'v{mqtt_packet.protolevel}',
                'connect_usernameflag': int(mqtt_packet.usernameflag),
                'connect_passwordflag': int(mqtt_packet.passwordflag),
                'connect_willretainflag': int(mqtt_packet.willretainflag),
                'connect_willQOSflag': int(mqtt_packet.willQOSflag),
                'connect_willflag': int(mqtt_packet.willflag),
                'connect_cleansession': int(mqtt_packet.cleansession),
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

        elif isinstance(mqtt_packet, MQTTConnack):
            self.packet_info.update({
                'connack_ackflag': int(mqtt_packet.sesspresent),
                'connack_return_code': str(mqtt_packet.retcode),
            })

        elif isinstance(mqtt_packet, MQTTPublish):
            self.packet_info.update({
                'publish_topic': str(mqtt_packet.topic),
                'publish_msgid': str(mqtt_packet.msgid),
                'publish_msgvalue': str(mqtt_packet.value),
            })

        elif isinstance(mqtt_packet, MQTTPuback):
            self.packet_info['puback_msgid'] = str(mqtt_packet.msgid)

        elif isinstance(mqtt_packet, MQTTPubrec):
            self.packet_info['pubrec_msgid'] = str(mqtt_packet.msgid)

        elif isinstance(mqtt_packet, MQTTPubrel):
            self.packet_info['pubrel_msgid'] = str(mqtt_packet.msgid)

        elif isinstance(mqtt_packet, MQTTPubcomp):
            self.packet_info['pubcomp_msgid'] = str(mqtt_packet.msgid)

        return self.packet_info
