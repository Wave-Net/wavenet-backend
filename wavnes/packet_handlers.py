from abc import ABC, abstractmethod
from scapy.all import *
from scapy.contrib.mqtt import *
from scapy.contrib.coap import *


def get_packet_handler(packet):
    if MQTT in packet:
        return MQTTHandler(packet)
    if CoAP in packet:
        return CoAPHandler(packet)
    return None


class PacketHandler(ABC):
    def __init__(self, packet):
        self.packet_info = {
            'source_ip': packet[IP].src,
            'destination_ip': packet[IP].dst,
            'length': len(packet),
        }

    @abstractmethod
    def process_packet(self, packet):
        pass

    def get_packet_info(self):
        return self.packet_info


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
                connack_info['return_code'] = str(
                    RETURN_CODE.get(mqtt_packet.retcode))
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


class CoAPHandler(PacketHandler):
    CONTENT_FORMATS = {
        0: "text/plain; charset=utf-8",
        40: "application/link-format",
        41: "application/xml",
        42: "application/octet-stream",
        47: "application/exi",
        50: "application/json",
        # 추가 포맷이 필요한 경우 여기에 추가할 수 있습니다.
    }

    def process_packet(self, packet):
        coap_packet = packet[CoAP]
        self.packet_info.update({
            'name': 'CoAP',
            'version': int(coap_packet.ver),
            'type': int(coap_packet.type),
            'token_length': int(coap_packet.tkl),
            'code': int(coap_packet.code),
            'message_id': int(coap_packet.msg_id),
            'token': bytes(coap_packet.token).hex()
        })

        if coap_packet.options:
            self.packet_info['options'] = []
            for option in coap_packet.options:
                try:
                    option_number, option_value = option

                    if option_number == 12:
                        option_value = self.CONTENT_FORMATS.get(
                            option_value, "Unknown")
                    elif isinstance(option_value, bytes):
                        option_value = option_value.decode(
                            'utf-8', errors='ignore')

                    self.packet_info['options'].append({
                        'number': option_number,
                        'value': option_value
                    })
                except Exception as e:
                    self.packet_info['options'].append({
                        'number': None,
                        'value': f"Error decoding option: {e}"
                    })

        if hasattr(coap_packet, 'payload') and coap_packet.payload:
            try:
                self.packet_info['payload'] = bytes(
                    coap_packet.payload).decode('utf-8', errors='ignore')
            except Exception as e:
                self.packet_info['payload'] = f"Cannot decode payload: {e}"
        else:
            self.packet_info['payload'] = "None"
