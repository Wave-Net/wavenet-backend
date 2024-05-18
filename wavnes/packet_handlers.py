from abc import ABC, abstractmethod
from scapy.all import *
from scapy.contrib.mqtt import *
from scapy.contrib.coap import *


def get_packet_src(packet):
    if IP in packet:
        return packet[IP].src
    elif IPv6 in packet:
        return packet[IPv6].src
    elif ARP in packet:
        return packet[ARP].psrc
    elif DHCP in packet:
        return packet[DHCP].ciaddr
    else:
        return ''


def get_packet_dst(packet):
    if IP in packet:
        return packet[IP].dst
    elif IPv6 in packet:
        return packet[IPv6].dst
    elif ARP in packet:
        return packet[ARP].pdst
    elif DHCP in packet:
        return packet[DHCP].siaddr
    else:
        return ''


def get_packet_handler(packet):
    if MQTT in packet:
        return MQTTHandler(packet)
    if CoAP in packet:
        return CoAPHandler(packet)
    return None


class PacketHandler(ABC):
    def __init__(self, packet):
        self.packet = packet
        self.src = get_packet_src(packet)
        self.dst = get_packet_dst(packet)
        self.packet_info = {
            'source_ip': self.src,
            'destination_ip': self.dst,
            'length': len(packet),
        }

    @abstractmethod
    def process_packet(self, packet):
        pass

    def get_packet_info(self):
        return self.packet_info


class MQTTHandler(PacketHandler):
    def process_packet(self, packet):
        self.packet = packet[MQTT]
        packet_type = CONTROL_PACKET_TYPE.get(self.packet.type, 'Unknown')

        self.packet_info.update({
            'name': 'MQTT',
            'header': {
                'msg_len': int(self.packet.len),
                'dup': str(self.packet.DUP),
                'qos': str(self.packet.QOS),
                'retain': str(self.packet.RETAIN),
            },
            'type': packet_type,
        })

        if packet_type == 'CONNECT':
            connect_info = {
                'proto_name': str(self.packet.protoname),
                'mqtt_level': str(PROTOCOL_LEVEL.get(self.packet.protolevel, "Unknown")),
                'usernameflag': int(self.packet.usernameflag),
                'passwordflag': int(self.packet.passwordflag),
                'willretainflag': int(self.packet.willretainflag),
                'willQOSflag': int(self.packet.willQOSflag),
                'willflag': int(self.packet.willflag),
                'cleansession': int(self.packet.cleansess),
                'reserved': int(self.packet.reserved),
                'clientId': str(self.packet.clientId),
            }
            if self.packet.klive is not None:
                connect_info['keep_alive'] = int(self.packet.klive)
            if self.packet.willflag and self.packet.willtopic:
                connect_info['willtopic'] = str(self.packet.willtopic)
            if self.packet.willflag and self.packet.willmsg:
                connect_info['willmsg'] = str(self.packet.willmsg)
            if self.packet.usernameflag and self.packet.username:
                connect_info['username'] = str(self.packet.username)
            if self.packet.passwordflag and self.packet.password:
                connect_info['password'] = str(self.packet.password)
            self.packet_info['connect'] = connect_info

        elif packet_type == 'CONNACK':
            connack_info = {
                'ackflag': int(self.packet.sessPresentFlag),
            }
            if self.packet.retcode is not None:
                connack_info['return_code'] = str(
                    RETURN_CODE.get(self.packet.retcode))
            self.packet_info['connack'] = connack_info

        elif packet_type == 'PUBLISH':
            publish_info = {
                'topic': str(self.packet.topic),
                'msgvalue': str(self.packet.value),
            }
            if self.packet.msgid is not None:
                publish_info['msgid'] = int(self.packet.msgid)
            self.packet_info['publish'] = publish_info

        elif packet_type in ['PUBACK', 'PUBREC', 'PUBREL', 'PUBCOMP']:
            self.packet_info[packet_type.lower()] = {
                'msgid': int(self.packet.msgid),
            }

        elif packet_type == 'SUBSCRIBE':
            topic_filters = []
            for topic_filter in self.packet.topics:
                topic_filters.append({
                    'topic': topic_filter.topic.decode('utf-8'),
                    'qos': topic_filter.QOS,
                })
            self.packet_info['subscribe'] = {
                'msgid': int(self.packet.msgid),
                'topic_filters': topic_filters,
            }

        elif packet_type == 'SUBACK':
            self.packet_info['suback'] = {
                'msgid': int(self.packet.msgid),
                'return_code': str(RETURN_CODE.get(self.packet.retcode)),
            }

        elif packet_type == 'UNSUBSCRIBE':
            topic_filters = [topic_filter.decode(
                'utf-8') for topic_filter in self.packet.topics]
            self.packet_info['unsubscribe'] = {
                'msgid': int(self.packet.msgid),
                'topic_filters': topic_filters,
            }

        elif packet_type == 'UNSUBACK':
            self.packet_info['unsuback'] = {
                'msgid': int(self.packet.msgid),
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
        self.packet = packet[CoAP]
        self.packet_info.update({
            'name': 'CoAP',
            'version': int(self.packet.ver),
            'type': int(self.packet.type),
            'token_length': int(self.packet.tkl),
            'code': int(self.packet.code),
            'message_id': int(self.packet.msg_id),
            'token': bytes(self.packet.token).hex()
        })

        if self.packet.options:
            self.packet_info['options'] = []
            for option in self.packet.options:
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

        if hasattr(self.packet, 'payload') and self.packet.payload:
            try:
                self.packet_info['payload'] = bytes(
                    self.packet.payload).decode('utf-8', errors='ignore')
            except Exception as e:
                self.packet_info['payload'] = f"Cannot decode payload: {e}"
        else:
            self.packet_info['payload'] = "None"
