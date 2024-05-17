from abc import ABC, abstractmethod
import time
from scapy.all import *
from scapy.contrib.mqtt import *
from scapy.contrib.coap import *


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
            'header': {
                'msg_len': len(mqtt_packet),
                'dup': int(mqtt_packet.DUP),
                'qos': int(mqtt_packet.QOS),
                'retain': int(mqtt_packet.RETAIN),
            },
            'type': packet_type,
        })

        if packet_type == 'CONNECT':
            self.packet_info['connect'] = {
                'proto_name': str(mqtt_packet.protoname),
                'mqtt_level': str(PROTOCOL_LEVEL.get(mqtt_packet.protolevel, "Unknown")),
                'usernameflag': int(mqtt_packet.usernameflag),
                'passwordflag': int(mqtt_packet.passwordflag),
                'willretainflag': int(mqtt_packet.willretainflag),
                'willQOSflag': int(mqtt_packet.willQOSflag),
                'willflag': int(mqtt_packet.willflag),
                'cleansession': int(mqtt_packet.cleansess),
                'reserved': int(mqtt_packet.reserved),
                'keep_alive': int(mqtt_packet.klive),
                'clientId': str(mqtt_packet.clientId),
            }
            if mqtt_packet.willflag:
                self.packet_info['connect']['willtopic'] = str(
                    mqtt_packet.willtopic)
                self.packet_info['connect']['willmsg'] = str(
                    mqtt_packet.willmsg)
            if mqtt_packet.usernameflag:
                self.packet_info['connect']['username'] = str(
                    mqtt_packet.username)
            if mqtt_packet.passwordflag:
                self.packet_info['connect']['password'] = str(
                    mqtt_packet.password)

        elif packet_type == 'CONNACK':
            self.packet_info['connack'] = {
                'ackflag': int(mqtt_packet.sessPresentFlag),
                'return_code': str(mqtt_packet.retcode),
            }

        elif packet_type == 'PUBLISH':
            self.packet_info['publish'] = {
                'topic': str(mqtt_packet.topic),
                'msgid': str(mqtt_packet.msgid),
                'msgvalue': str(mqtt_packet.value),
            }

        elif packet_type == 'PUBACK':
            self.packet_info['puback'] = {
                'msgid': str(mqtt_packet.msgid),
            }

        elif packet_type == 'PUBREC':
            self.packet_info['pubrec'] = {
                'msgid': str(mqtt_packet.msgid),
            }

        elif packet_type == 'PUBREL':
            self.packet_info['pubrel'] = {
                'msgid': str(mqtt_packet.msgid),
            }

        elif packet_type == 'PUBCOMP':
            self.packet_info['pubcomp'] = {
                'msgid': str(mqtt_packet.msgid),
            }

        return self.packet_info


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

        # Extracting options if they exist
        if coap_packet.options:
            self.packet_info['options'] = []
            for option in coap_packet.options:
                try:
                    option_number, option_value = option  # Unpacking the tuple

                    # Check if the option is Content-Format and map its numeric value to a string
                    if option_number == 12:  # Content-Format option number is 12
                        option_value = self.CONTENT_FORMATS.get(option_value, "Unknown")
                    elif isinstance(option_value, bytes):
                        option_value = option_value.decode('utf-8', errors='ignore')

                    self.packet_info['options'].append({
                        'number': option_number,
                        'value': option_value
                    })
                except Exception as e:
                    self.packet_info['options'].append({
                        'number': None,
                        'value': f"Error decoding option: {e}"
                    })
        # if coap_packet.options:
        #     self.packet_info['options'] = []
        #     for opt in coap_packet.options:
        #         try:
        #             if len(opt) >= 2:
        #                 option_number, option_value = opt[0], opt[1]
        #                 # Check if the option is Content-Format and map its numeric value to a string
        #                 print(f"option numebr is {option_number}")
        #                 if option_number == 'Content-Format':  # Content-Format option number
        #                     option_value = self.CONTENT_FORMATS.get(
        #                         option_value, "Text")
        #                 elif isinstance(option_value, bytes):
        #                     option_value = option_value.decode(
        #                         'utf-8', errors='ignore')

        #                 self.packet_info['options'].append({
        #                     'number': option_number,
        #                     'value': option_value
        #                 })
        #             else:
        #                 self.packet_info['options'].append({
        #                     'number': None,
        #                     'value': "Malformed option"
        #                 })
        #         except Exception as e:
        #             self.packet_info['options'].append({
        #                 'number': None,
        #                 'value': f"Error decoding option: {e}"
        #             })

        # Extracting payload if it exists
        if hasattr(coap_packet, 'payload') and coap_packet.payload:
            try:
                self.packet_info['payload'] = bytes(
                    coap_packet.payload).decode('utf-8', errors='ignore')
            except Exception as e:
                self.packet_info['payload'] = f"Cannot decode payload: {e}"
        else:
            self.packet_info['payload'] = "None"

        return self.packet_info
