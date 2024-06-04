from abc import ABC, abstractmethod


class ProtocolFields(ABC):
    COMMON_FIELDS = []
    LAYER_NAME = None

    @classmethod
    @abstractmethod
    def get_fields(cls):
        pass


class EthernetFields(ProtocolFields):
    COMMON_FIELDS = [
        ('dst', 48),
        ('src', 48),
        ('type', 16),
    ]
    LAYER_NAME = 'ETH'

    @classmethod
    def get_fields(cls):
        return cls.COMMON_FIELDS


class IpFields(ProtocolFields):
    COMMON_FIELDS = [
        ('version', 4),
        ('ihl', 4),
        ('tos', 8),
        ('len', 16),
        ('id', 16),
        ('flags', 3),
        ('frag_offset', 13),
        ('ttl', 8),
        ('protocol', 8),
        ('checksum', 16),
        ('src', 32),
        ('dst', 32),
    ]
    LAYER_NAME = 'IP'

    @classmethod
    def get_fields(cls):
        return cls.COMMON_FIELDS


class TcpFields(ProtocolFields):
    COMMON_FIELDS = [
        ('src_port', 16),
        ('dst_port', 16),
        ('seq_num', 32),
        ('ack_num', 32),
        ('data_offset', 4),
        ('reserved', 3),
        ('flags', 9),
        ('window', 16),
        ('checksum', 16),
        ('urgent_pointer', 16),
    ]
    LAYER_NAME = 'TCP'

    @classmethod
    def get_fields(cls):
        return cls.COMMON_FIELDS


class MqttFields(ProtocolFields):
    COMMON_FIELDS = [
        ('msgtype', 4),
        ('dupflag', 1),
        ('qos', 1),
        ('retain', 1),
        ('len', '~'),
    ]
    LAYER_NAME = 'MQTT'

    SPECIFIC_FIELDS = {
        "CONNECT": [
            ('proto_len', 16),
            ('protoname', 8),
            ('conflag_uname', 1),
            ('conflag_passwd', 1),
            ('conflag_qos', 1),
            ('conflag_willflag', 1),
            ('conflag_cleansess', 1),
            ('conflag_reserved', 1),
            ('kalive', 16),
            ('clientid_len', 16),
            ('clientid', '~'),
            ('willtopic_len', '~'),
            ('willtopic', '~'),
            ('willmsg_len', '~'),
            ('willmsg', '~'),
            ('username_len', '~'),
            ('username', '~'),
            ('passwd_len', '~'),
            ('passwd', '~'),
        ],
        "CONNACK": [
            ('conack_flags', 8),
            ('connack_reason_code', 8),
        ],
        "SUBSCRIBE": [
            ('msgid', 16),
            ('topic_len', 16),
            ('topic', '~'),
            ('sub_qos', 8),
        ],
        "SUBACK": [
            ('msgid', 16),
            ('suback_qos', 8),
        ],
        "UNSUBSCRIBE": [
            ('msgid', 16),
            ('topic_len', 16),
            ('topic', '~'),
        ],
        "PUBLISH": [
            ('topic_len', 16),
            ('topic', '~'),
            ('msgid', 16),
            ('msg', '~'),
        ],
        "PUBACK": [
            ('msgid', 16),
        ],
        "PUBREL": [
            ('msgid', 16),
        ],
        "PUBREC": [
            ('msgid', 16),
        ],
        "PUBCOMP": [
            ('msgid', 16),
        ],
        "UNSUBACK": [
            ('msgid', 16),
        ],
    }

    MQTT_MESSAGE_TYPES = {
        1: "CONNECT",
        2: "CONNACK",
        3: "PUBLISH",
        4: "PUBACK",
        5: "PUBREC",
        6: "PUBREL",
        7: "PUBCOMP",
        8: "SUBSCRIBE",
        9: "SUBACK",
        10: "UNSUBSCRIBE",
        11: "UNSUBACK",
        12: "PINGREQ",
        13: "PINGRESP",
        14: "DISCONNECT",
        15: "AUTH"
    }

    @classmethod
    def get_fields(cls, message_type):
        if isinstance(message_type, int):
            message_type = cls.MQTT_MESSAGE_TYPES.get(message_type, "UNKNOWN")
        return cls.COMMON_FIELDS + cls.SPECIFIC_FIELDS.get(message_type, [])


class CoapFields(ProtocolFields):
    COMMON_FIELDS = [
        ('version', 2),
        ('type', 2),
        ('token_length', 4),
        ('code', 8),
        ('message_id', 16),
        ('token', '~'),
    ]
    LAYER_NAME = 'COAP'

    @classmethod
    def get_fields(cls):
        return cls.COMMON_FIELDS


PROTOCOL_FIELDS_CLASSES = {
    'ETH': EthernetFields,
    'IP': IpFields,
    'TCP': TcpFields,
    'MQTT': MqttFields,
    'COAP': CoapFields,
}
