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
        ('hdr_len', 4),
        ('dsfield', 8),
        ('len', 16),
        ('id', 16),
        ('flags', 3),
        ('frag_offset', 13),
        ('ttl', 8),
        ('proto', 8),
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
        ('srcport', 16),
        ('dstport', 16),
        ('seq', 32),
        ('ack', 32),
        ('hdr_len', 4),
        ('flags', 12),
        ('window_size_value', 16),
        ('checksum', 16),
        ('urgent_pointer', 16),
        ('options', '~'),
    ]
    LAYER_NAME = 'TCP'

    @classmethod
    def get_fields(cls):
        return cls.COMMON_FIELDS


class UdpFields(ProtocolFields):
    COMMON_FIELDS = [
        ('srcport', 16),
        ('dstport', 16),
        ('length', 16),
        ('checksum', 16),
    ]
    LAYER_NAME = 'UDP'

    @classmethod
    def get_fields(cls):
        return cls.COMMON_FIELDS


class MqttFields(ProtocolFields):
    COMMON_FIELDS = [
        ('hdrflags', 8),
        ('len', '~'),
    ]
    LAYER_NAME = 'MQTT'

    SPECIFIC_FIELDS = {
        "CONNECT": [
            ('proto_len', 16),
            ('protoname', '~'),
            ('ver', 8),
            ('conflag_uname', 1),
            ('conflag_passwd', 1),
            ('conflag_retain', 1),
            ('conflag_qos', 2),
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
            ('conack_val', 8),
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
        ('token_len', 4),
        ('code', 8),
        ('mid', 16),
        ('token', '~'),
        ('opt_name', '~'),
    ]
    LAYER_NAME = 'COAP'

    @classmethod
    def get_fields(cls):
        return cls.COMMON_FIELDS


PROTOCOL_FIELDS_CLASSES = {
    'ETH': EthernetFields,
    'IP': IpFields,
    'TCP': TcpFields,
    'UDP': UdpFields,
    'MQTT': MqttFields,
    'COAP': CoapFields,
}
