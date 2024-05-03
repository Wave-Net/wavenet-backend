from scapy.all import *

# MQTT 패킷 정의
class MQTTPacket(Packet):
    name = "MQTT"
    fields_desc = [
        BitField("type", 0, 4),
        BitField("flags", 0, 4),
        FieldLenField("length", None, length_of="data", fmt="B"),
        StrLenField("data", "", length_from=lambda pkt: pkt.length)
    ]

# 남은 길이 디코딩 함수
def decode_remaining_length(packet):
    remaining_length = 0
    multiplier = 1
    for i in range(1, len(packet)):
        byte = orb(packet[i])
        remaining_length += (byte & 127) * multiplier
        multiplier *= 128
        if byte & 128 == 0:
            break
    return remaining_length