# mqtt_sniffer.py
from scapy.all import *
from mqtt_packet import MQTTPacket, decode_remaining_length
import json

# 패킷 캡처 콜백 함수
def mqtt_packet_callback(packet, websocket):
    if TCP in packet and Raw in packet:
        payload = packet[Raw].load
        if len(payload) >= 2:
            mqtt_type = orb(payload[0]) >> 4
            if 1 <= mqtt_type <= 14:
                remaining_length = decode_remaining_length(payload)
                if len(payload) == remaining_length + 2:
                    mqtt_packet = MQTTPacket(payload)
                    if mqtt_packet.length == len(mqtt_packet.data):
                        packet_info = {
                            'type': mqtt_packet.type,
                            'flags': mqtt_packet.flags,
                            'length': mqtt_packet.length,
                            'data': mqtt_packet.data.decode('utf-8')
                        }
                        # MQTT 패킷 정보를 JSON 형식으로 변환하여 프론트엔드로 전송
                        asyncio.create_task(websocket.send(json.dumps(packet_info)))
                        
                        # MQTT 패킷 정보를 CLI에 출력
                        print("MQTT Packet Detected:")
                        print(f"Type: {mqtt_packet.type}")
                        print(f"Flags: {mqtt_packet.flags}")
                        print(f"Length: {mqtt_packet.length}")
                        print(f"Data: {mqtt_packet.data.decode('utf-8')}")
                        print("--------------------")

# 패킷 스니핑 시작
def start_mqtt_sniffer(websocket):
    sniff(prn=lambda packet: mqtt_packet_callback(packet, websocket), store=0)