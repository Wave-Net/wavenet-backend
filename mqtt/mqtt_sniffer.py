# mqtt_sniffer.py
from scapy.all import *
from mqtt_packet import MQTTPacket, decode_remaining_length
import json
import asyncio

# 패킷 캡처 콜백 함수
def mqtt_packet_callback(packet, websocket, loop):
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
                        # MQTT 패킷 정보를 JSON 형식으로 변환하여 저장
                        json_data = json.dumps(packet_info)
                        
                        # MQTT 패킷 정보를 CLI에 출력
                        print("MQTT Packet Detected:")
                        print(f"Type: {mqtt_packet.type}")
                        print(f"Flags: {mqtt_packet.flags}")
                        print(f"Length: {mqtt_packet.length}")
                        print(f"Data: {mqtt_packet.data.decode('utf-8')}")
                        print("--------------------")
                        
                        # 웹소켓으로 패킷 정보 전송 (메인 스레드의 이벤트 루프에서 실행)
                        asyncio.run_coroutine_threadsafe(websocket.send(json_data), loop)

# 패킷 스니핑 시작
async def start_mqtt_sniffer(websocket):
    loop = asyncio.get_running_loop()
    await asyncio.to_thread(sniff, prn=lambda packet: mqtt_packet_callback(packet, websocket, loop), store=0)