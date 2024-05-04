import json
import asyncio
from scapy.all import *
from scapy.contrib.mqtt import *

start_time = None
previous_timestamp = None


def _packet_callback(packet, websocket, loop):
   global start_time, previous_timestamp

   if MQTT in packet:
       mqtt_packet = packet[MQTT]

       # 캡처 시작 시간 설정
       if start_time is None:
           start_time = packet.time

       # 이전 패킷과의 시간 간격 계산
       if previous_timestamp is None:
           seconds_since_previous = 0.0
       else:
           seconds_since_previous = float(packet.time - previous_timestamp)

       packet_info = {
           'protocol': 'MQTT',
           'timestamp': '{:.6f}'.format(packet.time),
           'time_of_day': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time)),
           'seconds_since_beginning': '{:.6f}'.format(float(packet.time - start_time)),
           'seconds_since_previous': '{:.6f}'.format(seconds_since_previous),
           'source_ip': str(packet[IP].src),
           'destination_ip': str(packet[IP].dst),
           'source_port': int(packet[TCP].sport),
           'destination_port': int(packet[TCP].dport),
           'type': str(type(mqtt_packet).__name__),
           'qos': int(mqtt_packet.QOS),
           'length': int(mqtt_packet.len)
       }

       if hasattr(mqtt_packet, 'flags'):
           packet_info['flags'] = int(mqtt_packet.flags)

       if hasattr(mqtt_packet, 'topic'):
           packet_info['topic'] = str(mqtt_packet.topic)

       if hasattr(mqtt_packet, 'value'):
           packet_info['value'] = mqtt_packet.value.decode('utf-8')

       # 이전 패킷의 타임스탬프 업데이트
       previous_timestamp = packet.time

       # packet_info 딕셔너리 내용 출력
       # print("Captured MQTT Packet:")
       # for key, value in packet_info.items():
       #     print(f"{key}: {value}")

       # MQTT 패킷 정보를 JSON 형식으로 변환하여 저장
       json_data = json.dumps(packet_info)

       # 웹소켓으로 패킷 정보 전송 (메인 스레드의 이벤트 루프에서 실행)
       asyncio.run_coroutine_threadsafe(websocket.send(json_data), loop)


# 패킷 스니핑 시작
async def start_mqtt_sniffer(websocket):
   loop = asyncio.get_running_loop()
   await asyncio.to_thread(sniff, prn=lambda packet: _packet_callback(packet, websocket, loop), store=0)
