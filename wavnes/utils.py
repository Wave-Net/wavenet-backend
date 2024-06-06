import os
import json
import pyshark
import platform
import subprocess
import socket
import netifaces
from mac_vendor_lookup import AsyncMacLookup
from wavnes.protocol_fields import PROTOCOL_FIELDS_CLASSES
from wavnes.logging_config import logger


def get_network_default_interface():
    os_name = platform.system()

    if os_name == "Darwin":  # Mac OS
        return "en0"
    elif os_name == "Windows":  # Windows
        return "Ethernet"
    elif os_name == "Linux":  # Linux
        return "eth0"
    elif os_name in ["FreeBSD", "OpenBSD", "NetBSD"]:  # BSD 계열 Unix
        return "re0"
    elif os_name in ["SunOS", "Solaris"]:  # Sun/Oracle Unix
        return "e1000g0"
    elif os_name == "AIX":  # IBM AIX Unix
        return "en0"
    else:
        return "eth0"  # Default value


def device_ip_to_file_path(directory: str, device_ip: str, file_type: str):
    sanitized_ip = device_ip.replace('.', '_')
    full_path = os.path.join(directory, f"{sanitized_ip}.{file_type}")
    return full_path


def make_csv_from_pcap(pcap_path, csv_path):
    csv_dir = os.path.dirname(csv_path)
    os.makedirs(csv_dir, exist_ok=True)

    cap = pyshark.FileCapture(pcap_path)

    with open(csv_path, 'w') as f:
        packet = cap[0]
        fieldnames = []
        for layer in packet.layers:
            fieldnames.extend(layer.field_names)
        header = ','.join(fieldnames)
        f.write(header + '\n')

        for packet in cap:
            row = []
            for layer in packet.layers:
                row.extend([getattr(layer, field, '')
                           for field in layer.field_names])
            f.write(','.join(row) + '\n')


def make_json_from_pcap(pcap_path, json_path):
    json_dir = os.path.dirname(json_path)
    os.makedirs(json_dir, exist_ok=True)

    cap = pyshark.FileCapture(pcap_path)
    packets = []

    for packet in cap:
        packet_dict = {}
        for layer in packet.layers:
            layer_dict = {}
            for field in layer.field_names:
                layer_dict[field] = getattr(layer, field, '')
            packet_dict[layer.layer_name] = layer_dict
        packets.append(packet_dict)

    with open(json_path, 'w') as f:
        json.dump(packets, f, indent=4)


def field_to_dict(layer, field_name, field_length):
    try:
        field_obj = layer.get_field(field_name)
    except:
        return None

    value = field_obj.showname_value
    raw_bytes = field_obj.raw_value

    spaced_raw_bytes = ' '.join(
        [raw_bytes[i:i+2] for i in range(0, len(raw_bytes), 2)])
    ascii_representation = ''.join([chr(int(raw_bytes[i:i+2], 16)) if 32 <= int(
        raw_bytes[i:i+2], 16) <= 126 else '.' for i in range(0, len(raw_bytes), 2)])
    field_length = len(raw_bytes) * 4 if field_length == '~' else field_length

    return {
        'value': value,
        'raw_bytes': spaced_raw_bytes,
        'ascii': ascii_representation,
        'field_length': field_length,
    }


def get_included_fields(layer):
    layer_name = layer.layer_name.upper()
    protocol_class = PROTOCOL_FIELDS_CLASSES.get(layer_name)

    if not protocol_class:
        raise KeyError(
            "Protocol class not found for layer: {}".format(layer_name))

    if layer_name == 'MQTT':
        message_type = int(layer.msgtype)
        fields = protocol_class.get_fields(message_type)
    else:
        fields = protocol_class.get_fields()

    return fields


def packet_to_dict(packet):
    pkt_dict = {}

    for layer in packet.layers:
        layer_name = layer.layer_name.upper()
        if layer_name == 'MQTT':
            layers_to_process = packet.get_multiple_layers('mqtt')
        else:
            layers_to_process = [layer]

        for i, current_layer in enumerate(layers_to_process):
            try:
                fields = get_included_fields(current_layer)
            except:
                continue
            layer_dict = {}
            for field_name, field_length in fields:
                try:
                    field_dict = field_to_dict(
                        current_layer, field_name, field_length)
                except:
                    continue
                layer_dict[field_name] = field_dict

            if layer_name == 'MQTT':
                pkt_dict[f'{layer_name}{i + 1}'] = layer_dict
            else:
                pkt_dict[layer_name] = layer_dict

    return pkt_dict


def make_packet_info(time_info, packet):
    iot_protocol = ''
    summary = ''
    if 'mqtt' in packet:
        iot_protocol = 'MQTT'
        summary = packet.mqtt.msgtype.showname_value
    elif 'coap' in packet:
        iot_protocol = 'CoAP'
        summary = packet.coap.code.showname_value

    packet_info = {'type': 'packet',
                   'data': {'info': {},
                            'layers': {}}
                   }
    time_info.update(packet)
    packet_info['data']['info'].update(time_info.get_time_info())
    packet_info['data']['info'].update({'src': packet.ip.src})
    packet_info['data']['info'].update({'dst': packet.ip.dst})
    packet_info['data']['info'].update({'len': len(packet)})
    packet_info['data']['info'].update({'protocol': iot_protocol})
    packet_info['data']['info'].update({'summary': summary})

    packet_info['data']['layers'].update(packet_to_dict(packet))

    return packet_info

def get_mac_address(ip):
    interfaces = netifaces.interfaces()
    for interface in interfaces:
        addr = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addr:
            ip_addresses = [ip_addr['addr'] for ip_addr in addr[netifaces.AF_INET]]
            if ip in ip_addresses:
                mac_address = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
                logger.info(f"MAC address of {ip} on interface {interface}: {mac_address}")
                return mac_address

    # IP address not found
    logger.warning(f"Could not find MAC address for IP {ip}")
    return 'Unknown'

def get_mac_by_ip(ip):
    try:
        system = platform.system()
        logger.info(f"현재 운영 체제: {system}")
        if system == 'Windows':
            cmd = f"arp -a {ip}"
            output = subprocess.check_output(cmd, shell=True).decode()
            logger.info(f"Windows 명령어 출력: {output}")
            lines = output.split('\n')
            for line in lines:
                logger.info(f"Windows 줄: {line}")
                if ip in line:
                    parts = line.split()
                    logger.info(f"Windows parts: {parts}")
                    if len(parts) > 1:
                        mac = parts[1]
                        logger.info(f"Windows에서 {ip}의 MAC 주소: {mac}")
                        return mac
            return 'Unknown'
        elif system == 'Linux':
            cmd = f"sudo ip neigh show {ip}"
            output = subprocess.check_output(cmd, shell=True).decode().strip()
            logger.info(f"Linux 명령어 출력: {output}")
            lines = output.split('\n')
            for line in lines:
                logger.info(f"Linux 줄: {line}")
                if ip in line:
                    parts = line.split()
                    logger.info(f"Linux parts: {parts}")
                    if len(parts) > 4:
                        mac = parts[4]
                        logger.info(f"Linux에서 {ip}의 MAC 주소: {mac}")
                        return mac
            return 'Unknown'
        elif system == 'Darwin':
            cmd = f"arp {ip}"
            output = subprocess.check_output(cmd, shell=True).decode()
            logger.info(f"macOS 명령어 출력: {output}")
            lines = output.split('\n')
            for line in lines:
                logger.info(f"macOS 줄: {line}")
                if ip in line:
                    parts = line.split()
                    logger.info(f"macOS parts: {parts}")
                    if len(parts) > 3:
                        mac = parts[3]
                        logger.info(f"macOS에서 {ip}의 MAC 주소: {mac}")
                        return mac
            return 'Unknown'
        else:
            logger.error(f"지원되지 않는 운영 체제: {system}")
            return 'Unknown'
    except:
        logger.error(f"{ip}의 MAC 주소를 가져오는 중 오류 발생: ")
        return 'Unknown'


def get_hostname_by_ip(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        logger.debug(f"Hostname for {ip}: {hostname}")
        return hostname
    except socket.herror as e:
        # logger.error(f"Error getting hostname for {ip}: {str(e)}")
        return 'Unknown'
    except Exception as e:
        # logger.error(f"Error getting hostname for {ip}: {str(e)}")
        return 'Unknown'


async def get_vendor_by_mac(mac):
    try:
        vendor = await AsyncMacLookup().lookup(mac)
        logger.debug(f"Vendor for {mac}: {vendor}")
        return vendor
    except Exception as e:
        logger.error(f"Error getting vendor for {mac}: {str(e)}")
        return 'Unknown'
