import os
import json
import pyshark
from wavnes.protocol_fields import PROTOCOL_FIELDS_CLASSES


def device_ip_to_file_path(directory: str, device_ip: str, file_type: str):
    sanitized_ip = device_ip.replace('.', '_')
    full_path = os.path.join(directory, f"{sanitized_ip}.{file_type}")
    return full_path


def make_csv_from_pcap(pcap_path, csv_path):
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


def format_field_value(layer, field):
    try:
        field_value = layer.get_field(field).showname_value
    except AttributeError:
        try:
            field_value = getattr(layer, field)
        except AttributeError:
            raise AttributeError
    return str(field_value)


def field_to_dict(layer, field_name, field_length):
    try:
        value = format_field_value(layer, field_name)
    except AttributeError:
        raise AttributeError

    field_obj = layer.get_field(field_name)
    raw_bytes = field_obj.raw_value if field_obj else ''
    spaced_raw_bytes = ' '.join(
        [raw_bytes[i:i+2] for i in range(0, len(raw_bytes), 2)]) if raw_bytes else ''
    ascii_representation = ''.join([chr(int(raw_bytes[i:i+2], 16)) if 32 <= int(
        raw_bytes[i:i+2], 16) <= 126 else '.' for i in range(0, len(raw_bytes), 2)]) if raw_bytes else ''

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
        try:
            fields = get_included_fields(layer)
        except KeyError:
            continue
        layer_dict = {}
        for field_name, field_length in fields:
            try:
                field_dict = field_to_dict(layer, field_name, field_length)
            except AttributeError:
                continue
            layer_dict[field_name] = field_dict
        pkt_dict[layer_name] = layer_dict

    return pkt_dict
