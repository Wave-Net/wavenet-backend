import os
import json
import pyshark


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
