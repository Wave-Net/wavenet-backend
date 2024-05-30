import os
import pyshark

def device_ip_to_file_path(directory: str, device_ip: str, file_type: str):
    sanitized_ip = device_ip.replace('.', '_')
    full_path = os.path.join(directory, f"{sanitized_ip}.{file_type}")
    return full_path

def make_csv_from_pcap(pcap_path: str, csv_path: str):
    cap = pyshark.FileCapture(pcap_path)
    with open(csv_path, 'w', newline='') as csvfile:
        header = ','.join(cap[0].fieldnames)
        csvfile.write(header + '\n')
        for packet in cap:
            row = ','.join([str(packet.get(field, ''))
                           for field in cap[0].fieldnames])
            csvfile.write(row + '\n')
