import os
from wavnes.utils import get_network_interface

PCAP_DIRECTORY = os.path.abspath("./wavnes/pcap")
CSV_DIRECTORY = os.path.abspath("./wavnes/csv")
JSON_DIRECTORY = os.path.abspath("./wavnes/json")
NETWORK_INTERFACE = get_network_interface()
SERVER_PORT = 8000
