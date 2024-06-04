import os
from wavnes.utils import get_network_default_interface

DEFAULT_NETWORK_INTERFACE = get_network_default_interface()

DEFAULT_SERVER_PORT = 8000

DEFAULT_PCAP_DIRECTORY = os.path.abspath("./pcap")

DEFAULT_CSV_DIRECTORY = os.path.abspath("./csv")

DEFAULT_JSON_DIRECTORY = os.path.abspath("./json")

try:
    from settings import NETWORK_INTERFACE
except ImportError:
    NETWORK_INTERFACE = DEFAULT_NETWORK_INTERFACE

try:
    from settings import SERVER_PORT
except ImportError:
    SERVER_PORT = DEFAULT_SERVER_PORT

try:
    from settings import PCAP_DIRECTORY
    PCAP_DIRECTORY = os.path.abspath(PCAP_DIRECTORY)
except ImportError:
    PCAP_DIRECTORY = DEFAULT_PCAP_DIRECTORY

try:
    from settings import CSV_DIRECTORY
    CSV_DIRECTORY = os.path.abspath(CSV_DIRECTORY)
except ImportError:
    CSV_DIRECTORY = DEFAULT_CSV_DIRECTORY

try:
    from settings import JSON_DIRECTORY
    JSON_DIRECTORY = os.path.abspath(JSON_DIRECTORY)
except ImportError:
    JSON_DIRECTORY = DEFAULT_JSON_DIRECTORY
