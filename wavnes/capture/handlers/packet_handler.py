from abc import ABC, abstractmethod


class PacketHandler(ABC):
    @abstractmethod
    def process_packet(self, packet):
        pass
