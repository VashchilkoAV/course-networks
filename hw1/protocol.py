import socket
import os


class UDPBasedProtocol:
    def __init__(self, *, local_addr, remote_addr):
        self.udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.remote_addr = remote_addr
        self.udp_socket.bind(local_addr)

    def sendto(self, data):
        return self.udp_socket.sendto(data, self.remote_addr)

    def recvfrom(self, n):
        msg, addr = self.udp_socket.recvfrom(n)
        return msg
    


class Packet:
    ID_LEN = 10

    def __init__(self, data: bytes):
        self.data = data
        self.id = os.urandom(self.ID_LEN)
        self.packet = bytearray()
        self.packet.extend(self.id)
        self.packet.extend(data)

    def to_bytes(self):
        return self.packet
    
    def get_data(self):
        return self.data
    
    @classmethod
    def from_bytes(cls, data: bytes):
        packet = Packet(b'')
        packet.id = data[:packet.ID_LEN]
        packet.data = data[packet.ID_LEN:]

        return packet


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seen_ids = set()

    def send(self, data: bytes):
        packet = Packet(data)
        packet_bytes = packet.to_bytes()
        packet_len = len(packet_bytes)
        for _ in range(5):
            sent_len = self.sendto(packet_bytes)
        assert sent_len == packet_len

        return len(data)

    def recv(self, n: int):
        while True:
            packet_bytes = self.recvfrom(4096)
            packet = Packet.from_bytes(packet_bytes)
            if packet.id not in self.seen_ids:
                self.seen_ids.add(packet.id)

                return packet.get_data()#[:n]


if __name__ == "__main__":
    print(Packet.from_bytes(Packet(b'haha').to_bytes()).get_data())