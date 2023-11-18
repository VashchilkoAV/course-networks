import socket
import os
import math


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
    

GLOBAL_PACKET_LEN = 10000
GLOBAL_N_REPEAT = 10

class Packet:
    TYPE_LEN = 2
    ID_LEN = 10
    PART_NUM_LEN = 2
    NUM_PARTS_LEN = 2
    PACKET_LEN = GLOBAL_PACKET_LEN
    DATA_LEN = PACKET_LEN - ID_LEN - PART_NUM_LEN - NUM_PARTS_LEN

    def __init__(self, data: bytes, send=True):
        self.current_part = 0
        if send == True:
            self.id = os.urandom(self.ID_LEN)
            self.num_parts = math.ceil(len(data) / self.DATA_LEN)
            self.data = [data[i * self.DATA_LEN: (i + 1) * self.DATA_LEN] for i in range(self.num_parts)]
        else:
            self.id = data[:self.ID_LEN]
            self.num_parts = int.from_bytes(data[self.ID_LEN: self.ID_LEN + self.NUM_PARTS_LEN], 'big')
            current_part = int.from_bytes(data[self.ID_LEN + self.NUM_PARTS_LEN: self.ID_LEN + self.NUM_PARTS_LEN + self.PART_NUM_LEN], 'big')
            self.data = [None] * self.num_parts
            self.data[current_part] = data[self.ID_LEN + self.NUM_PARTS_LEN + self.PART_NUM_LEN:]


    def __str__(self):
        return f"id={self.id}, num_parts={self.num_parts}, data={self.data}"
    
    def __iter__(self):
        return self
    
    def is_full(self):
        return all(self.data)

    def __next__(self):
        if self.current_part < self.num_parts:
            result = b''.join([
                self.id,
                self.num_parts.to_bytes(self.NUM_PARTS_LEN, 'big'),
                self.current_part.to_bytes(self.PART_NUM_LEN, 'big'),
                self.data[self.current_part]
                ])
            self.current_part += 1
            
            return result
        else:
            self.current_part = 0
            raise StopIteration
        
    def to_bytes(self):
        if self.is_full():
            return b''.join(self.data)
        else:
            raise ValueError("It is not permitted to call to_bytes() method when packet is not full\n")
        
    def extend_from_bytes(self, data: bytes):
        id = data[:self.ID_LEN]
        num_parts = int.from_bytes(data[self.ID_LEN: self.ID_LEN + self.NUM_PARTS_LEN], 'big')
        current_part = int.from_bytes(data[self.ID_LEN + self.NUM_PARTS_LEN: self.ID_LEN + self.NUM_PARTS_LEN + self.PART_NUM_LEN], 'big')
        if id == self.id and self.data[current_part] is None:
            self.data[current_part] = data[self.ID_LEN + self.NUM_PARTS_LEN + self.PART_NUM_LEN:]
            return True
        else:
            return False


class MyTCPProtocol(UDPBasedProtocol):
    N_REPEAT = GLOBAL_N_REPEAT


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seen_ids = set()

    def send(self, data: bytes):
        packet = Packet(data)
        for packet_part in packet:
            for _ in range(self.N_REPEAT):
                assert self.sendto(packet_part) == len(packet_part)

        return len(data)

    def recv(self, n: int):
        # return os.urandom(10)
        while True:
            packet_bytes = self.recvfrom(GLOBAL_PACKET_LEN)
            packet = Packet(packet_bytes, send=False)
            
            if packet.id not in self.seen_ids:
                self.seen_ids.add(packet.id)
                while not packet.is_full():
                    packet_bytes = self.recvfrom(GLOBAL_PACKET_LEN)
                    packet.extend_from_bytes(packet_bytes)
                    
                return packet.to_bytes()
                

if __name__ == "__main__":
    print(Packet.from_bytes(Packet(b'haha').to_bytes()).get_data())