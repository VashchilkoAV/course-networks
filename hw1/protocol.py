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
    

GLOBAL_PACKET_LEN = 4096
GLOBAL_N_REPEAT = 10

class Packet:
    # 2 bytes -- TYPE, 10 bytes -- ID, 2 bytes -- NUM_PARTS, 2 bytes -- PART_NUM
    TYPE_LEN = 2
    ID_LEN = 10
    PART_NUM_LEN = 2
    NUM_PARTS_LEN = 2
    PACKET_LEN = GLOBAL_PACKET_LEN
    DATA_LEN = PACKET_LEN - ID_LEN - PART_NUM_LEN - NUM_PARTS_LEN - TYPE_LEN

    def __init__(self, data: bytes, type=0):
        self.current_part = 0
        if type == 0:
            self.type = b'DT'
            self.id = os.urandom(self.ID_LEN)
            self.num_parts = math.ceil(len(data) / self.DATA_LEN)
            self.data = [data[i * self.DATA_LEN: (i + 1) * self.DATA_LEN] for i in range(self.num_parts)]
        elif type == 1:
            self.type = b'DT'
            self.id = data[self.TYPE_LEN : self.TYPE_LEN + self.ID_LEN]
            self.num_parts = int.from_bytes(data[self.TYPE_LEN + self.ID_LEN: self.TYPE_LEN + self.ID_LEN + self.NUM_PARTS_LEN], 'big')
            current_part = int.from_bytes(data[self.TYPE_LEN + self.ID_LEN + self.NUM_PARTS_LEN: self.TYPE_LEN + self.ID_LEN + self.NUM_PARTS_LEN + self.PART_NUM_LEN], 'big')
            self.data = [None] * self.num_parts
            self.data[current_part] = data[self.TYPE_LEN + self.ID_LEN + self.NUM_PARTS_LEN + self.PART_NUM_LEN:]
        elif type == 3:
            self.type = b'RE'
            self.id = os.urandom(self.ID_LEN)
            self.num_parts = 1
            self.current_part = 0
            self.data = [data]
        else:
            pass

    def __str__(self):
        return f"id={self.id}, num_parts={self.num_parts}, data={self.data}"
    
    def __iter__(self):
        return self
    
    def is_full(self):
        return all(self.data)

    def __next__(self):
        if self.current_part < self.num_parts:
            result = b''.join([
                self.type,
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
        id = data[self.TYPE_LEN: self.TYPE_LEN + self.ID_LEN]
        num_parts = int.from_bytes(data[self.TYPE_LEN + self.ID_LEN: self.TYPE_LEN + self.ID_LEN + self.NUM_PARTS_LEN], 'big')
        current_part = int.from_bytes(data[self.TYPE_LEN + self.ID_LEN + self.NUM_PARTS_LEN: self.TYPE_LEN + self.ID_LEN + self.NUM_PARTS_LEN + self.PART_NUM_LEN], 'big')
        if id == self.id and self.data[current_part] is None:
            self.data[current_part] = data[self.TYPE_LEN + self.ID_LEN + self.NUM_PARTS_LEN + self.PART_NUM_LEN:]
            return True
        else:
            return False


class TCPPacket():
    TYPE_LEN = 1
    ID_LEN = 3
    LEN = GLOBAL_PACKET_LEN
    DATA_LEN = LEN - TYPE_LEN - ID_LEN

    def __init__(self, type, data=None, id=None):
        self.id = os.urandom(self.ID_LEN) if id is None else id
        self.data = b'' if data is None else data
        self.type = type


    def __str__(self):
        return f"TYPE={self.type}, ID={self.id}, DATA={self.data}"


    def to_bytes(self):
        return b''.join([
            self.type,
            self.id,
            self.data,
        ])
    

    @classmethod
    def from_bytes(cls, data):
        return cls(
            type=data[:cls.TYPE_LEN],
            id=data[cls.TYPE_LEN: cls.TYPE_LEN + cls.ID_LEN],
            data=data[cls.TYPE_LEN + cls.ID_LEN:]
        )
    
    @classmethod
    def divide(cls, data):
        n_parts = math.ceil(len(data) / cls.DATA_LEN)
        ret = []
        for i in range(n_parts):
            ret.append(cls(b'D', data[i * cls.DATA_LEN: (i + 1) * cls.DATA_LEN]))

        ret.append(cls(b'F'))
        return ret


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.udp_socket.settimeout(0.005)
        self.seen_ids = set()

    def send(self, data: bytes):
        packets = TCPPacket.divide(data)
        for packet in packets:
            not_received = True
            packet_bytes = packet.to_bytes()
            while not_received:
                not_received = False
                try:
                    print(f'[SENDER]: sending {packet}')
                    assert self.sendto(packet_bytes) == len(packet_bytes)
                    print(f'[SENDER]: {packet} sent, trying to receive ACK')
                    ack = self.recvfrom(GLOBAL_PACKET_LEN)
                    ack_packet = TCPPacket.from_bytes(ack)
                    print(f'[SENDER]: received ACK {ack_packet}')
                    if ack_packet.type != b'A' or ack_packet.id != packet.id:
                        not_received = True
                except TimeoutError:
                    not_received = True

        return len(data)

    def recv(self, n: int):
        data = bytearray()
        while True:
            try:
                # print('trying to recieve')
                packet_bytes = self.recvfrom(GLOBAL_PACKET_LEN)
                packet = TCPPacket.from_bytes(packet_bytes)
                if packet.id not in self.seen_ids or packet.type == b'A':
                    self.seen_ids.add(packet.id)
                    print(f'[RECEIVER]: received {packet}')
                    if packet.type == b'D':
                        data.extend(packet.data)
                        ack = TCPPacket(b'A', id=packet.id)
                        print(f'[RECEIVER]: sending ACK {ack}')
                        ack_bytes = ack.to_bytes()
                        assert self.sendto(ack_bytes) == len(ack_bytes)
                        print(f'[RECEIVER]: {ack} sent')
                    elif packet.type == b'F':
                        print('[RECEIVER]: received FIN')
                        ack = TCPPacket(b'A', id=packet.id)
                        print(f'[RECEIVER]: sending ACK {ack}')
                        ack_bytes = ack.to_bytes()
                        assert self.sendto(ack_bytes) == len(ack_bytes)
                        print(f'[RECEIVER]: {ack} sent')    
                        return data
            except:
                continue
                