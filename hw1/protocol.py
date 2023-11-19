import socket
import os
import math
import select


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

class TCPPacket():
    TYPE_LEN = 1
    ID_LEN = 20
    SEQ_LEN = 4
    PACKET_LEN = GLOBAL_PACKET_LEN
    DATA_LEN = PACKET_LEN - TYPE_LEN - ID_LEN - SEQ_LEN

    def __init__(self, type, seq, message_id=None, data=None):
        self.message_id = os.urandom(self.ID_LEN) if message_id is None else message_id
        self.type = type
        self.seq = seq

        self.data = b'' if data is None else data


    def __str__(self):
        return f"TYPE={self.type}, SEQ={self.seq}, ID={self.message_id}, DATA len={len(self.data)}"


    def reshuffle_id(self):
        self.message_id = os.urandom(self.ID_LEN)


    def to_bytes(self):
        return b''.join([
            self.type,
            self.seq.to_bytes(self.SEQ_LEN, 'big'),
            self.message_id,
            self.data,
        ])
    

    @classmethod
    def from_bytes(cls, data):
        return cls(
            type=data[:cls.TYPE_LEN],
            seq=int.from_bytes(data[cls.TYPE_LEN: cls.TYPE_LEN + cls.SEQ_LEN], 'big'),
            message_id=data[cls.TYPE_LEN + cls.SEQ_LEN: cls.TYPE_LEN + cls.SEQ_LEN + cls.ID_LEN],
            data=data[cls.TYPE_LEN + cls.SEQ_LEN + cls.ID_LEN:]
        )
    
    @classmethod
    def divide(cls, data, start_seq):
        n_parts = math.ceil(len(data) / cls.DATA_LEN)
        ret = []
        current_seq = start_seq
        for i in range(n_parts):
            packet_data = data[i * cls.DATA_LEN: (i + 1) * cls.DATA_LEN]
            ret.append(cls(type=b'F' if i == n_parts - 1 else b'D', data=packet_data, seq=current_seq))
            current_seq += len(packet_data)

        return ret


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.udp_socket.settimeout(0.005)
        self.sender_seen_ids = set()
        self.receiver_seen_ids = set()
        
        self.send_count = 0
        self.recv_count = 0
    
    def sendto(self, data):
        return super().sendto(data)
    
    def recvfrom(self, n, is_receiver=False):
        while True:
            packet = TCPPacket.from_bytes(super().recvfrom(n))
            if is_receiver and packet.message_id in self.receiver_seen_ids or not is_receiver and packet.message_id in self.sender_seen_ids:
                continue
            else:
                return packet

    def send(self, data: bytes):
        # print(f'[SENDER]: START SEND: {len(data)}, {self.send_count}')
        current_seq = 0
        expected_seq = 0

        ############# DATA #############
        packets = TCPPacket.divide(data, start_seq=current_seq)
        for packet in packets:
            expected_seq += len(packet.data)

            not_received = True
            while not_received:
                not_received = False
                try:
                    packet.reshuffle_id()
                    packet_bytes = packet.to_bytes()
                    assert self.sendto(packet_bytes) == len(packet_bytes)
                    # print(f'[SENDER]: sent {packet}')
                    ack_packet = self.recvfrom(GLOBAL_PACKET_LEN)
                    #ack_packet = TCPPacket.from_bytes(ack)
                    if ack_packet.message_id in self.sender_seen_ids:
                        print('[SENDER]: duplicate')
                        not_received = True
                        continue
                    self.sender_seen_ids.add(ack_packet.message_id)
                    # print(f'[SENDER]: received ACK {ack_packet}')
                    if ack_packet.type != b'A' or ack_packet.seq != expected_seq:
                        not_received = True
                except TimeoutError:
                    not_received = True

            current_seq = expected_seq

        # print(f'[SENDER]: END SEND {self.send_count}')
        self.send_count += 1
        return len(data)


    def recv(self, n: int):
        print(f'[RECEIVER]: START RECV {self.recv_count}')
        data = bytearray()
        current_seq = 0

        while True:
            try:
                packet = self.recvfrom(GLOBAL_PACKET_LEN, is_receiver=True)
                #packet = TCPPacket.from_bytes(packet_bytes)

                if packet.message_id in self.receiver_seen_ids:
                    print('[RECEIVER]: duplicate')
                    continue

                self.receiver_seen_ids.add(packet.message_id)
                
                if packet.type != b'A':
                    if packet.seq == current_seq:
                        data.extend(packet.data)
                        current_seq += len(packet.data)
                        ack_packet = TCPPacket(type=b'A', message_id=packet.message_id, seq=current_seq)
                        ack_packet_bytes = ack_packet.to_bytes()
                        assert self.sendto(ack_packet_bytes) == len(ack_packet_bytes)
                        # print(f'[RECEIVER]: sent ACK {ack_packet}')
                        if packet.type == b'F':
                            for _ in range(4):
                                ack_packet.reshuffle_id()
                                ack_packet_bytes = ack_packet.to_bytes()
                                assert self.sendto(ack_packet_bytes) == len(ack_packet_bytes)
                            # print(f'[RECEIVER]: END RECV: {len(data)}, {self.recv_count}')
                            self.recv_count += 1
                            return data
                    else:
                        # print(f'wrong seq: curr={current_seq}, pack={packet.seq}')
                        ack_packet = TCPPacket(type=b'A', message_id=packet.message_id, seq=packet.seq + len(packet.data))
                        ack_packet_bytes = ack_packet.to_bytes()
                        assert self.sendto(ack_packet_bytes) == len(ack_packet_bytes)
                        # print(f'[RECEIVER]: sent ACK {ack_packet}')

            except:
                pass
        
                