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

class TCPPacket():
    TYPE_LEN = 1
    ID_LEN = 10
    SEQ_LEN = 4
    PACKET_LEN = GLOBAL_PACKET_LEN
    DATA_LEN = PACKET_LEN - TYPE_LEN - ID_LEN - SEQ_LEN

    def __init__(self, type, seq, message_id, data=None):
        self.message_id = message_id
        self.type = type
        self.seq = seq

        self.data = b'' if data is None else data


    def __str__(self):
        return f"TYPE={self.type}, SEQ={self.seq}, ID={self.message_id}, DATA len={len(self.data)}"


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
    def divide(cls, data, start_seq, message_id):
        n_parts = math.ceil(len(data) / cls.DATA_LEN)
        ret = []
        current_seq = start_seq
        for i in range(n_parts):
            packet_data = data[i * cls.DATA_LEN: (i + 1) * cls.DATA_LEN]
            ret.append(cls(type=b'D', data=packet_data, seq=current_seq, message_id=message_id))
            current_seq += len(packet_data)

        #ret.append(cls(type=b'F', seq=current_seq, message_id=message_id))

        return ret


class MyTCPProtocol(UDPBasedProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.udp_socket.settimeout(0.005)
        self.seen_ids = set()

    def send(self, data: bytes):
        print(f'[SENDER]: START SEND: {len(data)}')
        current_seq = 0
        expected_seq = 0
        message_id = os.urandom(TCPPacket.ID_LEN)

        ############# SYN #############
        syn_packet = TCPPacket(type=b'S', seq=current_seq, message_id=message_id)
        syn_packet_bytes = syn_packet.to_bytes()
        expected_seq += 1

        not_received = True
        while not_received:
            not_received = False
            try:
                assert self.sendto(syn_packet_bytes) == len(syn_packet_bytes)
                print(f'[SENDER]: sent {syn_packet}')
                ack = self.recvfrom(GLOBAL_PACKET_LEN)
                ack_packet = TCPPacket.from_bytes(ack)
                print(f'[SENDER]: received ACK {ack_packet}')
                if ack_packet.type != b'A' or ack_packet.message_id != message_id or ack_packet.seq != expected_seq:
                    not_received = True
            except TimeoutError:
                not_received = True
        current_seq = expected_seq

        ############# DATA #############
        packets = TCPPacket.divide(data, start_seq=current_seq, message_id=message_id)
        for packet in packets:
            expected_seq += len(packet.data)
            packet_bytes = packet.to_bytes()

            not_received = True
            while not_received:
                not_received = False
                try:
                    assert self.sendto(packet_bytes) == len(packet_bytes)
                    print(f'[SENDER]: sent {packet}')
                    ack = self.recvfrom(GLOBAL_PACKET_LEN)
                    ack_packet = TCPPacket.from_bytes(ack)
                    print(f'[SENDER]: received ACK {ack_packet}')
                    if ack_packet.type != b'A' or ack_packet.message_id != packet.message_id or ack_packet.seq != expected_seq:
                        not_received = True
                except TimeoutError:
                    not_received = True

            current_seq = expected_seq

        ############# FIN #############
        fin_packet = TCPPacket(type=b'F', seq=current_seq, message_id=message_id)
        fin_packet_bytes = fin_packet.to_bytes()
        expected_seq += 1

        not_received = True
        while not_received:
            not_received = False
            try:
                assert self.sendto(fin_packet_bytes) == len(fin_packet_bytes)
                print(f'[SENDER]: sent {fin_packet}')
                ack = self.recvfrom(GLOBAL_PACKET_LEN)
                ack_packet = TCPPacket.from_bytes(ack)
                print(f'[SENDER]: received ACK {ack_packet}')
                if ack_packet.type != b'A' or ack_packet.message_id != message_id or ack_packet.seq != expected_seq:
                    not_received = True
            except TimeoutError:
                not_received = True
        current_seq = expected_seq

        print(f'[SENDER]: END SEND')
        return len(data)


    def recv(self, n: int):
        print(f'[RECEIVER]: START RECV')
        data = bytearray()
        message_id = None
        current_seq = 0

        while True:
            try:
                packet_bytes = self.recvfrom(GLOBAL_PACKET_LEN)
                packet = TCPPacket.from_bytes(packet_bytes)
                print(f'[RECEIVER]: received {packet}')
                ############## SYN ##############
                if message_id is None and packet.type == b'S' and packet.message_id not in self.seen_ids:
                    message_id = packet.message_id
                    current_seq = packet.seq + 1
                    ack_packet = TCPPacket(type=b'A', message_id=packet.message_id, seq=current_seq)
                    ack_packet_bytes = ack_packet.to_bytes()
                    assert self.sendto(ack_packet_bytes) == len(ack_packet_bytes)
                    print(f'[RECEIVER]: sent ACK {ack_packet}')
                elif packet.type == b'S' and packet.message_id == message_id: # kostil
                    ack_packet = TCPPacket(type=b'A', message_id=packet.message_id, seq=1)
                    ack_packet_bytes = ack_packet.to_bytes()
                    assert self.sendto(ack_packet_bytes) == len(ack_packet_bytes)
                    print(f'[RECEIVER]: sent ACK {ack_packet}')
                elif packet.message_id == message_id and packet.type == b'D':
                    if packet.seq == current_seq:
                        data.extend(packet.data)
                        current_seq += len(packet.data)
                        ack_packet = TCPPacket(type=b'A', message_id=packet.message_id, seq=current_seq)
                        ack_packet_bytes = ack_packet.to_bytes()
                        assert self.sendto(ack_packet_bytes) == len(ack_packet_bytes)
                        print(f'[RECEIVER]: sent ACK {ack_packet}')
                    else:
                        # print(f'wrong seq: curr={current_seq}, pack={packet.seq}')
                        ack_packet = TCPPacket(type=b'A', message_id=packet.message_id, seq=packet.seq + len(packet.data))
                        ack_packet_bytes = ack_packet.to_bytes()
                        assert self.sendto(ack_packet_bytes) == len(ack_packet_bytes)
                        print(f'[RECEIVER]: sent ACK {ack_packet}')

                elif packet.message_id == message_id and packet.type == b'F':
                    if packet.seq == current_seq:
                        current_seq += 1
                        ack_packet = TCPPacket(type=b'A', message_id=packet.message_id, seq=current_seq)
                        ack_packet_bytes = ack_packet.to_bytes()
                        for _ in range(5): #kostil
                            assert self.sendto(ack_packet_bytes) == len(ack_packet_bytes)
                            print(f'[RECEIVER]: sent ACK {ack_packet}')
                        
                        self.seen_ids.add(message_id)
                        print(f'[RECEIVER]: ENV RECV: {len(data)}')
                        return data

                        # while recv ack
                    else:
                        print('wrong seq')
            except:
                pass
        
                