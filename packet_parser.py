import struct
from dataclasses import dataclass
from typing import Optional


@dataclass
class ParsedPacket:
    ts_sec: int
    ts_usec: int
    src_mac: str = ''
    dst_mac: str = ''
    ethertype: int = 0
    has_ip: bool = False
    src_ip: str = ''
    dst_ip: str = ''
    protocol: int = 0
    ttl: int = 0
    has_tcp: bool = False
    has_udp: bool = False
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: int = 0
    payload_offset: int = 0
    payload: bytes = b''


class PacketParser:
    ETH_HEADER_LEN = 14
    IPV4_MIN_HEADER_LEN = 20
    TCP_MIN_HEADER_LEN = 20
    UDP_HEADER_LEN = 8

    @staticmethod
    def mac_to_str(raw: bytes) -> str:
        return ':'.join(f'{b:02x}' for b in raw)

    @staticmethod
    def ip_to_str(raw: bytes) -> str:
        return '.'.join(str(b) for b in raw)

    @staticmethod
    def parse(packet_data: bytes) -> Optional[ParsedPacket]:
        if len(packet_data) < PacketParser.ETH_HEADER_LEN:
            return None

        ethertype = struct.unpack('!H', packet_data[12:14])[0]
        parsed = ParsedPacket(ts_sec=0, ts_usec=0, src_mac=PacketParser.mac_to_str(packet_data[6:12]),
                              dst_mac=PacketParser.mac_to_str(packet_data[0:6]), ethertype=ethertype)
        offset = PacketParser.ETH_HEADER_LEN

        if ethertype != 0x0800:
            return parsed

        if len(packet_data) < offset + PacketParser.IPV4_MIN_HEADER_LEN:
            return parsed

        version_ihl = packet_data[offset]
        version = version_ihl >> 4
        ihl = (version_ihl & 0x0F) * 4
        if version != 4 or ihl < PacketParser.IPV4_MIN_HEADER_LEN:
            return parsed

        parsed.has_ip = True
        parsed.ttl = packet_data[offset + 8]
        parsed.protocol = packet_data[offset + 9]
        parsed.src_ip = PacketParser.ip_to_str(packet_data[offset + 12:offset + 16])
        parsed.dst_ip = PacketParser.ip_to_str(packet_data[offset + 16:offset + 20])
        offset += ihl

        if parsed.protocol == 6 and len(packet_data) >= offset + PacketParser.TCP_MIN_HEADER_LEN:
            parsed.has_tcp = True
            parsed.src_port, parsed.dst_port = struct.unpack('!HH', packet_data[offset:offset + 4])
            parsed.tcp_flags = packet_data[offset + 13]
            data_offset = (packet_data[offset + 12] >> 4) * 4
            parsed.payload_offset = offset + data_offset
        elif parsed.protocol == 17 and len(packet_data) >= offset + PacketParser.UDP_HEADER_LEN:
            parsed.has_udp = True
            parsed.src_port, parsed.dst_port = struct.unpack('!HH', packet_data[offset:offset + 4])
            parsed.payload_offset = offset + PacketParser.UDP_HEADER_LEN

        if parsed.payload_offset and parsed.payload_offset < len(packet_data):
            parsed.payload = packet_data[parsed.payload_offset:]

        return parsed

    @staticmethod
    def tcp_flags_to_str(flags: int) -> str:
        names = []
        if flags & 0x01:
            names.append('FIN')
        if flags & 0x02:
            names.append('SYN')
        if flags & 0x04:
            names.append('RST')
        if flags & 0x08:
            names.append('PSH')
        if flags & 0x10:
            names.append('ACK')
        if flags & 0x20:
            names.append('URG')
        return '|'.join(names) if names else 'NONE'
