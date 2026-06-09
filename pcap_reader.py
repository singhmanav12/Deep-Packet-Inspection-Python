import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional


@dataclass
class PcapGlobalHeader:
    magic_number: int
    version_major: int
    version_minor: int
    thiszone: int
    sigfigs: int
    snaplen: int
    network: int


@dataclass
class PcapPacketHeader:
    ts_sec: int
    ts_usec: int
    incl_len: int
    orig_len: int


@dataclass
class RawPacket:
    header: PcapPacketHeader
    data: bytes


class PcapReader:
    def __init__(self) -> None:
        self._file: Optional[BinaryIO] = None
        self.global_header: Optional[PcapGlobalHeader] = None
        self._byte_order = '<'

    def open(self, path: str) -> None:
        self._file = open(path, 'rb')
        magic = self._file.read(4)
        if len(magic) != 4:
            raise ValueError('Invalid PCAP file: too short')

        if magic == b'\xd4\xc3\xb2\xa1':
            self._byte_order = '<'
        elif magic == b'\xa1\xb2\xc3\xd4':
            self._byte_order = '>'
        else:
            raise ValueError('Unsupported PCAP magic number')

        header_data = self._file.read(20)
        if len(header_data) != 20:
            raise ValueError('Invalid PCAP header')

        fields = struct.unpack(self._byte_order + 'HHIIII', header_data)
        self.global_header = PcapGlobalHeader(
            magic_number=int.from_bytes(magic, byteorder='little' if self._byte_order == '<' else 'big'),
            version_major=fields[0],
            version_minor=fields[1],
            thiszone=fields[2],
            sigfigs=fields[3],
            snaplen=fields[4],
            network=fields[5],
        )

    def close(self) -> None:
        if self._file is not None and not self._file.closed:
            self._file.close()
            self._file = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def packets(self) -> Iterator[RawPacket]:
        if self._file is None:
            raise ValueError('PCAP file is not open')

        while True:
            header_bytes = self._file.read(16)
            if len(header_bytes) != 16:
                break

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(self._byte_order + 'IIII', header_bytes)
            packet_data = self._file.read(incl_len)
            if len(packet_data) != incl_len:
                break

            yield RawPacket(
                header=PcapPacketHeader(ts_sec=ts_sec, ts_usec=ts_usec, incl_len=incl_len, orig_len=orig_len),
                data=packet_data,
            )


class PcapWriter:
    def __init__(self, path: str, global_header: PcapGlobalHeader, byte_order: str = '<') -> None:
        self._file = open(path, 'wb')
        self._byte_order = byte_order
        self._write_global_header(global_header)

    def _write_global_header(self, hdr: PcapGlobalHeader) -> None:
        magic = hdr.magic_number.to_bytes(4, byteorder='little' if self._byte_order == '<' else 'big')
        self._file.write(magic)
        self._file.write(struct.pack(self._byte_order + 'HHIIII', hdr.version_major, hdr.version_minor,
                                     hdr.thiszone, hdr.sigfigs, hdr.snaplen, hdr.network))

    def write_packet(self, header: PcapPacketHeader, data: bytes) -> None:
        self._file.write(struct.pack(self._byte_order + 'IIII', header.ts_sec, header.ts_usec,
                                     header.incl_len, header.orig_len))
        self._file.write(data)

    def close(self) -> None:
        if not self._file.closed:
            self._file.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
