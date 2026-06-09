import re
from typing import Optional


class SNIExtractor:
    @staticmethod
    def _read_uint16(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 2], 'big')

    @staticmethod
    def _read_uint24(data: bytes, offset: int) -> int:
        return int.from_bytes(data[offset:offset + 3], 'big')

    @staticmethod
    def is_tls_client_hello(payload: bytes) -> bool:
        if len(payload) < 9:
            return False
        if payload[0] != 0x16:
            return False
        version = SNIExtractor._read_uint16(payload, 1)
        if version < 0x0300 or version > 0x0304:
            return False
        if payload[5] != 0x01:
            return False
        return True

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not SNIExtractor.is_tls_client_hello(payload):
            return None

        try:
            offset = 5
            handshake_length = SNIExtractor._read_uint24(payload, offset + 1)
            offset += 4
            offset += 2 + 32
            session_id_len = payload[offset]
            offset += 1 + session_id_len
            cipher_len = SNIExtractor._read_uint16(payload, offset)
            offset += 2 + cipher_len
            compression_len = payload[offset]
            offset += 1 + compression_len
            extensions_len = SNIExtractor._read_uint16(payload, offset)
            offset += 2
            end = offset + extensions_len

            while offset + 4 <= end:
                ext_type = SNIExtractor._read_uint16(payload, offset)
                ext_len = SNIExtractor._read_uint16(payload, offset + 2)
                offset += 4
                if ext_type == 0x0000 and offset + ext_len <= end:
                    list_len = SNIExtractor._read_uint16(payload, offset)
                    offset += 2
                    if offset + 3 > end:
                        break
                    name_type = payload[offset]
                    name_len = SNIExtractor._read_uint16(payload, offset + 1)
                    offset += 3
                    if name_type == 0x00 and offset + name_len <= end:
                        return payload[offset:offset + name_len].decode('utf-8', errors='replace')
                    break
                offset += ext_len
        except (IndexError, ValueError):
            return None
        return None


class HTTPHostExtractor:
    METHODS = [b'GET ', b'POST', b'PUT ', b'HEAD', b'DELE', b'PATC', b'OPTI']
    HOST_RE = re.compile(rb'^[A-Za-z]+ .*?\r\n(?:.*?\r\n)*?Host:\s*([^\r\n:]+)', re.IGNORECASE | re.DOTALL)

    @staticmethod
    def extract(payload: bytes) -> Optional[str]:
        if not any(payload.startswith(method) for method in HTTPHostExtractor.METHODS):
            return None

        match = HTTPHostExtractor.HOST_RE.search(payload)
        if match:
            return match.group(1).decode('utf-8', errors='replace')
        return None


class DNSExtractor:
    @staticmethod
    def extract_query(payload: bytes) -> Optional[str]:
        if len(payload) < 12:
            return None
        flags = int.from_bytes(payload[2:4], 'big')
        if flags & 0x8000:
            return None
        qdcount = int.from_bytes(payload[4:6], 'big')
        if qdcount == 0:
            return None

        offset = 12
        labels = []
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            if offset + length > len(payload):
                return None
            labels.append(payload[offset:offset + length].decode('utf-8', errors='replace'))
            offset += length

        if not labels:
            return None

        return '.'.join(labels)
