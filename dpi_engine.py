from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .pcap_reader import PcapReader, PcapWriter
from .packet_parser import PacketParser, ParsedPacket
from .extractors import SNIExtractor, HTTPHostExtractor, DNSExtractor
from .rule_manager import AppType, RuleManager, sni_to_app_type


@dataclass
class DPIStats:
    total_packets: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    app_counts: Counter = field(default_factory=Counter)
    domains: Counter = field(default_factory=Counter)


class DPIEngine:
    def __init__(self) -> None:
        self.rules = RuleManager()
        self.stats = DPIStats()
        self.default_output_name = 'filtered_output.pcap'

    def classify_packet(self, parsed: ParsedPacket) -> tuple[AppType, str]:
        domain = ''
        app = AppType.UNKNOWN

        if parsed.has_tcp:
            if parsed.dst_port == 80 or parsed.src_port == 80:
                app = AppType.HTTP
                domain = HTTPHostExtractor.extract(parsed.payload) or ''
            elif parsed.dst_port == 443 or parsed.src_port == 443:
                domain = SNIExtractor.extract(parsed.payload) or ''
                app = sni_to_app_type(domain) if domain else AppType.HTTPS
            else:
                app = AppType.TLS if parsed.payload else AppType.UNKNOWN
        elif parsed.has_udp:
            if parsed.dst_port == 53 or parsed.src_port == 53:
                app = AppType.DNS
                domain = DNSExtractor.extract_query(parsed.payload) or ''
            else:
                app = AppType.UNKNOWN

        return app, domain

    def process_file(self, input_path: str, output_path: Optional[str] = None) -> None:
        output_path = output_path or self.default_output_name
        input_path = Path(input_path)
        output_path = Path(output_path)

        with PcapReader() as reader:
            reader.open(str(input_path))
            if reader.global_header is None:
                raise RuntimeError('Unable to read PCAP global header')

            with PcapWriter(str(output_path), reader.global_header) as writer:
                for raw_packet in reader.packets():
                    self.stats.total_packets += 1
                    parsed = PacketParser.parse(raw_packet.data)
                    if parsed is None:
                        self.stats.dropped_packets += 1
                        continue

                    parsed.ts_sec = raw_packet.header.ts_sec
                    parsed.ts_usec = raw_packet.header.ts_usec

                    if parsed.has_tcp:
                        self.stats.tcp_packets += 1
                    elif parsed.has_udp:
                        self.stats.udp_packets += 1

                    app, domain = self.classify_packet(parsed)
                    self.stats.app_counts[app] += 1
                    if domain:
                        self.stats.domains[domain] += 1

                    reason = self.rules.should_block(parsed.src_ip, parsed.dst_port, app, domain)
                    if reason is None:
                        writer.write_packet(raw_packet.header, raw_packet.data)
                        self.stats.forwarded_packets += 1
                    else:
                        self.stats.dropped_packets += 1

    def print_report(self) -> None:
        print('DPI Processing Report')
        print('---------------------')
        print(f'Total packets: {self.stats.total_packets}')
        print(f'Forwarded packets: {self.stats.forwarded_packets}')
        print(f'Dropped packets: {self.stats.dropped_packets}')
        print(f'TCP packets: {self.stats.tcp_packets}')
        print(f'UDP packets: {self.stats.udp_packets}')
        print('Top applications:')
        for app, count in self.stats.app_counts.most_common(8):
            print(f'  {app.name}: {count}')
        if self.stats.domains:
            print('Top extracted domains:')
            for domain, count in self.stats.domains.most_common(8):
                print(f'  {domain}: {count}')
