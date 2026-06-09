import argparse
from pathlib import Path

from .dpi_engine import DPIEngine
from .rule_manager import AppType


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Python DPI PCAP processor')
    parser.add_argument('input_pcap', help='Input PCAP file')
    parser.add_argument('-o', '--output', help='Output PCAP file path', default='python_filtered_output.pcap')
    parser.add_argument('--block-domain', action='append', default=[], help='Domain to block (supports *.example.com)')
    parser.add_argument('--block-ip', action='append', default=[], help='Source IP address to block')
    parser.add_argument('--block-port', action='append', type=int, default=[], help='Destination port to block')
    parser.add_argument('--block-http', action='store_true', help='Block HTTP traffic')
    parser.add_argument('--block-https', action='store_true', help='Block HTTPS traffic')
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    engine = DPIEngine()

    for ip in args.block_ip:
        engine.rules.block_ip(ip)
    for domain in args.block_domain:
        engine.rules.block_domain(domain)
    for port in args.block_port:
        engine.rules.block_port(port)
    if args.block_http:
        engine.rules.block_app(AppType.HTTP)
    if args.block_https:
        engine.rules.block_app(AppType.HTTPS)

    input_path = Path(args.input_pcap)
    if not input_path.exists():
        if not input_path.is_absolute():
            fallback_path = Path(__file__).resolve().parent / args.input_pcap
            if fallback_path.exists():
                input_path = fallback_path
        if not input_path.exists():
            raise FileNotFoundError(f'Input file not found: {input_path}')

    engine.process_file(str(input_path), args.output)
    engine.print_report()


if __name__ == '__main__':
    main()
