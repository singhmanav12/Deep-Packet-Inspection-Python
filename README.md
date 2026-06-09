## Goals

The goal is to provide a readable, extendable Python implementation that:
- reads PCAP packet captures
- parses Ethernet / IPv4 / TCP / UDP headers
- extracts HTTP Host headers, TLS SNI, and DNS queries
- applies rule-based blocking for IP, domain, port, and application type
- writes filtered packets back to a new PCAP file

## Project structure

- `pcap_reader.py` - PCAP global header parser, packet reader, and writer
- `packet_parser.py` - Basic Ethernet/IPv4/TCP/UDP parsing into a common packet model
- `extractors.py` - TLS SNI extraction, HTTP Host extraction, DNS query extraction
- `rule_manager.py` - Blocking rules for IPs, domains, ports, and detected apps
- `dpi_engine.py` - Sequential DPI engine with classification and reporting
- `main.py` - CLI entrypoint for running the processor
- `__main__.py` - Enables `python -m DPI2`

## Installation

No external Python packages are required for this initial implementation.

From the repository root, install the package in editable mode if desired:

```bash
python -m pip install -e .
```

## Usage

Run the package with a PCAP file from the parent folder of the `DPI2` package:

```bash
cd "c:\Users\prata\OneDrive\Desktop"
python -m DPI2 test_dpi.pcap -o python_filtered_output.pcap
```

If your PCAP file is inside the `DPI2` folder, you can still run from the parent folder and the package will resolve the file automatically:

```bash
cd "c:\Users\prata\OneDrive\Desktop"
python -m DPI2 test_dpi.pcap -o python_filtered_output.pcap
```

Or run directly from inside the `DPI2` folder using the wrapper script:

```bash
cd "c:\Users\prata\OneDrive\Desktop\DPI2"
python run_python_dpi.py test_dpi.pcap -o python_filtered_output.pcap
```

If you installed the package in editable mode, you can also use the console script from anywhere:

```bash
python-dpi test_dpi.pcap -o python_filtered_output.pcap
```

### Blocking examples

Block a specific source IP:

```bash
python run_python_dpi.py test_dpi.pcap -o filtered.pcap --block-ip 192.168.0.10
```

Block one or more domains:

```bash
python run_python_dpi.py test_dpi.pcap -o filtered.pcap --block-domain facebook.com --block-domain *.youtube.com
```

Block HTTP or HTTPS traffic by application classification:

```bash
python run_python_dpi.py test_dpi.pcap -o filtered.pcap --block-http
python run_python_dpi.py test_dpi.pcap -o filtered.pcap --block-https
```

## Output

The engine writes only forwarded packets to the output PCAP file. Blocked packets are dropped and not included in the output.

After processing, it prints a summary report including:
- total packets processed
- forwarded vs dropped counts
- TCP/UDP packet counts
- top detected application types
- top extracted domains

## Notes

- This Python implementation is intended for prototyping and inspection of moderate-size PCAPs.
- It does not yet include a high-performance threaded pipeline.
- The logic is intentionally simple so the project can be extended easily.

## Next improvements

- add thread-based packet processing for better throughput
- add rule loading from config files
- support more application classification rules
- add unit tests for parser and extractor functions
