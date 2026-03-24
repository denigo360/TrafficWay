#!/usr/bin/env python3
"""
!!!
This is testing version of sniffer, result is not guaranteed
!!!




Usage: python ja3_extractor.py <pcap_file> [--json output.json]
"""

from scapy.all import rdpcap, IP, TCP, Raw
import sys
import json
import hashlib
import struct
from collections import defaultdict

# Constants
TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_SERVER_HELLO = 0x02


def calculate_ja3(data):
    """Calculate JA3 fingerprint from ClientHello data"""
    try:
        if not data or len(data) < 5:
            return None

        pos = 4

        # SSL Version
        if pos + 2 > len(data):
            return None
        ssl_version = data[pos:pos + 2].hex()
        pos += 2

        # Random
        if pos + 32 > len(data):
            return None
        pos += 32

        # Session ID
        if pos + 1 > len(data):
            return None
        session_id_len = data[pos]
        pos += 1
        if pos + session_id_len > len(data):
            return None
        pos += session_id_len

        # Cipher Suites
        if pos + 2 > len(data):
            return None
        cipher_suites_len = (data[pos] << 8) + data[pos + 1]
        pos += 2
        cipher_suites = []
        if pos + cipher_suites_len <= len(data):
            for i in range(0, cipher_suites_len, 2):
                if i + 2 <= cipher_suites_len:
                    cipher_suites.append(data[pos + i:pos + i + 2].hex())
        pos += cipher_suites_len

        # Compression Methods
        if pos + 1 > len(data):
            return None
        compression_len = data[pos]
        pos += 1
        if pos + compression_len > len(data):
            return None
        pos += compression_len

        # Extensions
        if pos + 2 > len(data):
            return None
        extensions_len = (data[pos] << 8) + data[pos + 1]
        pos += 2

        extensions = []
        elliptic_curves = []
        ec_point_formats = []
        ext_end = pos + extensions_len

        while pos + 4 <= ext_end and pos < len(data):
            ext_type = (data[pos] << 8) + data[pos + 1]
            ext_len = (data[pos + 2] << 8) + data[pos + 3]
            ext_data = data[pos + 4:pos + 4 + ext_len] if pos + 4 + ext_len <= len(data) else b''

            extensions.append(ext_type)

            if ext_type == 10 and len(ext_data) >= 2:
                curves_len = (ext_data[0] << 8) + ext_data[1]
                for i in range(0, curves_len, 2):
                    if i + 2 <= len(ext_data):
                        curve = (ext_data[i + 2] << 8) + ext_data[i + 3] if i + 3 < len(ext_data) else None
                        if curve:
                            elliptic_curves.append(curve)

            if ext_type == 11 and len(ext_data) >= 1:
                formats_len = ext_data[0]
                for i in range(formats_len):
                    if i + 1 <= len(ext_data):
                        ec_point_formats.append(ext_data[i + 1])

            pos += 4 + ext_len

        ja3_string = f"{ssl_version},{','.join(cipher_suites)},{','.join(map(str, extensions))},{','.join(map(str, elliptic_curves))},{','.join(map(str, ec_point_formats))}"
        ja3_hash = hashlib.md5(ja3_string.encode()).hexdigest()

        return {
            'hash': ja3_hash,
            'string': ja3_string,
            'cipher_suites': len(cipher_suites),
            'extensions': len(extensions),
            'grease': any(0x1a1a <= e <= 0xffff and e % 0x1a1a == 0 for e in extensions)
        }
    except Exception as e:
        return None


def find_tls_handshakes(payload, direction='client'):
    """Extract TLS handshake messages from packet payload"""
    if not payload:
        return []

    handshakes = []
    pos = 0

    while pos + 5 <= len(payload):
        # Look for TLS handshake record
        if payload[pos] != TLS_HANDSHAKE:
            pos += 1
            continue

        record_len = struct.unpack('>H', payload[pos + 3:pos + 5])[0]
        if pos + 5 + record_len > len(payload):
            pos += 1
            continue

        record_data = payload[pos + 5:pos + 5 + record_len]
        msg_pos = 0

        while msg_pos + 4 <= len(record_data):
            msg_type = record_data[msg_pos]
            msg_len = struct.unpack('>I', b'\x00' + record_data[msg_pos + 1:msg_pos + 4])[0]

            if msg_pos + 4 + msg_len <= len(record_data):
                # Collect both ClientHello and ServerHello
                if msg_type in [TLS_CLIENT_HELLO, TLS_SERVER_HELLO]:
                    handshakes.append({
                        'type': msg_type,
                        'data': record_data[msg_pos:msg_pos + 4 + msg_len]
                    })
                msg_pos += 4 + msg_len
            else:
                break

        pos += 5 + record_len

    return handshakes


def extract_sni(data):
    """Extract SNI from ClientHello"""
    try:
        if not data or data[0] != TLS_CLIENT_HELLO:
            return None

        pos = 4

        # Skip version, random, session_id
        pos += 2 + 32

        if pos + 1 > len(data):
            return None
        session_id_len = data[pos]
        pos += 1 + session_id_len

        # Skip cipher suites
        if pos + 2 > len(data):
            return None
        cipher_suites_len = (data[pos] << 8) + data[pos + 1]
        pos += 2 + cipher_suites_len

        # Skip compression methods
        if pos + 1 > len(data):
            return None
        compression_len = data[pos]
        pos += 1 + compression_len

        # Parse extensions
        if pos + 2 > len(data):
            return None
        extensions_len = (data[pos] << 8) + data[pos + 1]
        pos += 2

        end = pos + extensions_len
        while pos + 4 <= end:
            ext_type = (data[pos] << 8) + data[pos + 1]
            ext_len = (data[pos + 2] << 8) + data[pos + 3]

            if ext_type == 0x0000:  # SNI
                ext_data = data[pos + 4:pos + 4 + ext_len]
                if len(ext_data) >= 5 and ext_data[0] == 0x00:
                    name_len = (ext_data[2] << 8) + ext_data[3]
                    if 4 + name_len <= len(ext_data):
                        return ext_data[4:4 + name_len].decode('utf-8', errors='ignore')

            pos += 4 + ext_len
    except:
        pass
    return None


def analyze_pcap(filename):
    """Extract all JA3 fingerprints from PCAP"""
    print(f"[*] Reading {filename}...")
    packets = rdpcap(filename)

    results = []
    streams = defaultdict(list)
    stream_counter = 0

    print(f"[*] Found {len(packets)} packets")
    print("[*] Extracting JA3 fingerprints (searching in both directions)...\n")

    # Collect all packets into streams
    for pkt in packets:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            continue

        ip_layer = pkt[IP]
        tcp_layer = pkt[TCP]

        # Only analyze port 443
        if tcp_layer.dport != 443 and tcp_layer.sport != 443:
            continue

        # Create stream key
        key = tuple(sorted([(ip_layer.src, tcp_layer.sport), (ip_layer.dst, tcp_layer.dport)]))

        payload = bytes(pkt[Raw])
        streams[key].append({
            'seq': tcp_layer.seq,
            'payload': payload,
            'src': ip_layer.src,
            'dst': ip_layer.dst,
            'sport': tcp_layer.sport,
            'dport': tcp_layer.dport
        })

    print(f"[*] Found {len(streams)} TCP streams\n")
    print("=" * 90)

    # Analyze each stream
    for key, packets in streams.items():
        # Sort by sequence number
        packets.sort(key=lambda x: x['seq'])

        # Reassemble stream in both directions separately
        client_data = bytearray()
        server_data = bytearray()
        last_seq_client = None
        last_seq_server = None

        src_ip, src_port = key[0]
        dst_ip, dst_port = key[1]

        for pkt in packets:
            # Determine direction
            if pkt['src'] == src_ip and pkt['sport'] == src_port:
                # Client to server
                if last_seq_client is None or pkt['seq'] > last_seq_client:
                    client_data.extend(pkt['payload'])
                    last_seq_client = pkt['seq'] + len(pkt['payload'])
            else:
                # Server to client
                if last_seq_server is None or pkt['seq'] > last_seq_server:
                    server_data.extend(pkt['payload'])
                    last_seq_server = pkt['seq'] + len(pkt['payload'])

        # Try to find ClientHello in client->server data
        found = False

        if len(client_data) >= 50:
            handshakes = find_tls_handshakes(bytes(client_data), 'client')

            for hs in handshakes:
                if hs['type'] == TLS_CLIENT_HELLO:
                    ja3 = calculate_ja3(hs['data'])
                    if ja3:
                        sni = extract_sni(hs['data'])
                        stream_counter += 1

                        print(f"\n[{stream_counter}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
                        print(f"    JA3: {ja3['hash']}")
                        print(f"    SNI: {sni if sni else 'None'}")
                        print(f"    Cipher Suites: {ja3['cipher_suites']}")
                        print(f"    Extensions: {ja3['extensions']}")
                        print(f"    GREASE: {'Yes' if ja3['grease'] else 'No'}")

                        results.append({
                            'stream_id': stream_counter,
                            'source': f"{src_ip}:{src_port}",
                            'destination': f"{dst_ip}:{dst_port}",
                            'ja3_hash': ja3['hash'],
                            'ja3_string': ja3['string'],
                            'sni': sni,
                            'cipher_suites_count': ja3['cipher_suites'],
                            'extensions_count': ja3['extensions'],
                            'has_grease': ja3['grease']
                        })
                        found = True
                        break

        # If not found in client data, try server data (for Telegram Desktop)
        if not found and len(server_data) >= 50:
            handshakes = find_tls_handshakes(bytes(server_data), 'server')

            for hs in handshakes:
                if hs['type'] == TLS_CLIENT_HELLO:
                    ja3 = calculate_ja3(hs['data'])
                    if ja3:
                        sni = extract_sni(hs['data'])
                        stream_counter += 1

                        print(f"\n[{stream_counter}] {dst_ip}:{dst_port} -> {src_ip}:{src_port} (reverse direction)")
                        print(f"    JA3: {ja3['hash']}")
                        print(f"    SNI: {sni if sni else 'None'}")
                        print(f"    Cipher Suites: {ja3['cipher_suites']}")
                        print(f"    Extensions: {ja3['extensions']}")
                        print(f"    GREASE: {'Yes' if ja3['grease'] else 'No'}")

                        results.append({
                            'stream_id': stream_counter,
                            'source': f"{dst_ip}:{dst_port}",
                            'destination': f"{src_ip}:{src_port}",
                            'ja3_hash': ja3['hash'],
                            'ja3_string': ja3['string'],
                            'sni': sni,
                            'cipher_suites_count': ja3['cipher_suites'],
                            'extensions_count': ja3['extensions'],
                            'has_grease': ja3['grease'],
                            'note': 'Found in server->client traffic'
                        })
                        found = True
                        break

    return results


def main():
    if len(sys.argv) < 2:
        print("Usage: python ja3_extractor.py <pcap_file> [--json output.json]")
        print("\nExamples:")
        print("  python ja3_extractor.py capture.pcap")
        print("  python ja3_extractor.py capture.pcap --json ja3_results.json")
        sys.exit(1)

    pcap_file = sys.argv[1]

    # Parse command line
    output_json = None
    if len(sys.argv) >= 4 and sys.argv[2] == '--json':
        output_json = sys.argv[3]

    # Analyze PCAP
    results = analyze_pcap(pcap_file)

    # Print summary
    print("\n" + "=" * 90)
    print("SUMMARY")
    print("=" * 90)
    print(f"Total unique JA3 fingerprints: {len(set(r['ja3_hash'] for r in results))}")
    print(f"Total streams with JA3: {len(results)}")

    print("\n")
    print(f"!!! This is testing version of sniffer, result is not guaranteed !!!")

    if results:
        print("\nUnique JA3 Hashes:")
        ja3_counts = defaultdict(int)
        for r in results:
            ja3_counts[r['ja3_hash']] += 1

        for ja3_hash, count in sorted(ja3_counts.items(), key=lambda x: x[1], reverse=True):
            sample = next(r for r in results if r['ja3_hash'] == ja3_hash)
            note = f" - {sample.get('note', '')}" if sample.get('note') else ''
            print(f"  {ja3_hash} ({count} streams) - SNI: {sample['sni'] if sample['sni'] else 'None'}{note}")

    # Save to JSON if requested
    if output_json:
        with open(output_json, 'w') as f:
            json.dump({
                'file': pcap_file,
                'total_streams': len(results),
                'unique_ja3': len(set(r['ja3_hash'] for r in results)),
                'results': results
            }, f, indent=2)
        print(f"\n[*] Results saved to {output_json}")


if __name__ == "__main__":
    main()