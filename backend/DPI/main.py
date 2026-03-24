#!/usr/bin/env python3
"""
TLS Traffic Analyzer with Application Detection
Analyzes PCAP files to detect applications based on JA3, SNI, and IP addresses
"""

from scapy.all import rdpcap, Raw, IP, TCP
import sys
from collections import Counter, defaultdict
import struct
import hashlib
import ipaddress

# Constants
TLS_HANDSHAKE = 0x16
TLS_APPLICATION_DATA = 0x17
TLS_CLIENT_HELLO = 0x01
TLS_EXTENSION_SERVER_NAME = 0x0000
TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO = 0xfe0d

MAX_STREAM_SIZE = 100 * 1024 * 1024
MAX_PACKETS_PER_STREAM = 1000

# Known JA3 fingerprints
KNOWN_JA3_FINGERPRINTS = {
    # Browsers
    "c6336e2978935be330753d2ff32b5f4d": {"app": "Chrome", "type": "Browser", "version": "86-90"},
    "0b96d95b98054d59017f603f1b3356ec": {"app": "Chrome", "type": "Browser", "version": "80-85"},
    "6734f37431670b3ab4292b8f60f29984": {"app": "Chrome", "type": "Browser", "version": "70-79"},
    "de9c92ba51c6752a5eab798a196b33ae": {"app": "Chrome", "type": "Browser", "version": "100+"},
    "2791a674f8eb1aa5cef382248d08804b": {"app": "Yandex Browser", "type": "Browser", "version": "23+"},
    "4403c6661d9dd1f1a269c135e6c23c22": {"app": "Yandex Browser", "type": "Browser", "version": "23+"},
    "063e77d802539f43e7e5adb3d5d9d0f1": {"app": "Yandex Browser", "type": "Browser", "version": "23+"},
    "a684ee32d5c189db9341535b8568b8b5": {"app": "Yandex Browser", "type": "Browser", "version": "23+"},
    "e7d705a4e6eef9d16b5ea3b10ba437b0": {"app": "Firefox", "type": "Browser", "version": "80-90"},
    "cd08e514941c7ec8b2b46e9c3c93d4ab": {"app": "Firefox", "type": "Browser", "version": "70-79"},
    "2b9c8d7f6e5a4b3c2d1e0f9a8b7c6d5e": {"app": "Edge", "type": "Browser", "version": "90-100"},
    "f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8": {"app": "Edge", "type": "Browser", "version": "100+"},
    "0c7f6e3d5b8a2e9c4d7f1e5a3b8c6d0f": {"app": "Safari", "type": "Browser", "version": "14+"},

    # Telegram Web JA3
    "a68476b5456580a50a6554826392776c": {"app": "Telegram Web", "type": "Messenger", "version": "web"},
}

# Telegram IP ranges (updated with more addresses)
TELEGRAM_IP_RANGES = [
    "149.154.160.0/20",
    "149.154.164.0/22",
    "91.108.4.0/22",
    "91.108.8.0/22",
    "91.108.12.0/22",
    "91.108.16.0/22",
    "91.108.20.0/22",
    "91.108.56.0/22",
    "95.161.64.0/20",
    "91.105.192.0/23",  # Additional Telegram ranges
    "91.105.194.0/23",
]

TELEGRAM_IPS = [
    "149.154.167.41", "149.154.167.50", "149.154.167.51", "149.154.167.91",
    "149.154.167.92", "149.154.167.93", "149.154.167.99", "149.154.167.151",
    "149.154.175.50", "149.154.175.100", "149.154.174.200",
    "91.108.56.100", "91.108.56.101", "91.108.56.102",
    "91.108.56.103", "91.108.56.104", "91.108.56.105",
    "91.105.192.100", "91.105.192.101",
]

TELEGRAM_DOMAINS = [
    "telegram.org", "tdesktop.com", "telegram.dog", "t.me", "telegra.ph",
    "telesco.pe", "tg.dev", "mytelegram.org", "contest.com", "cdn.telegram.org",
    "web.telegram.org", "zws1.web.telegram.org", "zws2.web.telegram.org",
    "zws2-1.web.telegram.org", "zws3.web.telegram.org", "zws4.web.telegram.org",
]

# Yandex IP ranges
YANDEX_IP_RANGES = [
    "77.88.0.0/18",
    "87.250.224.0/19",
    "93.158.128.0/18",
    "213.180.192.0/19",
    "5.45.192.0/21",
    "95.108.128.0/17",
]

YANDEX_DOMAINS = [
    "yandex.ru", "yandex.com", "yandex.net", "yandex.ua", "yandex.kz", "yandex.by",
    "ya.ru", "yandex.st", "yastatic.net", "yandexadexchange.net", "yandexadsystem.com",
    "yandexvideo.com", "yandexmusic.com", "yandexmaps.com", "yandexcloud.ru",
    "yandex360.ru", "yandexsearch.com", "yandexmail.com", "yandexdisk.com",
    "maps.yandex.ru", "music.yandex.ru", "mail.yandex.ru", "cloud.yandex.ru",
    "market.yandex.ru", "kinopoisk.ru", "zen.yandex.ru", "csp.yandex.net",
    "mc.yandex.ru", "adfox.ru", "ads.adfox.ru", "static-mon.yandex.net",
    "core-renderer-tiles.maps.yandex.ru", "surveys.yandex.ru", "cloud-api.yandex.ru",
    "dr.yandex.net", "avatars.mds.yandex.net", "frontend.vh.yandex.ru"
]


def ip_in_range(ip, ip_ranges):
    """Check if IP belongs to any of the given ranges"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        for network in ip_ranges:
            if ip_obj in ipaddress.ip_network(network, strict=False):
                return True
    except Exception:
        pass
    return False


def ip_in_telegram_range(ip):
    """Check if IP belongs to Telegram"""
    return ip in TELEGRAM_IPS or ip_in_range(ip, TELEGRAM_IP_RANGES)


def ip_in_yandex_range(ip):
    """Check if IP belongs to Yandex"""
    return ip_in_range(ip, YANDEX_IP_RANGES)


def calculate_ja3(client_hello_data):
    """Calculate JA3 fingerprint from ClientHello data"""
    try:
        if not client_hello_data or len(client_hello_data) < 5:
            return None

        data = client_hello_data
        pos = 4

        if pos + 2 > len(data):
            return None
        ssl_version = data[pos:pos + 2].hex()
        pos += 2

        if pos + 32 > len(data):
            return None
        pos += 32

        if pos + 1 > len(data):
            return None
        session_id_len = data[pos]
        pos += 1
        if pos + session_id_len > len(data):
            return None
        pos += session_id_len

        if pos + 2 > len(data):
            return None
        cipher_suites_len = (data[pos] << 8) + data[pos + 1]
        pos += 2
        cipher_suites = []
        if pos + cipher_suites_len <= len(data):
            for i in range(0, cipher_suites_len, 2):
                if i + 2 <= cipher_suites_len:
                    cs = data[pos + i:pos + i + 2].hex()
                    cipher_suites.append(cs)
        pos += cipher_suites_len

        if pos + 1 > len(data):
            return None
        compression_len = data[pos]
        pos += 1
        if pos + compression_len > len(data):
            return None
        pos += compression_len

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
            'ja3_hash': ja3_hash,
            'ja3_string': ja3_string[:200] + "..." if len(ja3_string) > 200 else ja3_string,
            'cipher_suites_count': len(cipher_suites),
            'extensions_count': len(extensions),
            'elliptic_curves': elliptic_curves[:5],
            'has_ech': 0xfe0d in extensions,
            'has_grease': any(0x1a1a <= e <= 0xffff and e % 0x1a1a == 0 for e in extensions)
        }

    except Exception:
        return None


def identify_by_ip(src_ip, dst_ip):
    """Identify application by IP address"""
    if ip_in_telegram_range(src_ip) or ip_in_telegram_range(dst_ip):
        return {"app": "Telegram", "type": "Messenger", "detected_by": "IP"}
    if ip_in_yandex_range(src_ip) or ip_in_yandex_range(dst_ip):
        return {"app": "Yandex", "type": "Service", "detected_by": "IP"}
    return None


def identify_yandex_service(sni_lower):
    """Identify specific Yandex service"""
    if "cloud-api" in sni_lower or "cloud.yandex" in sni_lower:
        return {"app": "Yandex Cloud", "type": "Cloud", "detected_by": "SNI"}
    elif "maps" in sni_lower:
        return {"app": "Yandex Maps", "type": "Maps", "detected_by": "SNI"}
    elif "music" in sni_lower:
        return {"app": "Yandex Music", "type": "Streaming", "detected_by": "SNI"}
    elif "mail" in sni_lower:
        return {"app": "Yandex Mail", "type": "Email", "detected_by": "SNI"}
    elif "disk" in sni_lower:
        return {"app": "Yandex Disk", "type": "Cloud", "detected_by": "SNI"}
    elif "market" in sni_lower:
        return {"app": "Yandex Market", "type": "Shopping", "detected_by": "SNI"}
    elif "zen" in sni_lower:
        return {"app": "Yandex Zen", "type": "Content", "detected_by": "SNI"}
    elif "kinopoisk" in sni_lower:
        return {"app": "Kinopoisk", "type": "Streaming", "detected_by": "SNI"}
    elif "static" in sni_lower or "yastatic" in sni_lower:
        return {"app": "Yandex CDN", "type": "Content Delivery", "detected_by": "SNI"}
    else:
        return {"app": "Yandex", "type": "Service", "detected_by": "SNI"}


def identify_app_by_sni(sni):
    """Identify application by SNI domain"""
    if not sni:
        return None

    sni_lower = sni.lower()

    for domain in YANDEX_DOMAINS:
        if domain in sni_lower:
            return identify_yandex_service(sni_lower)

    for domain in TELEGRAM_DOMAINS:
        if domain in sni_lower:
            return {"app": "Telegram", "type": "Messenger", "detected_by": "SNI"}

    if "telegram" in sni_lower:
        return {"app": "Telegram", "type": "Messenger", "detected_by": "SNI"}
    elif "vk.com" in sni_lower or "vkontakte" in sni_lower:
        return {"app": "VK", "type": "Social", "detected_by": "SNI"}
    elif "discord" in sni_lower or "discordapp" in sni_lower:
        return {"app": "Discord", "type": "Messenger", "detected_by": "SNI"}
    elif "whatsapp" in sni_lower:
        return {"app": "WhatsApp", "type": "Messenger", "detected_by": "SNI"}
    elif "spotify" in sni_lower:
        return {"app": "Spotify", "type": "Streaming", "detected_by": "SNI"}
    elif "netflix" in sni_lower:
        return {"app": "Netflix", "type": "Streaming", "detected_by": "SNI"}
    elif "twitch" in sni_lower:
        return {"app": "Twitch", "type": "Streaming", "detected_by": "SNI"}
    elif "youtube" in sni_lower or "googlevideo" in sni_lower:
        return {"app": "YouTube", "type": "Streaming", "detected_by": "SNI"}
    elif "steam" in sni_lower:
        return {"app": "Steam", "type": "Gaming", "detected_by": "SNI"}
    elif "google" in sni_lower:
        return {"app": "Google", "type": "Service", "detected_by": "SNI"}
    elif "microsoft" in sni_lower or "bing" in sni_lower:
        return {"app": "Microsoft", "type": "Service", "detected_by": "SNI"}
    elif "github" in sni_lower:
        return {"app": "GitHub", "type": "Development", "detected_by": "SNI"}

    return None


def identify_app_by_features(ja3_info, sni, src_ip, dst_ip):
    """Identify application by behavioral features"""
    ip_app = identify_by_ip(src_ip, dst_ip)
    if ip_app:
        return ip_app

    if not ja3_info:
        return None

    if ja3_info['has_grease'] and ja3_info['cipher_suites_count'] == 16:
        if sni and "yandex" in sni.lower():
            return {"app": "Yandex Browser", "type": "Browser", "detected_by": "features"}
        elif sni and ("google" in sni.lower() or "youtube" in sni.lower()):
            return {"app": "Chrome", "type": "Browser", "detected_by": "features"}
        elif sni and ("microsoft" in sni.lower() or "bing" in sni.lower()):
            return {"app": "Edge", "type": "Browser", "detected_by": "features"}
        elif sni and "firefox" in sni.lower():
            return {"app": "Firefox", "type": "Browser", "detected_by": "features"}
        else:
            return {"app": "Chromium Browser", "type": "Browser", "detected_by": "features"}

    if ja3_info['has_ech']:
        if sni and ("cdn" in sni.lower() or "static" in sni.lower()):
            return {"app": "CDN Content", "type": "Content Delivery", "detected_by": "features"}
        elif ip_in_yandex_range(src_ip) or ip_in_yandex_range(dst_ip):
            return {"app": "Yandex Service", "type": "Service", "detected_by": "features"}
        else:
            return {"app": "Modern Application", "type": "Application", "detected_by": "features"}

    return None


def get_app_info(ja3_hash, ja3_info, sni, src_ip, dst_ip):
    """Get application information using all available methods"""
    ip_app = identify_by_ip(src_ip, dst_ip)
    if ip_app:
        return ip_app

    if ja3_hash in KNOWN_JA3_FINGERPRINTS:
        return KNOWN_JA3_FINGERPRINTS[ja3_hash]

    app_by_sni = identify_app_by_sni(sni)
    if app_by_sni:
        return app_by_sni

    app_by_features = identify_app_by_features(ja3_info, sni, src_ip, dst_ip)
    if app_by_features:
        return app_by_features

    return {"app": "Other", "type": "Other", "detected_by": "none"}


def parse_tls_records_from_stream(data, max_records=100):
    """Parse TLS records from stream data"""
    records = []
    pos = 0
    data_len = len(data)
    records_count = 0

    while pos < data_len and records_count < max_records:
        while pos < data_len and data[pos] not in [TLS_HANDSHAKE, TLS_APPLICATION_DATA]:
            pos += 1

        if pos + 5 > data_len:
            break

        record_len = struct.unpack('>H', data[pos + 3:pos + 5])[0]

        if record_len > 0 and record_len <= 16384:
            if pos + 5 + record_len <= data_len:
                record_data = data[pos:pos + 5 + record_len]
                records.append(record_data)
                pos += 5 + record_len
                records_count += 1
            else:
                break
        else:
            pos += 1

    return records


def find_client_hello_in_stream(stream_data):
    """Find ClientHello message in stream data"""
    search_limit = min(len(stream_data), 20000)
    search_data = stream_data[:search_limit]

    tls_records = parse_tls_records_from_stream(search_data)

    for record in tls_records:
        if len(record) < 5:
            continue

        record_data = record[5:]
        pos = 0

        while pos + 4 <= len(record_data):
            msg_type = record_data[pos]
            msg_len = struct.unpack('>I', b'\x00' + record_data[pos + 1:pos + 4])[0]

            if pos + 4 + msg_len <= len(record_data):
                if msg_type == TLS_CLIENT_HELLO:
                    msg_data = record_data[pos:pos + 4 + msg_len]
                    return msg_data
                pos += 4 + msg_len
            else:
                break

    return None


def parse_client_hello_extensions(client_hello_data):
    """Parse extensions from ClientHello message"""
    if len(client_hello_data) < 5 or client_hello_data[0] != TLS_CLIENT_HELLO:
        return None

    data = client_hello_data[4:]
    pos = 0

    if pos + 2 > len(data):
        return None
    pos += 2

    if pos + 32 > len(data):
        return None
    pos += 32

    if pos + 1 > len(data):
        return None
    session_id_len = data[pos]
    pos += 1
    if pos + session_id_len > len(data):
        return None
    pos += session_id_len

    if pos + 2 > len(data):
        return None
    cipher_suites_len = struct.unpack('>H', data[pos:pos + 2])[0]
    pos += 2
    if pos + cipher_suites_len > len(data):
        return None
    pos += cipher_suites_len

    if pos + 1 > len(data):
        return None
    compression_len = data[pos]
    pos += 1
    if pos + compression_len > len(data):
        return None
    pos += compression_len

    if pos + 2 > len(data):
        return None
    extensions_len = struct.unpack('>H', data[pos:pos + 2])[0]
    pos += 2

    extensions = {}
    end = pos + extensions_len
    max_extensions = 50
    ext_count = 0

    while pos + 4 <= end and ext_count < max_extensions:
        ext_type = struct.unpack('>H', data[pos:pos + 2])[0]
        ext_len = struct.unpack('>H', data[pos + 2:pos + 4])[0]

        if pos + 4 + ext_len <= end:
            ext_data = data[pos + 4:pos + 4 + ext_len]
            extensions[ext_type] = ext_data

        pos += 4 + ext_len
        ext_count += 1

    return extensions


def extract_sni(extensions):
    """Extract SNI from extensions"""
    if TLS_EXTENSION_SERVER_NAME not in extensions:
        return None

    ext_data = extensions[TLS_EXTENSION_SERVER_NAME]

    if len(ext_data) < 5:
        return None

    pos = 0
    pos += 2

    if pos + 3 > len(ext_data):
        return None

    if ext_data[pos] != 0x00:
        return None
    pos += 1

    name_len = struct.unpack('>H', ext_data[pos:pos + 2])[0]
    pos += 2

    if pos + name_len <= len(ext_data):
        try:
            sni = ext_data[pos:pos + name_len].decode('utf-8', errors='ignore')
            if sni and '.' in sni and len(sni) > 3:
                return sni
        except:
            pass

    return None


def has_ech(extensions):
    """Check if ECH extension is present"""
    return TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO in extensions


def get_ech_config_id(extensions):
    """Get ECH config ID if present"""
    if TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO not in extensions:
        return None

    ech_data = extensions[TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO]
    if len(ech_data) >= 8:
        return ech_data[:8].hex()
    return None


class TCPStreamReassembler:
    """Reassemble TCP streams from packets"""

    def __init__(self):
        self.streams = defaultdict(list)
        self.stream_sizes = defaultdict(int)

    def add_packet(self, src_ip, dst_ip, src_port, dst_port, seq, data):
        key = tuple(sorted([(src_ip, src_port), (dst_ip, dst_port)]))

        if len(self.streams[key]) > MAX_PACKETS_PER_STREAM:
            return

        self.streams[key].append((seq, data))
        self.stream_sizes[key] += len(data)

    def get_reassembled_stream(self, key):
        if key not in self.streams:
            return None

        if self.stream_sizes[key] > MAX_STREAM_SIZE:
            return None

        sorted_packets = sorted(self.streams[key], key=lambda x: x[0])

        stream_data = bytearray()
        last_seq = None

        for seq, data in sorted_packets:
            if last_seq is None:
                stream_data.extend(data)
                last_seq = seq + len(data)
            else:
                if seq > last_seq:
                    gap = seq - last_seq
                    if gap < 1000000:
                        stream_data.extend(b'\x00' * min(gap, 10000))
                    stream_data.extend(data)
                    last_seq = seq + len(data)
                elif seq < last_seq:
                    overlap = last_seq - seq
                    if overlap < len(data):
                        stream_data.extend(data[overlap:])
                    last_seq = max(last_seq, seq + len(data))
                else:
                    stream_data.extend(data)
                    last_seq = seq + len(data)

        return bytes(stream_data[:MAX_STREAM_SIZE])


def analyze_stream_telegram_by_ip(stream_key, stats):
    """Analyze stream for Telegram detection by IP even without ClientHello"""
    ip1, ip2 = stream_key[0][0], stream_key[1][0]

    if ip_in_telegram_range(ip1) or ip_in_telegram_range(ip2):
        return {"app": "Telegram", "type": "Messenger", "detected_by": "IP"}
    return None


def analyze_pcap(filename):
    """Main analysis function"""
    print(f"Reading {filename}...")
    pkts = rdpcap(filename)

    reassembler = TCPStreamReassembler()

    print("Building TCP streams...")
    for pkt in pkts:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            continue

        if pkt[TCP].dport == 443 or pkt[TCP].sport == 443:
            payload = bytes(pkt[Raw])
            if payload:
                reassembler.add_packet(
                    pkt[IP].src, pkt[IP].dst,
                    pkt[TCP].sport, pkt[TCP].dport,
                    pkt[TCP].seq, payload
                )

    print(f"Found {len(reassembler.streams)} TCP streams on port 443")
    print("=" * 90)
    print("TLS SNI/ECH ANALYSIS with Application Detection")
    print("=" * 90)

    stats = {
        'total_streams': 0,
        'ech_streams': 0,
        'sni_streams': 0,
        'no_sni_streams': 0,
        'no_clienthello': 0,
        'telegram_streams': 0,
        'yandex_streams': 0,
        'detected_by_ip': 0,
        'detected_by_sni': 0,
        'detected_by_ja3': 0,
        'detected_by_features': 0
    }

    domains = Counter()
    app_stats = Counter()
    type_stats = Counter()
    detection_methods = Counter()

    for stream_key, packets in reassembler.streams.items():
        stream_data = reassembler.get_reassembled_stream(stream_key)

        if not stream_data or len(stream_data) < 50:
            continue

        stats['total_streams'] += 1

        ip1, ip2 = stream_key[0][0], stream_key[1][0]
        port1, port2 = stream_key[0][1], stream_key[1][1]

        print(f"\n[Stream {stats['total_streams']}] {ip1}:{port1} <-> {ip2}:{port2}")
        print(f"  Size: {len(stream_data)} bytes")

        client_hello = find_client_hello_in_stream(stream_data)

        app_info = None
        ja3_info = None
        sni = None

        if client_hello is None:
            print(f"  No ClientHello found")
            stats['no_clienthello'] += 1

            # Try to identify by IP even without ClientHello
            app_info = analyze_stream_telegram_by_ip(stream_key, stats)
            if app_info:
                print(f"  Application: {app_info['app']} [{app_info['type']}] (detected by: {app_info['detected_by']})")
                app_stats[app_info['app']] += 1
                type_stats[app_info['type']] += 1
                detection_methods[app_info['detected_by']] += 1

                if app_info['app'] == "Telegram":
                    stats['telegram_streams'] += 1
                    stats['detected_by_ip'] += 1
            continue

        extensions = parse_client_hello_extensions(client_hello)

        if extensions is None:
            print(f"  Failed to parse extensions")
            continue

        sni = extract_sni(extensions)
        ja3_info = calculate_ja3(client_hello)

        if ja3_info:
            app_info = get_app_info(ja3_info['ja3_hash'], ja3_info, sni, ip1, ip2)

            detected_by = app_info.get('detected_by', 'none')
            if detected_by != 'none':
                detection_methods[detected_by] += 1

                if app_info['app'] == "Telegram":
                    stats['telegram_streams'] += 1
                    if detected_by == 'IP':
                        stats['detected_by_ip'] += 1
                    elif detected_by == 'SNI':
                        stats['detected_by_sni'] += 1
                    elif detected_by == 'JA3':
                        stats['detected_by_ja3'] += 1
                    elif detected_by == 'features':
                        stats['detected_by_features'] += 1

                if "Yandex" in app_info['app']:
                    stats['yandex_streams'] += 1

            print(f"  JA3: {ja3_info['ja3_hash']}")
            print(f"  Application: {app_info['app']} [{app_info['type']}] (detected by: {detected_by})")

            app_stats[app_info['app']] += 1
            type_stats[app_info['type']] += 1

            print(f"  Cipher Suites: {ja3_info['cipher_suites_count']}")
            print(f"  Extensions: {ja3_info['extensions_count']}")
            if ja3_info['elliptic_curves']:
                curves = [f"0x{curve:04x}" for curve in ja3_info['elliptic_curves'][:3]]
                print(f"  Curves: {', '.join(curves)}")
            if ja3_info['has_grease']:
                print(f"  GREASE: Yes")
            if ja3_info['has_ech']:
                print(f"  ECH: Yes")
        else:
            print(f"  Could not calculate JA3")

        if extensions:
            ext_types = sorted(extensions.keys())
            ext_names = []
            for t in ext_types[:10]:
                if t == 0:
                    ext_names.append("SNI")
                elif t == 0xfe0d:
                    ext_names.append("ECH")
                elif t == 0x2b:
                    ext_names.append("supported_versions")
                elif t == 0x33:
                    ext_names.append("key_share")
                else:
                    ext_names.append(f"0x{t:04x}")

            print(f"  Extensions: {', '.join(ext_names)}")

            if has_ech(extensions):
                stats['ech_streams'] += 1
                config_id = get_ech_config_id(extensions)
                print(f"  ECH DETECTED (Config ID: {config_id})")

        if sni:
            stats['sni_streams'] += 1
            print(f"  SNI: {sni}")
            domains[sni] += 1
        else:
            if extensions and not has_ech(extensions):
                stats['no_sni_streams'] += 1
                print(f"  No SNI found")

    print("\n" + "=" * 90)
    print("FINAL STATISTICS")
    print("=" * 90)

    if stats['total_streams'] > 0:
        print(f"Total TCP streams:              {stats['total_streams']}")
        print(
            f"├─ With ECH:                    {stats['ech_streams']} ({stats['ech_streams'] / stats['total_streams'] * 100:.1f}%)")
        print(
            f"├─ With clear-text SNI:         {stats['sni_streams']} ({stats['sni_streams'] / stats['total_streams'] * 100:.1f}%)")
        print(
            f"├─ Without SNI (no ECH):        {stats['no_sni_streams']} ({stats['no_sni_streams'] / stats['total_streams'] * 100:.1f}%)")
        print(
            f"└─ No ClientHello:              {stats['no_clienthello']} ({stats['no_clienthello'] / stats['total_streams'] * 100:.1f}%)")

        if stats['telegram_streams'] > 0:
            print(
                f"\nTelegram Streams:               {stats['telegram_streams']} ({stats['telegram_streams'] / stats['total_streams'] * 100:.1f}%)")
            print(
                f"├─ Detected by IP:              {stats['detected_by_ip']} ({stats['detected_by_ip'] / stats['telegram_streams'] * 100:.1f}%)")
            print(
                f"├─ Detected by SNI:             {stats['detected_by_sni']} ({stats['detected_by_sni'] / stats['telegram_streams'] * 100:.1f}%)")
            print(
                f"├─ Detected by JA3:             {stats['detected_by_ja3']} ({stats['detected_by_ja3'] / stats['telegram_streams'] * 100:.1f}%)")
            print(
                f"└─ Detected by features:        {stats['detected_by_features']} ({stats['detected_by_features'] / stats['telegram_streams'] * 100:.1f}%)")

        if stats['yandex_streams'] > 0:
            print(
                f"\nYandex Streams:                 {stats['yandex_streams']} ({stats['yandex_streams'] / stats['total_streams'] * 100:.1f}%)")

    if domains:
        print("\n" + "=" * 90)
        print("TOP DOMAINS")
        print("=" * 90)
        for domain, count in domains.most_common(15):
            print(f"  {domain:<50} {count:>4}")

    if type_stats:
        print("\n" + "=" * 90)
        print("APPLICATION TYPE STATISTICS")
        print("=" * 90)
        for app_type, count in type_stats.most_common():
            print(f"  {app_type:<20} {count:>4}")

    if app_stats:
        print("\n" + "=" * 90)
        print("APPLICATION STATISTICS")
        print("=" * 90)
        for app, count in app_stats.most_common(20):
            print(f"  {app:<35} {count:>4}")

    if detection_methods:
        print("\n" + "=" * 90)
        print("DETECTION METHODS")
        print("=" * 90)
        for method, count in detection_methods.most_common():
            print(f"  {method:<15} {count:>4}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tls_analyzer.py <pcap_file>")
        sys.exit(1)

    analyze_pcap(sys.argv[1])