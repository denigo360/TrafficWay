#!/usr/bin/env python3
"""
Multi-Protocol Traffic Analyzer with Application Detection
Supports: TLS/HTTPS, SSH, HTTP, DNS, Telnet, UDP-Lite
Features: JA3 fingerprinting, ECH detection, DPI evasion detection
"""

from scapy.all import rdpcap, Raw, IP, TCP, UDP
import sys
from collections import Counter, defaultdict
import struct
import hashlib
import ipaddress
import re

# ============================================================================
# Constants
# ============================================================================

IPPROTO_UDPLITE = 136

TLS_HANDSHAKE = 0x16
TLS_APPLICATION_DATA = 0x17
TLS_CLIENT_HELLO = 0x01
TLS_EXTENSION_SERVER_NAME = 0x0000
TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO = 0xfe0d

SSH_PORT = 22
SSH_PROTOCOL_STRING = b"SSH-"

HTTP_PORTS = [80, 8080, 8000, 8888]
HTTP_METHODS = [b"GET", b"POST", b"HEAD", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"CONNECT"]
HTTP_VERSION = [b"HTTP/1.0", b"HTTP/1.1", b"HTTP/2.0", b"HTTP/3"]

DNS_PORT = 53
DNS_HEADER_SIZE = 12
DNS_QTYPE_MAP = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV"
}

TELNET_PORTS = [23, 2323]
TELNET_IAC = 0xFF
TELNET_OPTIONS = {
    0x01: "ECHO", 0x03: "SUPPRESS_GO_AHEAD", 0x18: "TERMINAL_TYPE",
    0x1F: "NAWS", 0x20: "TERMINAL_SPEED", 0x22: "LINEMODE"
}

MAX_STREAM_SIZE = 100 * 1024 * 1024
MAX_PACKETS_PER_STREAM = 1000

# ============================================================================
# Known fingerprints databases
# ============================================================================

KNOWN_JA3_FINGERPRINTS = {
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
    "a68476b5456580a50a6554826392776c": {"app": "Telegram Web", "type": "Messenger", "version": "web"},
}

KNOWN_SSH_CLIENTS = {
    b"OpenSSH": {"app": "OpenSSH Client", "type": "SSH Client"},
    b"PuTTY": {"app": "PuTTY", "type": "SSH Client"},
    b"SecureCRT": {"app": "SecureCRT", "type": "SSH Client"},
    b"libssh": {"app": "libssh", "type": "SSH Library"},
    b"paramiko": {"app": "Paramiko", "type": "SSH Library"},
}

KNOWN_SSH_SERVERS = {
    b"OpenSSH": {"app": "OpenSSH Server", "type": "SSH Server"},
    b"Dropbear": {"app": "Dropbear Server", "type": "SSH Server"},
}

# Telegram IP ranges
TELEGRAM_IP_RANGES = [
    "149.154.160.0/20", "149.154.164.0/22", "91.108.4.0/22",
    "91.108.8.0/22", "91.108.12.0/22", "91.108.16.0/22",
    "91.108.20.0/22", "91.108.56.0/22", "95.161.64.0/20",
    "91.105.192.0/23", "91.105.194.0/23",
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
    "77.88.0.0/18", "87.250.224.0/19", "93.158.128.0/18",
    "213.180.192.0/19", "5.45.192.0/21", "95.108.128.0/17",
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


# ============================================================================
# IP helper functions
# ============================================================================

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
    return ip in TELEGRAM_IPS or ip_in_range(ip, TELEGRAM_IP_RANGES)


def ip_in_yandex_range(ip):
    return ip_in_range(ip, YANDEX_IP_RANGES)


def identify_by_ip(src_ip, dst_ip):
    """Identify application by IP address"""
    if ip_in_telegram_range(src_ip) or ip_in_telegram_range(dst_ip):
        return {"app": "Telegram", "type": "Messenger", "detected_by": "IP"}
    if ip_in_yandex_range(src_ip) or ip_in_yandex_range(dst_ip):
        return {"app": "Yandex", "type": "Service", "detected_by": "IP"}
    return None


# ============================================================================
# HTTP detection
# ============================================================================

def detect_http(data):
    """Detect HTTP traffic and extract info"""
    if not data or len(data) < 10:
        return None

    try:
        for method in HTTP_METHODS:
            if data.startswith(method):
                end_idx = data.find(b'\r\n')
                if end_idx == -1:
                    end_idx = data.find(b'\n')
                if end_idx != -1:
                    request_line = data[:end_idx].decode('ascii', errors='ignore')
                    parts = request_line.split(' ')
                    if len(parts) >= 2:
                        return {
                            "app": "HTTP Request",
                            "type": "HTTP",
                            "method": parts[0],
                            "path": parts[1],
                            "version": parts[2] if len(parts) > 2 else "HTTP/1.1"
                        }

        for version in HTTP_VERSION:
            if data.startswith(version):
                end_idx = data.find(b'\r\n')
                if end_idx == -1:
                    end_idx = data.find(b'\n')
                if end_idx != -1:
                    status_line = data[:end_idx].decode('ascii', errors='ignore')
                    parts = status_line.split(' ')
                    if len(parts) >= 2:
                        return {
                            "app": "HTTP Response",
                            "type": "HTTP",
                            "version": parts[0],
                            "status_code": parts[1],
                            "status_text": ' '.join(parts[2:]) if len(parts) > 2 else ""
                        }

        if b"Host:" in data[:500]:
            match = re.search(rb'Host:\s*([^\r\n]+)', data[:500])
            if match:
                host = match.group(1).decode('ascii', errors='ignore')
                return {
                    "app": "HTTP",
                    "type": "HTTP",
                    "host": host,
                    "detected_by": "Host Header"
                }
    except Exception:
        pass

    return None


# ============================================================================
# DNS detection
# ============================================================================

def decode_dns_name(data, pos):
    """Decode DNS name with support for compression pointers"""
    labels = []
    jumped = False
    jump_pos = pos
    original_pos = pos

    try:
        while True:
            if jump_pos >= len(data):
                return None, pos + 1 if not jumped else original_pos + 2

            label_len = data[jump_pos]

            if label_len & 0xC0:
                if not jumped:
                    offset = ((label_len & 0x3F) << 8) | data[jump_pos + 1]
                    jump_pos = offset
                    jumped = True
                else:
                    break
                continue

            if label_len == 0:
                jump_pos += 1
                break

            jump_pos += 1
            if jump_pos + label_len > len(data):
                return None, pos + 1 if not jumped else original_pos + 2

            label = data[jump_pos:jump_pos + label_len].decode('ascii', errors='ignore')
            labels.append(label)
            jump_pos += label_len

        name = '.'.join(labels)
        return name, jump_pos if not jumped else original_pos + 2
    except Exception:
        return None, pos + 1


def detect_dns(data):
    """Detect DNS traffic and extract info"""
    if not data or len(data) < DNS_HEADER_SIZE:
        return None

    try:
        transaction_id = struct.unpack('>H', data[:2])[0]
        flags = struct.unpack('>H', data[2:4])[0]
        qdcount = struct.unpack('>H', data[4:6])[0]

        qr = (flags >> 15) & 1

        if 0 < qdcount < 10:
            pos = DNS_HEADER_SIZE
            query_name, pos = decode_dns_name(data, pos)

            if query_name and pos + 4 <= len(data):
                qtype = struct.unpack('>H', data[pos:pos + 2])[0]
                qtype_name = DNS_QTYPE_MAP.get(qtype, f"TYPE{qtype}")

                return {
                    "app": "DNS",
                    "type": "DNS",
                    "qr": "Response" if qr else "Query",
                    "domain": query_name,
                    "query_type": qtype_name,
                    "transaction_id": transaction_id
                }
    except Exception:
        pass

    return None


# ============================================================================
# Telnet detection
# ============================================================================

def detect_telnet(data):
    """Detect Telnet traffic"""
    if not data or len(data) < 3:
        return None

    try:
        for i in range(len(data) - 2):
            if data[i] == TELNET_IAC:
                cmd = data[i + 1] if i + 1 < len(data) else 0
                opt = data[i + 2] if i + 2 < len(data) else 0
                if cmd in [0xFB, 0xFC, 0xFD, 0xFE]:
                    opt_name = TELNET_OPTIONS.get(opt, f"UNKNOWN({opt})")
                    return {
                        "app": "Telnet",
                        "type": "Telnet",
                        "detected_by": "Option Negotiation",
                        "option": opt_name
                    }

        telnet_prompts = [b"login:", b"username:", b"password:", b"> ", b"$ ", b"# "]
        data_lower = data[:200].lower()
        for prompt in telnet_prompts:
            if prompt in data_lower:
                return {
                    "app": "Telnet",
                    "type": "Telnet",
                    "detected_by": "Login Prompt",
                    "prompt": prompt.decode('ascii', errors='ignore')
                }
    except Exception:
        pass

    return None


# ============================================================================
# SSH detection
# ============================================================================

def detect_ssh_banner(data):
    """Detect SSH banner in data and return application info"""
    try:
        if not data or len(data) < 4:
            return None

        ssh_pos = data.find(b'SSH-')
        if ssh_pos == -1:
            return None

        banner_data = data[ssh_pos:ssh_pos + 255]

        if not banner_data.startswith(b'SSH-'):
            return None

        version_end = banner_data.find(b'-', 4)
        if version_end == -1:
            return None

        version = banner_data[4:version_end].decode('ascii', errors='ignore')

        software_start = version_end + 1
        software_end = software_start
        while software_end < len(banner_data) and banner_data[software_end] not in (ord('\r'), ord('\n')):
            software_end += 1

        if software_start >= software_end:
            return None

        software = banner_data[software_start:software_end].decode('ascii', errors='ignore')
        software = software.strip()

        app_name = None
        for client_key, info in KNOWN_SSH_CLIENTS.items():
            if client_key.lower() in software.lower():
                app_name = info["app"]
                break

        if not app_name:
            for server_key, info in KNOWN_SSH_SERVERS.items():
                if server_key.lower() in software.lower():
                    app_name = info["app"]
                    break

        if not app_name:
            app_name = f"SSH ({software})"

        return {
            "app": app_name,
            "type": "SSH",
            "detected_by": "SSH Banner",
            "ssh_version": version,
            "ssh_software": software
        }
    except Exception:
        pass

    return None


# ============================================================================
# TLS/JA3 detection
# ============================================================================

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

        if 0 < record_len <= 16384:
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
                    return record_data[pos:pos + 4 + msg_len]
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

    pos = 2

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
    return TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO in extensions


def get_ech_config_id(extensions):
    if TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO not in extensions:
        return None
    ech_data = extensions[TLS_EXTENSION_ENCRYPTED_CLIENT_HELLO]
    if len(ech_data) >= 8:
        return ech_data[:8].hex()
    return None


def identify_yandex_service(sni_lower):
    """Identify specific Yandex service"""
    if "cloud-api" in sni_lower or "cloud.yandex" in sni_lower:
        return {"app": "Yandex Cloud", "type": "Cloud"}
    elif "maps" in sni_lower:
        return {"app": "Yandex Maps", "type": "Maps"}
    elif "music" in sni_lower:
        return {"app": "Yandex Music", "type": "Streaming"}
    elif "mail" in sni_lower:
        return {"app": "Yandex Mail", "type": "Email"}
    elif "disk" in sni_lower:
        return {"app": "Yandex Disk", "type": "Cloud"}
    elif "market" in sni_lower:
        return {"app": "Yandex Market", "type": "Shopping"}
    elif "zen" in sni_lower:
        return {"app": "Yandex Zen", "type": "Content"}
    elif "kinopoisk" in sni_lower:
        return {"app": "Kinopoisk", "type": "Streaming"}
    elif "static" in sni_lower or "yastatic" in sni_lower:
        return {"app": "Yandex CDN", "type": "Content Delivery"}
    else:
        return {"app": "Yandex", "type": "Service"}


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
            return {"app": "Telegram", "type": "Messenger"}

    if "telegram" in sni_lower:
        return {"app": "Telegram", "type": "Messenger"}
    elif "vk.com" in sni_lower or "vkontakte" in sni_lower:
        return {"app": "VK", "type": "Social"}
    elif "discord" in sni_lower or "discordapp" in sni_lower:
        return {"app": "Discord", "type": "Messenger"}
    elif "whatsapp" in sni_lower:
        return {"app": "WhatsApp", "type": "Messenger"}
    elif "spotify" in sni_lower:
        return {"app": "Spotify", "type": "Streaming"}
    elif "netflix" in sni_lower:
        return {"app": "Netflix", "type": "Streaming"}
    elif "twitch" in sni_lower:
        return {"app": "Twitch", "type": "Streaming"}
    elif "youtube" in sni_lower or "googlevideo" in sni_lower:
        return {"app": "YouTube", "type": "Streaming"}
    elif "steam" in sni_lower:
        return {"app": "Steam", "type": "Gaming"}
    elif "google" in sni_lower:
        return {"app": "Google", "type": "Service"}
    elif "microsoft" in sni_lower or "bing" in sni_lower:
        return {"app": "Microsoft", "type": "Service"}
    elif "github" in sni_lower:
        return {"app": "GitHub", "type": "Development"}

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
            return {"app": "Yandex Browser", "type": "Browser"}
        elif sni and ("google" in sni.lower() or "youtube" in sni.lower()):
            return {"app": "Chrome", "type": "Browser"}
        elif sni and ("microsoft" in sni.lower() or "bing" in sni.lower()):
            return {"app": "Edge", "type": "Browser"}
        elif sni and "firefox" in sni.lower():
            return {"app": "Firefox", "type": "Browser"}
        else:
            return {"app": "Chromium Browser", "type": "Browser"}

    if ja3_info['has_ech']:
        if sni and ("cdn" in sni.lower() or "static" in sni.lower()):
            return {"app": "CDN Content", "type": "Content Delivery"}
        elif ip_in_yandex_range(src_ip) or ip_in_yandex_range(dst_ip):
            return {"app": "Yandex Service", "type": "Service"}
        else:
            return {"app": "Modern Application", "type": "Application"}

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

    return {"app": "Other", "type": "Other"}


# ============================================================================
# DPI evasion detection
# ============================================================================

def detect_dpi_evasion(stream_data, ja3_info=None, extensions=None, packet_count=None):
    """Detect DPI evasion techniques"""
    evasion_detected = False
    evasion_type = None
    evasion_details = []

    if not stream_data or len(stream_data) < 50:
        return evasion_detected, evasion_type, evasion_details

    try:
        if b"CONNECT" in stream_data[:200] and b"HTTP/1.1" in stream_data[:200]:
            evasion_detected = True
            evasion_type = "HTTP CONNECT Tunnel"
            evasion_details.append("HTTP proxy tunnel detected")
    except:
        pass

    if packet_count and packet_count > 5:
        avg_packet_size = len(stream_data) / packet_count
        if avg_packet_size < 200:
            evasion_detected = True
            evasion_type = "Packet Fragmentation"
            evasion_details.append(f"High fragmentation: {packet_count} packets, avg {avg_packet_size:.0f} bytes")

    if ja3_info and ja3_info.get('has_grease'):
        cipher_count = ja3_info.get('cipher_suites_count', 0)
        if cipher_count not in [16, 17, 18]:
            evasion_detected = True
            evasion_type = "Spoofed JA3 Fingerprint"
            evasion_details.append(f"Unusual cipher suites count: {cipher_count}")

    if extensions and not extract_sni(extensions):
        if ja3_info and ja3_info.get('has_grease'):
            evasion_detected = True
            evasion_type = "SNI Obfuscation"
            evasion_details.append("SNI missing with GREASE present")

    return evasion_detected, evasion_type, evasion_details


class TCPStreamReassembler:
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
            elif seq > last_seq:
                gap = seq - last_seq
                if gap < 1000000:
                    stream_data.extend(b'\x00' * min(gap, 10000))
                stream_data.extend(data)
                last_seq = seq + len(data)
            elif seq < last_seq:
                overlap = last_seq - seq
                if overlap < len(data):
                    stream_data.extend(data[overlap:])
                    last_seq = seq + len(data)
        return bytes(stream_data[:MAX_STREAM_SIZE])


def process_udp_packet(pkt, udp_streams, udplite_streams):
    if not pkt.haslayer(IP):
        return
    ip_layer = pkt[IP]
    payload = None
    src_port = None
    dst_port = None
    is_udplite = False
    if pkt.haslayer(UDP) and pkt.haslayer(Raw):
        udp = pkt[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        payload = bytes(pkt[Raw])
    elif ip_layer.proto == IPPROTO_UDPLITE and pkt.haslayer(Raw):
        raw_data = bytes(pkt[Raw])
        if len(raw_data) >= 4:
            src_port = struct.unpack('>H', raw_data[:2])[0]
            dst_port = struct.unpack('>H', raw_data[2:4])[0]
            payload = raw_data[8:]
            is_udplite = True
    if payload and src_port and dst_port:
        key = tuple(sorted([(ip_layer.src, src_port), (ip_layer.dst, dst_port)]))
        if is_udplite:
            udplite_streams[key].append(payload)
        else:
            udp_streams[key].append(payload)


def analyze_pcap(filename):
    print(f"Reading {filename}...")
    pkts = rdpcap(filename)

    tcp_reassembler = TCPStreamReassembler()
    udp_streams = defaultdict(list)
    udplite_streams = defaultdict(list)

    print("Building streams...")
    for pkt in pkts:
        if not pkt.haslayer(IP):
            continue
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            tcp = pkt[TCP]
            payload = bytes(pkt[Raw])
            if payload:
                tcp_reassembler.add_packet(
                    pkt[IP].src, pkt[IP].dst,
                    tcp.sport, tcp.dport,
                    tcp.seq, payload
                )
        else:
            process_udp_packet(pkt, udp_streams, udplite_streams)

    print(f"Found {len(tcp_reassembler.streams)} TCP streams, "
          f"{len(udp_streams)} UDP streams, "
          f"{len(udplite_streams)} UDP-Lite streams")
    print("=" * 90)
    print("MULTI-PROTOCOL ANALYSIS (TLS/SSH/HTTP/DNS/Telnet/UDP-Lite)")
    print("=" * 90)

    stats = {
        'total_streams': 0, 'tls_streams': 0, 'ssh_streams': 0,
        'http_streams': 0, 'dns_streams': 0, 'telnet_streams': 0,
        'udplite_streams': 0, 'ech_streams': 0, 'sni_streams': 0,
        'dpi_evasion_detected': 0, 'evasion_types': Counter()
    }

    domains = Counter()
    app_stats = Counter()
    type_stats = Counter()
    detection_methods = Counter()
    stream_counter = 0

    # Analyze TCP streams
    for stream_key, packets in tcp_reassembler.streams.items():
        stream_data = tcp_reassembler.get_reassembled_stream(stream_key)
        if not stream_data or len(stream_data) < 20:
            continue

        stream_counter += 1
        stats['total_streams'] = stream_counter

        ip1, ip2 = stream_key[0][0], stream_key[1][0]
        port1, port2 = stream_key[0][1], stream_key[1][1]

        print(f"\n[{stream_counter}] {ip1}:{port1} <-> {ip2}:{port2}")
        print(f"  Size: {len(stream_data)} bytes")

        packet_count = len(packets)
        detected = False

        # ================================================================
        # SSH DETECTION - DIRECT BANNER CHECK
        # ================================================================
        # Check if data starts with SSH- or contains SSH- somewhere
        ssh_banner_found = False
        ssh_banner_pos = stream_data.find(b'SSH-')

        if ssh_banner_pos != -1:
            # Found SSH banner
            ssh_banner_found = True
            stats['ssh_streams'] += 1

            # Parse the banner
            banner_data = stream_data[ssh_banner_pos:ssh_banner_pos + 100]
            try:
                # Format: SSH-2.0-OpenSSH_8.3\r\n
                dash1 = banner_data.find(b'-', 4)  # after "SSH-"
                if dash1 != -1:
                    version = banner_data[4:dash1].decode('ascii', errors='ignore')
                    dash2 = banner_data.find(b'-', dash1 + 1)
                    if dash2 != -1:
                        # SSH-2.0-OpenSSH_8.3
                        software_end = banner_data.find(b'\r', dash2)
                        if software_end == -1:
                            software_end = banner_data.find(b'\n', dash2)
                        if software_end == -1:
                            software_end = len(banner_data)
                        software = banner_data[dash1 + 1:software_end].decode('ascii', errors='ignore')
                        software = software.strip()
                    else:
                        # Alternative format
                        software_end = banner_data.find(b'\r', dash1)
                        if software_end == -1:
                            software_end = banner_data.find(b'\n', dash1)
                        if software_end == -1:
                            software_end = len(banner_data)
                        software = banner_data[dash1 + 1:software_end].decode('ascii', errors='ignore')
                        version = banner_data[4:dash1].decode('ascii', errors='ignore')
                else:
                    version = "unknown"
                    software_end = banner_data.find(b'\r')
                    if software_end == -1:
                        software_end = banner_data.find(b'\n')
                    if software_end == -1:
                        software_end = len(banner_data)
                    software = banner_data[4:software_end].decode('ascii', errors='ignore')

                print(f"  Application: SSH ({software}) [SSH]")
                print(f"  SSH Version: {version}")
                print(f"  SSH Software: {software}")
                app_stats[f"SSH ({software})"] += 1
                type_stats["SSH"] += 1
                detection_methods['ssh_banner'] += 1
                detected = True
            except Exception as e:
                print(f"  Application: SSH [SSH] (detected by banner, parse error: {e})")
                app_stats["SSH"] += 1
                type_stats["SSH"] += 1
                detection_methods['ssh_banner'] += 1
                detected = True

        # ================================================================
        # HTTP detection
        # ================================================================
        if not detected:
            http_info = detect_http(stream_data[:2000])
            if http_info:
                stats['http_streams'] += 1
                print(f"  Application: {http_info['app']} [{http_info['type']}]")
                if 'method' in http_info:
                    print(f"  HTTP Method: {http_info['method']} {http_info.get('path', '')}")
                if 'host' in http_info:
                    print(f"  Host: {http_info['host']}")
                app_stats[http_info['app']] += 1
                type_stats[http_info['type']] += 1
                detection_methods['http'] += 1
                detected = True

        # ================================================================
        # Telnet detection
        # ================================================================
        if not detected:
            telnet_info = detect_telnet(stream_data[:500])
            if telnet_info:
                stats['telnet_streams'] += 1
                print(f"  Application: {telnet_info['app']} [{telnet_info['type']}]")
                app_stats[telnet_info['app']] += 1
                type_stats[telnet_info['type']] += 1
                detection_methods['telnet'] += 1
                detected = True

        # ================================================================
        # TLS/HTTPS detection
        # ================================================================
        if not detected:
            client_hello = find_client_hello_in_stream(stream_data)
            if client_hello:
                stats['tls_streams'] += 1
                extensions = parse_client_hello_extensions(client_hello)
                sni = extract_sni(extensions) if extensions else None
                ja3_info = calculate_ja3(client_hello)

                if ja3_info:
                    print(f"  JA3: {ja3_info['ja3_hash']}")
                    print(f"  Cipher Suites: {ja3_info['cipher_suites_count']}")
                    if ja3_info['has_grease']:
                        print(f"  GREASE: Yes")
                    if ja3_info['has_ech']:
                        print(f"  ECH: Yes")

                    if sni:
                        if "telegram" in sni.lower():
                            app_info = {"app": "Telegram", "type": "Messenger"}
                        elif "yandex" in sni.lower():
                            app_info = {"app": "Yandex", "type": "Service"}
                        else:
                            app_info = {"app": "HTTPS", "type": "Web"}

                        print(f"  Application: {app_info['app']} [{app_info['type']}]")
                        print(f"  SNI: {sni}")
                        domains[sni] += 1
                        app_stats[app_info['app']] += 1
                        type_stats[app_info['type']] += 1
                        detection_methods['sni'] += 1
                        stats['sni_streams'] += 1

                if extensions and has_ech(extensions):
                    stats['ech_streams'] += 1
                detected = True

        # ================================================================
        # Unknown
        # ================================================================
        if not detected:
            hex_preview = ' '.join(f'{b:02x}' for b in stream_data[:50])
            print(f"  Unknown protocol")
            print(f"  Data preview (hex): {hex_preview}")

    # Analyze UDP streams
    for stream_key, packets in udp_streams.items():
        if not packets:
            continue
        stream_counter += 1
        stats['total_streams'] = stream_counter
        stats['dns_streams'] += 1
        ip1, port1 = stream_key[0]
        ip2, port2 = stream_key[1]
        print(f"\n[{stream_counter}] {ip1}:{port1} <-> {ip2}:{port2} (UDP)")
        dns_info = detect_dns(packets[0]) if packets else None
        if dns_info:
            print(f"  Application: {dns_info['app']} [{dns_info['type']}]")
            app_stats[dns_info['app']] += 1
            type_stats[dns_info['type']] += 1
        else:
            print(f"  Application: UDP Traffic")
            app_stats["UDP"] += 1
            type_stats["UDP"] += 1

    # Analyze UDP-Lite streams
    for stream_key, packets in udplite_streams.items():
        if not packets:
            continue
        stream_counter += 1
        stats['total_streams'] = stream_counter
        stats['udplite_streams'] += 1
        ip1, port1 = stream_key[0]
        ip2, port2 = stream_key[1]
        print(f"\n[{stream_counter}] {ip1}:{port1} <-> {ip2}:{port2} (UDP-Lite)")
        print(f"  Application: UDP-Lite Traffic")
        print(f"  Packets: {len(packets)}")
        app_stats["UDP-Lite"] += 1
        type_stats["UDP-Lite"] += 1

    # Print statistics
    print("\n" + "=" * 90)
    print("FINAL STATISTICS")
    print("=" * 90)

    if stats['total_streams'] > 0:
        print(f"Total streams:                  {stats['total_streams']}")
        print(
            f"├─ TLS/HTTPS:                   {stats['tls_streams']} ({stats['tls_streams'] / stats['total_streams'] * 100:.1f}%)")
        print(
            f"├─ HTTP:                        {stats['http_streams']} ({stats['http_streams'] / stats['total_streams'] * 100:.1f}%)")
        print(
            f"├─ SSH:                         {stats['ssh_streams']} ({stats['ssh_streams'] / stats['total_streams'] * 100:.1f}%)")
        print(
            f"├─ Telnet:                      {stats['telnet_streams']} ({stats['telnet_streams'] / stats['total_streams'] * 100:.1f}%)")
        print(
            f"├─ DNS (UDP):                   {stats['dns_streams']} ({stats['dns_streams'] / stats['total_streams'] * 100:.1f}%)")
        print(
            f"├─ UDP-Lite:                    {stats['udplite_streams']} ({stats['udplite_streams'] / stats['total_streams'] * 100:.1f}%)")
        print(
            f"├─ With ECH:                    {stats['ech_streams']} ({stats['ech_streams'] / stats['total_streams'] * 100:.1f}%)")
        print(
            f"└─ With SNI:                    {stats['sni_streams']} ({stats['sni_streams'] / stats['total_streams'] * 100:.1f}%)")

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

    return stats, type_stats, app_stats

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python multi_protocol_analyzer.py <pcap_file>")
        sys.exit(1)
    analyze_pcap(sys.argv[1])