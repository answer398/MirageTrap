from __future__ import annotations

import ipaddress
import struct
from datetime import timezone

from app.utils.web_request import parse_request_content, parse_response_content


def build_session_pcap(events: list, honeypot_ip: str = "198.18.0.10", honeypot_port: int = 80) -> bytes:
    packets = bytearray()
    packets.extend(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))

    seq_client = 1000
    seq_server = 5000
    for index, event in enumerate(events):
        event_time = event.created_at
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
        timestamp = event_time.astimezone(timezone.utc).timestamp()
        seconds = int(timestamp)
        micros = int((timestamp - seconds) * 1_000_000)

        request_record = parse_request_content(event.request_content)
        response_record = parse_response_content(event.response_content)
        client_ip = _safe_ipv4(event.source_ip, fallback=f"203.0.113.{(index % 200) + 1}")
        client_port = int(event.source_port or (40000 + index))

        request_payload = _build_http_request_bytes(request_record)
        response_payload = _build_http_response_bytes(response_record)

        request_packet = _build_ipv4_tcp_packet(
            src_ip=client_ip,
            dst_ip=honeypot_ip,
            src_port=client_port,
            dst_port=honeypot_port,
            seq=seq_client,
            ack=0,
            payload=request_payload,
        )
        packets.extend(struct.pack("<IIII", seconds, micros, len(request_packet), len(request_packet)))
        packets.extend(request_packet)
        seq_client += max(len(request_payload), 1)

        response_packet = _build_ipv4_tcp_packet(
            src_ip=honeypot_ip,
            dst_ip=client_ip,
            src_port=honeypot_port,
            dst_port=client_port,
            seq=seq_server,
            ack=seq_client,
            payload=response_payload,
        )
        packets.extend(struct.pack("<IIII", seconds, min(micros + 500, 999999), len(response_packet), len(response_packet)))
        packets.extend(response_packet)
        seq_server += max(len(response_payload), 1)

    return bytes(packets)


def _build_http_request_bytes(record: dict) -> bytes:
    method = str(record.get("method") or "GET").strip().upper() or "GET"
    path = str(record.get("path") or "/").strip() or "/"
    query_string = str(record.get("query_string") or "").strip()
    target = f"{path}{('?' + query_string) if query_string else ''}"
    body = str(record.get("body") or "")
    headers = dict(record.get("headers") or {})
    headers.setdefault("Host", "honeypot.local")
    headers.setdefault("User-Agent", "MirageTrap-PCAP/1.0")
    headers.setdefault("Content-Length", str(len(body.encode('utf-8'))))

    lines = [f"{method} {target} HTTP/1.1"]
    lines.extend(f"{key}: {value}" for key, value in headers.items())
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines).encode("utf-8", errors="replace")


def _build_http_response_bytes(record: dict) -> bytes:
    status = int(record.get("status") or 200)
    body = str(record.get("body") or "OK")
    headers = dict(record.get("headers") or {})
    headers.setdefault("Content-Type", "text/html; charset=utf-8")
    headers.setdefault("Content-Length", str(len(body.encode('utf-8'))))

    lines = [f"HTTP/1.1 {status} OK"]
    lines.extend(f"{key}: {value}" for key, value in headers.items())
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines).encode("utf-8", errors="replace")


def _build_ipv4_tcp_packet(
    *,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    seq: int,
    ack: int,
    payload: bytes,
) -> bytes:
    version_ihl = 0x45
    total_length = 20 + 20 + len(payload)
    identification = 0
    flags_fragment = 0
    ttl = 64
    protocol = 6
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        0,
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
    )
    ip_checksum = _checksum(ip_header)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        version_ihl,
        0,
        total_length,
        identification,
        flags_fragment,
        ttl,
        protocol,
        ip_checksum,
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
    )

    tcp_offset_reserved_flags = (5 << 12) | 0x18
    window = 65535
    tcp_header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        tcp_offset_reserved_flags,
        window,
        0,
        0,
    )
    pseudo_header = struct.pack(
        "!4s4sBBH",
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
        0,
        6,
        len(tcp_header) + len(payload),
    )
    tcp_checksum = _checksum(pseudo_header + tcp_header + payload)
    tcp_header = struct.pack(
        "!HHIIHHHH",
        src_port,
        dst_port,
        seq,
        ack,
        tcp_offset_reserved_flags,
        window,
        tcp_checksum,
        0,
    )

    return ip_header + tcp_header + payload


def _checksum(data: bytes) -> int:
    if len(data) % 2 == 1:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _safe_ipv4(raw: str | None, *, fallback: str) -> str:
    try:
        return str(ipaddress.ip_address(str(raw or "").strip()))
    except ValueError:
        return fallback
