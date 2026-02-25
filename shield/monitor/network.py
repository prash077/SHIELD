import psutil
import socket

import config


def get_network_status() -> dict:
    connections = psutil.net_connections(kind='inet')
    
    cloud_hits = []
    total_established = 0
    local_ai_connections = 0

    for conn in connections:
        if conn.status != 'ESTABLISHED':
            continue
        
        total_established += 1

        if not conn.raddr:
            continue

        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port

        try:
            remote_host = socket.getfqdn(remote_ip)
        except Exception:
            remote_host = remote_ip

        for endpoint in config.CLOUD_AI_ENDPOINTS:
            if endpoint in remote_host or endpoint in remote_ip:
                cloud_hits.append({
                    "endpoint": endpoint,
                    "ip": remote_ip,
                    "port": remote_port,
                })

        if remote_ip in ("127.0.0.1", "::1", "localhost"):
            if remote_port in (11434, 8000, 8080):
                local_ai_connections += 1

    return {
        "cloud_ai_connections": len(cloud_hits),
        "cloud_ai_details": cloud_hits,
        "local_ai_connections": local_ai_connections,
        "total_established": total_established,
        "status": "SECURE" if len(cloud_hits) == 0 else "WARNING",
        "summary": (
            f"0 cloud AI connections detected. "
            f"{local_ai_connections} local AI connection(s) active. "
            f"All processing is on-device."
        ) if len(cloud_hits) == 0 else (
            f"WARNING: {len(cloud_hits)} cloud AI connection(s) detected! "
            f"Endpoints: {', '.join(h['endpoint'] for h in cloud_hits)}"
        ),
    }


def get_bytes_transferred() -> dict:
    counters = psutil.net_io_counters()
    return {
        "bytes_sent": counters.bytes_sent,
        "bytes_recv": counters.bytes_recv,
        "bytes_sent_formatted": _format_bytes(counters.bytes_sent),
        "bytes_recv_formatted": _format_bytes(counters.bytes_recv),
    }


def _format_bytes(b: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b /= 1024
    return f"{b:.1f} TB"


if __name__ == "__main__":
    status = get_network_status()
    print(f"Status: {status['status']}")
    print(f"Cloud AI Connections: {status['cloud_ai_connections']}")
    print(f"Local AI Connections: {status['local_ai_connections']}")
    print(f"Total Established: {status['total_established']}")
    print(f"Summary: {status['summary']}")
    
    bytes_info = get_bytes_transferred()
    print(f"\nBytes Sent: {bytes_info['bytes_sent_formatted']}")
    print(f"Bytes Received: {bytes_info['bytes_recv_formatted']}")
