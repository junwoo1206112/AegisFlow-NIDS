from __future__ import annotations

import random
from datetime import datetime, timezone

from app.schemas import NetworkFlow


class TrafficSimulator:
    """Produces labeled-looking flow shapes for a safe, repeatable live demo."""

    def __init__(self, seed: int = 42) -> None:
        self.random = random.Random(seed)
        self.internal_hosts = [f"10.20.{subnet}.{host}" for subnet in range(1, 4) for host in range(10, 35)]
        self.external_hosts = ["185.220.101.45", "45.83.64.12", "91.92.240.88", "203.0.113.50", "198.51.100.21"]

    def _base(self) -> dict[str, object]:
        protocol = self.random.choices(["TCP", "UDP", "ICMP"], weights=[76, 20, 4])[0]
        packets = max(1, int(self.random.lognormvariate(2.7, 0.7)))
        return {
            "timestamp": datetime.now(timezone.utc),
            "src_ip": self.random.choice(self.internal_hosts),
            "dst_ip": self.random.choice(self.external_hosts),
            "src_port": self.random.randint(1024, 65535),
            "dst_port": self.random.choices([53, 80, 123, 443, 993, 3389], weights=[13, 19, 4, 53, 7, 4])[0],
            "protocol": protocol,
            "duration_ms": round(self.random.lognormvariate(5.4, 0.9), 2),
            "packets": packets,
            "bytes_total": int(packets * self.random.uniform(180, 1250)),
            "tcp_syn_count": self.random.randint(0, min(packets, 3)) if protocol == "TCP" else 0,
            "failed_logins": 0,
            "connections_last_minute": self.random.randint(1, 35),
            "unique_ports_last_minute": self.random.randint(1, 5),
        }

    def next_flow(self) -> NetworkFlow:
        profile = self.random.choices(
            ["benign", "scan", "brute", "dos", "exfil", "c2"],
            weights=[74, 7, 6, 5, 4, 4],
        )[0]
        data = self._base()
        if profile == "scan":
            data.update(src_ip=self.random.choice(self.external_hosts), dst_ip=self.random.choice(self.internal_hosts),
                        dst_port=self.random.randint(1, 49151), packets=self.random.randint(80, 240),
                        tcp_syn_count=self.random.randint(45, 130), connections_last_minute=self.random.randint(120, 500),
                        unique_ports_last_minute=self.random.randint(30, 180), duration_ms=self.random.uniform(800, 7000))
        elif profile == "brute":
            data.update(src_ip=self.random.choice(self.external_hosts), dst_ip=self.random.choice(self.internal_hosts),
                        dst_port=self.random.choice([22, 3389]), packets=self.random.randint(150, 650),
                        failed_logins=self.random.randint(9, 55), connections_last_minute=self.random.randint(70, 380),
                        duration_ms=self.random.uniform(20_000, 180_000))
        elif profile == "dos":
            data.update(src_ip=self.random.choice(self.external_hosts), dst_ip=self.random.choice(self.internal_hosts),
                        dst_port=443, packets=self.random.randint(15_000, 90_000), bytes_total=self.random.randint(5_000_000, 60_000_000),
                        tcp_syn_count=self.random.randint(2000, 12_000), connections_last_minute=self.random.randint(1200, 8000),
                        duration_ms=self.random.uniform(800, 5000))
        elif profile == "exfil":
            data.update(dst_port=self.random.choice([21, 8088, 9001]), packets=self.random.randint(80_000, 180_000),
                        bytes_total=self.random.randint(100_000_000, 900_000_000), duration_ms=self.random.uniform(90_000, 900_000))
        elif profile == "c2":
            data.update(dst_port=self.random.choice([4444, 5555, 6667, 31337]), packets=self.random.randint(3, 30),
                        bytes_total=self.random.randint(400, 9000), duration_ms=self.random.uniform(20_000, 240_000),
                        connections_last_minute=self.random.randint(1, 8))
        return NetworkFlow(**data)


def example_flows() -> list[NetworkFlow]:
    simulator = TrafficSimulator(seed=7)
    return [simulator.next_flow() for _ in range(20)]

