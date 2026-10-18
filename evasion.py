"""IDS/Firewall evasion techniques. Fragment, decoy, timing randomization."""

import random
import time
from typing import List, Tuple


class EvolutionTechniques:
    """Evasion strategies to slip past firewalls."""

    def __init__(self, aggression_level: int = 3):
        """
        aggression_level: 1=paranoid (slow), 2=sneaky, 3=polite, 4=aggressive, 5=insane
        """
        self.aggression = aggression_level
        self.timing_config = self._timing_by_aggression()

    def _timing_by_aggression(self) -> dict:
        """Timing profiles by aggression level."""
        profiles = {
            1: {"delay_ms": (100, 300), "retries": 3, "timeout": 5.0, "threads": 4},
            2: {"delay_ms": (50, 150), "retries": 3, "timeout": 3.0, "threads": 8},
            3: {"delay_ms": (10, 50), "retries": 2, "timeout": 2.0, "threads": 16},
            4: {"delay_ms": (1, 25), "retries": 1, "timeout": 1.0, "threads": 32},
            5: {"delay_ms": (0, 10), "retries": 1, "timeout": 0.5, "threads": 64},
        }
        return profiles.get(self.aggression, profiles[3])

    def randomize_delay(self) -> float:
        """Random inter-packet delay based on aggression."""
        delay_range = self.timing_config["delay_ms"]
        delay = random.randint(delay_range[0], delay_range[1]) / 1000.0
        time.sleep(delay)
        return delay

    def decoy_ips(self, count: int = 3) -> List[str]:
        """Generate decoy IP addresses (fake sources for fragmented packets)."""
        decoys = [f"192.168.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(count)]
        return decoys

    def fragment_probe(self, probe: bytes, mtu: int = 1480) -> List[bytes]:
        """Fragment probe into MTU-sized chunks. MTU fragmentation evades simple pattern matching."""
        fragments = []
        for i in range(0, len(probe), mtu):
            fragments.append(probe[i:i+mtu])
        return fragments

    def randomize_packet_timing(self, port_count: int) -> List[float]:
        """Generate random timing offsets for port scanning."""
        return [random.uniform(0, self.timing_config["delay_ms"][1] / 1000.0) for _ in range(port_count)]

    def get_timeout(self) -> float:
        """Socket timeout based on aggression."""
        return self.timing_config["timeout"]

    def get_retries(self) -> int:
        """Retry count for failed probes."""
        return self.timing_config["retries"]

    def get_thread_count(self) -> int:
        """Optimal thread count for aggression level."""
        return self.timing_config["threads"]