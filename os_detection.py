"""OS detection via TTL, TCP stack fingerprinting, port patterns, and banners."""

import subprocess
import platform
import struct
import socket
import re
from typing import Tuple, Dict


class OSFingerprinter:
    """Detect OS using TCP stack features, TTL, port patterns, and banners."""

    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.os_signatures = {
            "Windows": {
                "ttl": (120, 128),
                "win_sizes": [8192, 64240, 65535],
                "common_ports": [135, 139, 445, 3389],
                "services": ["SMB", "RDP", "DCOM"],
                "banners": ["Windows", "Microsoft"]
            },
            "Linux": {
                "ttl": (60, 64),
                "win_sizes": [5840, 14600, 28960, 29200, 64240],
                "common_ports": [22, 111, 2049, 3306, 5432, 27017],
                "services": ["SSH", "MySQL", "PostgreSQL", "MongoDB"],
                "banners": ["OpenSSH", "Ubuntu", "CentOS", "Debian", "Linux"]
            },
            "macOS": {
                "ttl": (60, 64),
                "win_sizes": [65535],
                "common_ports": [22, 548, 3689, 5900],
                "services": ["SSH", "VNC"],
                "banners": ["Darwin", "macOS"]
            },
            "Cisco / Network Device": {
                "ttl": (250, 255),
                "win_sizes": [4128, 8192, 16384],
                "common_ports": [23, 80, 22],
                "services": ["Telnet"],
                "banners": ["Cisco", "IOS"]
            }
        }

    def get_ttl(self, target_ip: str) -> int:
        """Ping target and extract initial TTL."""
        try:
            cmd = ["ping", "-n" if platform.system() == "Windows" else "-c", "1", target_ip]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            
            for line in result.stdout.split('\n'):
                if "ttl=" in line.lower():
                    parts = line.lower().split("ttl=")
                    return int(parts[1].split()[0])
        except Exception:
            pass
        return -1

    def capture_tcp_fingerprint(self, target_ip: str, open_port: int) -> Dict[str, any]:
        """Inspect raw TCP parameters (Window Size & TTL) from SYN-ACK packet."""
        fp = {"window": -1, "ttl": -1}
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_sock.settimeout(2.0)
            
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_sock.settimeout(1.5)
            test_sock.connect_ex((target_ip, open_port))
            
            packet, addr = raw_sock.recvfrom(65535)
            if addr[0] == target_ip:
                ip_hdr_len = (packet[0] & 0x0F) * 4
                tcp_hdr = packet[ip_hdr_len:ip_hdr_len + 20]
                _, _, _, _, _, _, window, _, _ = struct.unpack("!HHLLBBHHH", tcp_hdr)
                fp["window"] = window
                fp["ttl"] = packet[8]
            
            test_sock.close()
            raw_sock.close()
        except (PermissionError, socket.error):
            pass
        return fp

    def fingerprint_os(self, ttl: int, open_ports: list, services: list, banners: list, tcp_fp: Dict[str, any]) -> Tuple[str, int]:
        """Multi-factor OS scoring engine."""
        if not open_ports and ttl <= 0:
            return ("Unknown", 0)

        scores = {}

        for os_name, sig in self.os_signatures.items():
            score = 0
            max_score = 100

            # TCP Window Size Match (30 pts)
            if tcp_fp.get("window", -1) in sig["win_sizes"]:
                score += 30
            elif tcp_fp.get("window", -1) > 0:
                score += 5

            # TTL Range Match (30 pts)
            target_ttl = tcp_fp.get("ttl") if tcp_fp.get("ttl", -1) > 0 else ttl
            if target_ttl > 0:
                ttl_min, ttl_max = sig["ttl"]
                if ttl_min <= target_ttl <= ttl_max:
                    score += 30
                elif ttl_min - 5 <= target_ttl <= ttl_max + 5:
                    score += 15

            # Open Port Matching (20 pts)
            matching_ports = set(open_ports) & set(sig["common_ports"])
            if matching_ports:
                score += int(20 * (len(matching_ports) / len(sig["common_ports"])))

            # Service & Banner Matching (20 pts)
            matching_services = set(services) & set(sig["services"])
            if matching_services:
                score += 10

            for banner in banners:
                if any(b.lower() in banner.lower() for b in sig["banners"]):
                    score += 10
                    break

            confidence = min(score, max_score)
            scores[os_name] = confidence

        best_os = max(scores.items(), key=lambda x: x[1])
        return best_os[0], best_os[1]


class OSDetailFingerprinter:
    """Detailed OS classification: Linux distro, Windows version, etc."""

    def __init__(self):
        pass
        self.linux_signatures = {
            "Ubuntu": [r"Ubuntu", r"openssh.*ubuntu", r"ubuntu.*lts"],
            "Debian": [r"Debian", r"openssh.*debian"],
            "CentOS": [r"CentOS", r"Red Hat.*CentOS"],
            "RHEL": [r"Red Hat Enterprise Linux", r"RHEL"],
            "Fedora": [r"Fedora"],
            "Alpine": [r"Alpine"],
            "Arch": [r"Arch Linux"]
        }

        self.windows_signatures = {
            "Windows 11 / Server 2022": [r"Windows NT 10\.0.*22\d{3}", r"Windows Server 2022", r"Win11"],
            "Windows 10 / Server 2019": [r"Windows NT 10\.0", r"Windows Server 2019", r"Win10"],
            "Windows Server 2016": [r"Windows Server 2016", r"14393"],
            "Windows 7 / Server 2008 R2": [r"Windows NT 6\.1", r"Windows 7"]
        }

    def classify_linux_distro(self, banners: list, services: list) -> Tuple[str, int]:
        scores = {}
        for distro, patterns in self.linux_signatures.items():
            score = 0
            for pattern in patterns:
                for banner in banners:
                    if re.search(pattern, banner, re.IGNORECASE):
                        score += 1
                        break
            if score > 0:
                scores[distro] = int((score / len(patterns)) * 100)

        if not scores:
            return ("Generic Linux Kernel", 30)

        best_distro = max(scores.items(), key=lambda x: x[1])
        return best_distro[0], best_distro[1]

    def classify_windows_version(self, banners: list, services: list) -> Tuple[str, int]:
        scores = {}
        for version, patterns in self.windows_signatures.items():
            score = 0
            for pattern in patterns:
                for banner in banners:
                    if re.search(pattern, banner, re.IGNORECASE):
                        score += 1
                        break
            if score > 0:
                scores[version] = int((score / len(patterns)) * 100)

        if not scores:
            return ("Windows (Generic)", 30)

        best_version = max(scores.items(), key=lambda x: x[1])
        return best_version[0], best_version[1]

    def extract_service_versions(self, banners: list) -> Dict[str, str]:
        versions = {}
        patterns = {
            'SSH': r'SSH-2\.0-([^\r\n]+)',
            'Apache': r'Apache/([^\s\r\n]+)',
            'Nginx': r'nginx/([^\s\r\n]+)',
            'IIS': r'Microsoft-IIS/([^\s\r\n]+)',
            'OpenSSL': r'OpenSSL/([^\s\r\n]+)',
            'PHP': r'PHP/([^\s\r\n]+)'
        }
        for banner in banners:
            if not banner:
                continue
            for service, pattern in patterns.items():
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    versions[service] = match.group(1)
        return versions