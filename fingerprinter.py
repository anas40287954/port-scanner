"""Service and banner fingerprinting."""

import re
from typing import Tuple


class ServiceFingerprinter:
    """Match banners/responses to known service signatures."""

    def __init__(self):
        pass

    def identify_service(self, port: int, banner: str) -> str:
        """Identify service from banner or port fallback."""
        if not banner:
            return self._guess_by_port(port)
        
        # HTTP
        if "HTTP/" in banner:
            return "HTTP"
        # SSH
        elif "SSH" in banner:
            return "SSH"
        # FTP
        elif "220" in banner and ("FTP" in banner or "ftp" in banner):
            return "FTP"
        # SMTP
        elif "220" in banner and ("SMTP" in banner or "smtp" in banner):
            return "SMTP"
        # MySQL
        elif "mysql_native_password" in banner or "\x00\x00\x00" in banner:
            return "MySQL"
        # PostgreSQL
        elif "FATAL" in banner or "NOTICE" in banner:
            return "PostgreSQL"
        # MongoDB
        elif "MongoDB" in banner or "ismaster" in banner:
            return "MongoDB"
        # Elasticsearch
        elif "elasticsearch" in banner.lower() or '"version"' in banner:
            return "Elasticsearch"
        # RDP
        elif "\x03\x00" in banner:
            return "RDP"
        # SMB
        elif "SMB" in banner or "CIFS" in banner:
            return "SMB"
        # VNC
        elif "RFB" in banner:
            return "VNC"
        else:
            return self._guess_by_port(port)

    def extract_version(self, banner: str) -> str:
        """Extract version string from banner."""
        if not banner:
            return ""
        
        patterns = [
            r'Server:\s*([^\r\n]+)',
            r'SSH-[0-9.]+[^r\n]+',
            r'Apache/([^\s\r\n]+)',
            r'nginx/([^\s\r\n]+)',
            r'IIS/([^\s\r\n]+)',
            r'MySQL\s+([^\s\r\n]+)',
            r'PostgreSQL\s+([^\s\r\n]+)',
            r'version["\']?\s*:\s*["\']?([^\s",\r\n]+)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)[:30] if match.groups() else match.group(0)[:30]
        
        return ""

    def guess_by_port(self, port: int) -> str:
        """Port-based service fallback."""
        port_map = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            8080: "HTTP-Alt", 8888: "HTTP-Alt", 9200: "Elasticsearch",
            27017: "MongoDB", 3000: "HTTP", 5000: "HTTP"
        }
        return port_map.get(port, "Unknown")
    
    def _guess_by_port(self, port: int) -> str:
        """Internal port-based fallback."""
        return self.guess_by_port(port)