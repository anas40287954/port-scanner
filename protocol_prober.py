"""Active protocol-specific probing. Sends real handshakes, parses responses."""

import socket
import re
from snmp_prober import SNMPProber


class ProtocolProber:
    """Active protocol-specific probing. Sends real handshakes, parses deep responses."""
    
    def __init__(self, target_ip):  # ADD target_ip parameter
        """Initialize protocol prober."""
        self.target_ip = target_ip
    
    def probe_http(self, sock, port: int) -> str:
        """Send HTTP GET request. Grab response headers."""
        try:
            request = (
                f"GET / HTTP/1.1\r\n"
                f"Host: localhost:{port}\r\n"
                f"User-Agent: Scanner/1.0\r\n"
                f"Connection: close\r\n"
                f"Accept-Encoding: gzip, deflate\r\n"
                f"\r\n"
            )
            sock.sendall(request.encode())
            response = b""
            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                except socket.timeout:
                    break
            return response.decode('utf-8', errors='ignore')
        except Exception:
            return ""
    
    def probe_ssh(self, sock) -> str:
        """SSH protocol: read server's identification line."""
        try:
            banner = b""
            while True:
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    banner += chunk
                    if b"\r\n" in banner or b"\n" in banner:
                        break
                except socket.timeout:
                    break
            return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            return ""
    
    def probe_smtp(self, sock) -> str:
        """SMTP: server sends 220 greeting unsolicited. Send EHLO for extended response."""
        try:
            greeting = b""
            try:
                greeting = sock.recv(1024)
            except socket.timeout:
                pass
            
            sock.sendall(b"EHLO scanner\r\n")
            ehlo_resp = b""
            try:
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    ehlo_resp += chunk
                    if b"250 " in chunk:
                        break
            except socket.timeout:
                pass
            
            full_response = greeting + ehlo_resp
            return full_response.decode('utf-8', errors='ignore')
        except Exception:
            return ""
    
    def probe_ftp(self, sock) -> str:
        """FTP: server sends 220 greeting. Send USER anonymous."""
        try:
            greeting = b""
            try:
                greeting = sock.recv(1024)
            except socket.timeout:
                pass
            
            sock.sendall(b"USER anonymous\r\n")
            user_resp = b""
            try:
                user_resp = sock.recv(1024)
            except socket.timeout:
                pass
            
            return (greeting + user_resp).decode('utf-8', errors='ignore')
        except Exception:
            return ""
    
    def probe_tls_ssl(self, sock, hostname: str) -> str:
        """Send TLS ClientHello. Parse ServerHello + Certificate."""
        try:
            client_hello = bytes.fromhex(
                "160303"
                "0041"
                "01"
                "00003d"
                "0303"
                + "00" * 32
                + "00"
                + "0004"
                + "002f0035"
                + "01"
                + "00"
                + "000f"
                + "000b000409030603020301"
            )
            
            sock.sendall(client_hello)
            
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            
            banner = self._parse_tls_response(response, hostname)
            return banner
        except Exception:
            return ""
    
    def _parse_tls_response(self, data: bytes, hostname: str) -> str:
        """Extract TLS version, cipher, certificate info from response."""
        info = ""
        
        if b"\x03\x03" in data:
            info += "TLS 1.2 "
        elif b"\x03\x04" in data:
            info += "TLS 1.3 "
        
        cert_start = data.find(b"\x0b")
        if cert_start > 0:
            info += "(Certificate Present) "
        
        if b"CN=" in data:
            cn_idx = data.find(b"CN=")
            cn_end = data.find(b"\x00", cn_idx)
            if cn_end > cn_idx:
                cn = data[cn_idx+3:cn_end].decode('utf-8', errors='ignore')
                info += f"CN={cn} "
        
        return info if info else "(TLS detected)"
    
    def probe_mysql(self, sock) -> str:
        """MySQL: server sends greeting with version unsolicited."""
        try:
            greeting = b""
            try:
                greeting = sock.recv(1024)
            except socket.timeout:
                pass
            
            if greeting and greeting[0:1] == b"\n":
                version_end = greeting.find(b"\x00", 1)
                if version_end > 1:
                    version = greeting[1:version_end].decode('utf-8', errors='ignore')
                    return f"MySQL {version}"
            
            return greeting.decode('utf-8', errors='ignore')
        except Exception:
            return ""
    
    def probe_postgresql(self, sock) -> str:
        """PostgreSQL: send StartupMessage, extract server_version."""
        try:
            startup = (
                b"\x00\x00\x00\x21"
                b"\x00\x03\x00\x00"
                b"user\x00postgres\x00"
                b"database\x00postgres\x00"
                b"\x00"
            )
            sock.sendall(startup)
            
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            
            if b"server_version" in response:
                idx = response.find(b"server_version")
                end_idx = response.find(b"\x00", idx)
                if end_idx > idx:
                    version = response[idx+15:end_idx].decode('utf-8', errors='ignore')
                    return f"PostgreSQL {version}"
            
            return response[:100].decode('utf-8', errors='ignore')
        except Exception:
            return ""
    
    def probe_rdp(self, sock) -> str:
        """RDP: send X.224 Connection Request PDU."""
        try:
            rdp_request = bytes.fromhex("030000130ee000000000010800030000")
            sock.sendall(rdp_request)
            
            response = b""
            try:
                response = sock.recv(1024)
            except socket.timeout:
                pass
            
            if response and response[0:1] == b"\x03":
                return "RDP (X.224 handshake detected)"
            return ""
        except Exception:
            return ""
    
    def probe_dns(self, sock, target_ip: str) -> str:
        """DNS query over TCP port 53."""
        try:
            dns_query = bytes.fromhex(
                "0000"
                "0100"
                "0001"
                "0000"
                "0000"
                "0000"
                "0474657374056c6f63616c00"
                "00010001"
            )
            
            query_with_len = len(dns_query).to_bytes(2, 'big') + dns_query
            sock.sendall(query_with_len)
            
            response = b""
            try:
                response = sock.recv(1024)
            except socket.timeout:
                pass
            
            return "DNS (response received)" if response else ""
        except Exception:
            return ""
    
    def probe_mongodb(self, sock) -> str:
        """MongoDB: send ismaster command."""
        try:
            query = bytes.fromhex(
                "00000000"
                "00000000"
                "d4070000"
                "00000000"
                "61646d696e2e24636d6400000000"
                "00000000"
                "01000000"
                "0c0000000a69736d61737465720000"
            )
            sock.sendall(query)
            
            response = b""
            try:
                response = sock.recv(1024)
            except socket.timeout:
                pass
            
            if b"version" in response:
                return "MongoDB (ismaster response received)"
            return ""
        except Exception:
            return ""
    
    def probe_snmp(self, sock, target_ip: str) -> str:
        """
        SNMP enumeration: extract system info, interfaces, processes.
        Returns formatted summary of SNMP data.
        """
        try:
            prober = SNMPProber(target_ip, community="public", timeout=2.0)
        
            results = "SNMP Enumeration:\n"
        
            # System info
            system = prober.enumerate_system()
            if system:
                results += "[System Info]\n"
                for key, val in system.items():
                    results += f"  {key}: {val}\n"
        
            # Interfaces
            interfaces = prober.enumerate_interfaces()
            if interfaces:
                results += "\n[Network Interfaces]\n"
                for if_group in interfaces:
                    for if_name, if_data in if_group.items():
                        results += f"  {if_name}:\n"
                        for k, v in if_data.items():
                            results += f"    {k}: {v}\n"
        
            # Routes
            routes = prober.enumerate_routes()
            if routes:
                results += "\n[Routing Table]\n"
                for route in routes:
                    results += f"  {route.get('Destination', 'N/A')} -> "
                    results += f"{route.get('NextHop', 'N/A')} "
                    results += f"(Mask: {route.get('Mask', 'N/A')})\n"
        
            # Processes
            processes = prober.enumerate_processes()
            if processes:
                results += "\n[Running Processes]\n"
                for proc in processes[:10]:  # First 10
                    results += f"  {proc.get('Name', 'N/A')}\n"
                    if proc.get('Path'):
                        results += f"    Path: {proc['Path']}\n"
        
            return results
        except Exception as e:
            return f"SNMP error: {str(e)}"
    
    def probe_elasticsearch(self, sock) -> str:
        """Elasticsearch: GET / returns JSON with version."""
        try:
            request = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            sock.sendall(request)
            
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass
            
            if b'"version"' in response and b'"number"' in response:
                version_match = re.search(rb'"number":"([^"]+)"', response)
                if version_match:
                    version = version_match.group(1).decode('utf-8', errors='ignore')
                    return f"Elasticsearch {version}"
            
            return response[:100].decode('utf-8', errors='ignore')
        except Exception:
            return ""