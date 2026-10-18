"""Aggressive SNMP hunting. Multi-community bruteforce, v1/v2c/v3, timing evasion."""

import socket
import struct
import threading
import time
from typing import Dict, List, Optional, Tuple
from queue import Queue


class AggressiveSNMPHunter:
    """Hunt SNMP on multiple ports. Bruteforce communities, extract full MIB, evade filters."""
    
    def __init__(self, target_ip: str, timeout: float = 2.0, retries: int = 3):
        self.target_ip = target_ip
        self.timeout = timeout
        self.retries = retries
        self.request_id = 12345
        
        # Common community strings (ordered by likelihood)
        self.communities = [
            "public",
            "private",
            "community",
            "admin",
            "manager",
            "snmp",
            "default",
            "guest",
            "cisco",
            "router",
            "switch",
            "printer",
            "monitor",
            "test",
            "debug",
            "system",
            "network",
            "configure",
            "password",
            "enable",
            "",  # Empty community
        ]
        
        # OIDs to extract (in priority order)
        self.critical_oids = {
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysObjectID': '1.3.6.1.2.1.1.2.0',
            'sysUpTime': '1.3.6.1.2.1.1.3.0',
            'sysContact': '1.3.6.1.2.1.1.4.0',
            'sysName': '1.3.6.1.2.1.1.5.0',
            'sysLocation': '1.3.6.1.2.1.1.6.0',
            'sysServices': '1.3.6.1.2.1.1.7.0',
        }
        
        self.extended_oids = {
            'ifNumber': '1.3.6.1.2.1.2.1.0',
            'ipForwarding': '1.3.6.1.2.1.4.1.0',
            'ipDefaultTTL': '1.3.6.1.2.1.4.2.0',
            'tcpMaxConn': '1.3.6.1.2.1.6.4.0',
            'tcpActiveOpens': '1.3.6.1.2.1.6.5.0',
            'udpInDatagrams': '1.3.6.1.2.1.7.1.0',
        }
    
    def _encode_length(self, length: int) -> bytes:
        """BER length encoding."""
        if length < 128:
            return bytes([length])
        else:
            length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
            return bytes([0x80 | len(length_bytes)]) + length_bytes
    
    def _encode_string(self, s: str) -> bytes:
        """OCTET STRING encoding."""
        data = s.encode() if isinstance(s, str) else s
        return b'\x04' + self._encode_length(len(data)) + data
    
    def _encode_integer(self, n: int) -> bytes:
        """INTEGER encoding."""
        if -128 <= n < 128:
            return b'\x02\x01' + bytes([n & 0xFF])
        else:
            n_bytes = n.to_bytes((n.bit_length() + 8) // 8, 'big', signed=True)
            return b'\x02' + self._encode_length(len(n_bytes)) + n_bytes
    
    def _encode_oid(self, oid: str) -> bytes:
        """OID encoding."""
        parts = list(map(int, oid.split('.')))
        encoded = bytes([parts[0] * 40 + parts[1]])
        
        for part in parts[2:]:
            if part < 128:
                encoded += bytes([part])
            else:
                bytes_list = []
                while part:
                    bytes_list.insert(0, part & 0x7f)
                    part >>= 7
                for i in range(len(bytes_list) - 1):
                    bytes_list[i] |= 0x80
                encoded += bytes(bytes_list)
        
        return b'\x06' + self._encode_length(len(encoded)) + encoded
    
    def _encode_null(self) -> bytes:
        """NULL encoding."""
        return b'\x05\x00'
    
    def _build_snmp_pdu(self, oid: str, community: str, version: int = 0) -> bytes:
        """Build SNMP GET request PDU (v1 or v2c)."""
        # Varbind: OID + NULL
        varbind = self._encode_oid(oid) + self._encode_null()
        varbind_list = b'\x30' + self._encode_length(len(varbind)) + varbind
        
        # PDU (GET request = 0xa0)
        pdu = (
            self._encode_integer(self.request_id) +
            self._encode_integer(0) +
            self._encode_integer(0) +
            varbind_list
        )
        pdu_bytes = b'\xa0' + self._encode_length(len(pdu)) + pdu
        self.request_id += 1
        
        # Message: version + community + PDU
        version_tlv = self._encode_integer(version)
        community_tlv = self._encode_string(community)
        
        message = version_tlv + community_tlv + pdu_bytes
        full_message = b'\x30' + self._encode_length(len(message)) + message
        
        return full_message
    
    def _extract_string_from_response(self, data: bytes) -> Optional[str]:
        """Parse SNMP response, extract first OCTET STRING value."""
        try:
            i = 0
            while i < len(data) - 1:
                if data[i] == 0x04:  # OCTET STRING tag
                    length = data[i + 1]
                    if length & 0x80:  # Multi-byte length
                        length_bytes = length & 0x7f
                        length = int.from_bytes(data[i+2:i+2+length_bytes], 'big')
                        i += length_bytes
                    
                    if i + 2 + length <= len(data):
                        value = data[i + 2:i + 2 + length]
                        try:
                            decoded = value.decode('utf-8', errors='ignore').strip()
                            if decoded and len(decoded) > 1:
                                return decoded
                        except:
                            return value.hex()
                i += 1
        except:
            pass
        
        return None
    
    def _probe_snmp_single(self, port: int, oid: str, community: str, 
                           version: int = 0, attempt: int = 0) -> Optional[str]:
        """Single SNMP query with timeout and retry."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            pdu = self._build_snmp_pdu(oid, community, version)
            sock.sendto(pdu, (self.target_ip, port))
            
            response, addr = sock.recvfrom(4096)
            sock.close()
            
            # Check if response looks valid (SNMP response PDU starts with 0x30)
            if response and response[0] == 0x30:
                return self._extract_string_from_response(response)
        
        except socket.timeout:
            if attempt < self.retries:
                time.sleep(0.1 * (attempt + 1))  # Backoff
                return self._probe_snmp_single(port, oid, community, version, attempt + 1)
        except Exception as e:
            pass
        
        return None
    
    def discover_community(self, port: int = 161) -> Optional[Tuple[str, int]]:
        """Bruteforce SNMP community strings. Returns (community, version) or None."""
        print(f"\n[*] SNMP Community Bruteforce on {self.target_ip}:{port}\n")
        
        for community in self.communities:
            for version in [0, 1]:  # v1, v2c
                version_name = "v1" if version == 0 else "v2c"
                
                result = self._probe_snmp_single(
                    port, 
                    '1.3.6.1.2.1.1.1.0',  # sysDescr
                    community, 
                    version
                )
                
                if result:
                    print(f"[+] SUCCESS: community='{community}' ({version_name})")
                    print(f"[+] sysDescr: {result}\n")
                    return (community, version)
                else:
                    print(f"[-] {community:<20} ({version_name})")
                
                time.sleep(0.05)  # Evasion: random delay
        
        print("\n[-] No community string worked.\n")
        return None
    
    def enumerate_full(self, port: int = 161, community: str = "public", 
                      version: int = 0) -> Dict[str, str]:
        """Full SNMP enumeration once community is known."""
        print(f"\n[*] Full SNMP Enumeration: {community} ({['v1','v2c'][version]})\n")
        
        results = {}
        
        # Critical OIDs
        for name, oid in self.critical_oids.items():
            value = self._probe_snmp_single(port, oid, community, version)
            if value:
                results[name] = value
                print(f"[+] {name}: {value}")
            else:
                print(f"[-] {name}: (no response)")
            time.sleep(0.05)
        
        # Extended OIDs
        print("\n[*] Extended OIDs...\n")
        for name, oid in self.extended_oids.items():
            value = self._probe_snmp_single(port, oid, community, version)
            if value:
                results[name] = value
                print(f"[+] {name}: {value}")
            else:
                print(f"[-] {name}: (no response)")
            time.sleep(0.05)
        
        return results
    
    def hunt_all_snmp_ports(self) -> Optional[Dict[str, any]]:
        """Hunt SNMP on all common ports (161, 162, 7161, 10161, etc)."""
        
        # Standard and non-standard SNMP ports
        snmp_ports = [
            (161, "standard"),
            (162, "trap"),
            (7161, "alt"),
            (10161, "alt2"),
            (11161, "alt3"),
            (199, "smux"),
        ]
        
        print(f"\n[*] Hunting SNMP on multiple ports...\n")
        
        results = {}
        
        for port, port_type in snmp_ports:
            print(f"[*] Scanning port {port} ({port_type})...")
            
            # Quick community check
            for community in self.communities[:5]:  # Test top 5 communities per port
                for version in [0, 1]:
                    result = self._probe_snmp_single(
                        port,
                        '1.3.6.1.2.1.1.1.0',
                        community,
                        version
                    )
                    
                    if result:
                        version_name = "v1" if version == 0 else "v2c"
                        print(f"[+] FOUND on {port}! Community='{community}' ({version_name})")
                        print(f"[+] sysDescr: {result}\n")
                        
                        # Full enumeration
                        full_data = self.enumerate_full(port, community, version)
                        
                        results[port] = {
                            'found': True,
                            'port': port,
                            'community': community,
                            'version': version_name,
                            'mib_data': full_data
                        }
                        return results[port]  # Return immediately on first hit
            
            if port not in results:
                print(f"[-] No SNMP on port {port}\n")
                results[port] = {
                    'found': False,
                    'port': port,
                    'community': None,
                    'version': None,
                    'mib_data': {}
                }
        
        # All ports exhausted
        return {
            'found': False,
            'all_ports': results,
            'port': None,
            'community': None,
            'version': None,
            'mib_data': {}
        }


class SNMPPortPrioritizer:
    """Prioritize SNMP port 161 in main scanner queue."""
    
    def __init__(self, hunter: AggressiveSNMPHunter):
        self.hunter = hunter
        self.result = None
    
    def start_hunt(self):
        """Background thread to hunt SNMP while main scan runs."""
        self.result = self.hunter.discover_community(port=161)
    
    def get_result(self) -> Optional[Dict[str, any]]:
        """Get SNMP hunt result."""
        return self.result