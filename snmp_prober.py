"""SNMP enumeration. Extract system info, interfaces, routes, processes."""

import struct
import socket
from typing import Dict, List, Tuple, Optional


class SNMPProber:
    """SNMP v1/v2c query engine. Extract MIB data."""
    
    def __init__(self, target_ip: str, community: str = "public", timeout: float = 2.0):
        self.target_ip = target_ip
        self.community = community
        self.timeout = timeout
        self.request_id = 1
    
    def _encode_length(self, length: int) -> bytes:
        """Encode BER length field."""
        if length < 128:
            return bytes([length])
        else:
            length_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
            return bytes([0x80 | len(length_bytes)]) + length_bytes
    
    def _encode_string(self, s: str) -> bytes:
        """Encode OCTET STRING."""
        data = s.encode()
        return b'\x04' + self._encode_length(len(data)) + data
    
    def _encode_integer(self, n: int) -> bytes:
        """Encode INTEGER."""
        if n >= 0 and n < 128:
            return b'\x02\x01' + bytes([n])
        else:
            n_bytes = n.to_bytes((n.bit_length() + 8) // 8, 'big', signed=True)
            return b'\x02' + self._encode_length(len(n_bytes)) + n_bytes
    
    def _encode_oid(self, oid: str) -> bytes:
        """Encode OID (Object Identifier)."""
        parts = list(map(int, oid.split('.')))
        encoded = bytes([parts[0] * 40 + parts[1]]) + b''
        
        for part in parts[2:]:
            if part < 128:
                encoded += bytes([part])
            else:
                # Multi-byte encoding
                bytes_list = []
                while part:
                    bytes_list.insert(0, part & 0x7f)
                    part >>= 7
                for i in range(len(bytes_list) - 1):
                    bytes_list[i] |= 0x80
                encoded += bytes(bytes_list)
        
        return b'\x06' + self._encode_length(len(encoded)) + encoded
    
    def _encode_null(self) -> bytes:
        """Encode NULL."""
        return b'\x05\x00'
    
    def _build_snmp_pdu(self, oid: str, request_type: int = 0) -> bytes:
        """Build SNMP GET request PDU (SNMPv1/v2c)."""
        # Variable binding: OID + NULL
        varbind = self._encode_oid(oid) + self._encode_null()
        varbind_list = b'\x30' + self._encode_length(len(varbind)) + varbind
        
        # PDU (GET request = 0xa0)
        pdu = (
            self._encode_integer(self.request_id) +
            self._encode_integer(0) +  # Error status
            self._encode_integer(0) +  # Error index
            varbind_list
        )
        pdu_bytes = b'\xa0' + self._encode_length(len(pdu)) + pdu
        self.request_id += 1
        
        # Sequence: version + community + PDU
        version = self._encode_integer(0)  # SNMPv1
        community = self._encode_string(self.community)
        
        message = version + community + pdu_bytes
        full_message = b'\x30' + self._encode_length(len(message)) + message
        
        return full_message
    
    def _parse_tlv(self, data: bytes, offset: int = 0) -> Tuple[int, int, bytes, int]:
        """Parse TLV (Tag-Length-Value). Returns (tag, length, value, new_offset)."""
        tag = data[offset]
        offset += 1
        
        length = data[offset]
        offset += 1
        
        if length & 0x80:
            length_bytes = length & 0x7f
            length = int.from_bytes(data[offset:offset+length_bytes], 'big')
            offset += length_bytes
        
        value = data[offset:offset+length]
        offset += length
        
        return tag, length, value, offset
    
    def _parse_oid(self, data: bytes) -> str:
        """Decode OID from bytes."""
        if not data:
            return ""
        
        first = data[0]
        parts = [first // 40, first % 40]
        
        i = 1
        while i < len(data):
            value = 0
            while i < len(data):
                byte = data[i]
                i += 1
                value = (value << 7) | (byte & 0x7f)
                if not (byte & 0x80):
                    break
            parts.append(value)
        
        return '.'.join(map(str, parts))
    
    def _parse_string(self, data: bytes) -> str:
        """Decode OCTET STRING."""
        try:
            return data.decode('utf-8', errors='ignore')
        except:
            return data.hex()
    
    def _parse_integer(self, data: bytes) -> int:
        """Decode INTEGER."""
        if len(data) == 0:
            return 0
        return int.from_bytes(data, 'big', signed=True)
    
    def _parse_snmp_response(self, data: bytes) -> Dict[str, any]:
        """Parse SNMP response PDU."""
        result = {}
        
        try:
            offset = 0
            tag, length, sequence_data, offset = self._parse_tlv(data, offset)
            
            if tag != 0x30:  # SEQUENCE
                return result
            
            # Parse version
            tag, length, version_data, inner_offset = self._parse_tlv(sequence_data, 0)
            version = self._parse_integer(version_data)
            
            # Parse community
            tag, length, community_data, inner_offset = self._parse_tlv(sequence_data, inner_offset)
            community = self._parse_string(community_data)
            
            # Parse PDU
            tag, length, pdu_data, inner_offset = self._parse_tlv(sequence_data, inner_offset)
            
            pdu_offset = 0
            # Request ID
            tag, length, req_id_data, pdu_offset = self._parse_tlv(pdu_data, pdu_offset)
            request_id = self._parse_integer(req_id_data)
            
            # Error status
            tag, length, error_data, pdu_offset = self._parse_tlv(pdu_data, pdu_offset)
            error_status = self._parse_integer(error_data)
            
            # Error index
            tag, length, err_idx_data, pdu_offset = self._parse_tlv(pdu_data, pdu_offset)
            error_index = self._parse_integer(err_idx_data)
            
            # Variable bindings
            tag, length, varbind_list_data, pdu_offset = self._parse_tlv(pdu_data, pdu_offset)
            
            vb_offset = 0
            while vb_offset < len(varbind_list_data):
                tag, length, varbind_data, vb_offset = self._parse_tlv(varbind_list_data, vb_offset)
                
                if tag == 0x30:  # SEQUENCE
                    # Parse OID
                    tag, length, oid_data, vb_inner = self._parse_tlv(varbind_data, 0)
                    oid = self._parse_oid(oid_data)
                    
                    # Parse value
                    tag, length, value_data, vb_inner = self._parse_tlv(varbind_data, vb_inner)
                    
                    if tag == 0x02:  # INTEGER
                        value = self._parse_integer(value_data)
                    elif tag == 0x04:  # OCTET STRING
                        value = self._parse_string(value_data)
                    elif tag == 0x06:  # OID
                        value = self._parse_oid(value_data)
                    else:
                        value = value_data.hex()
                    
                    result[oid] = value
        except Exception as e:
            pass
        
        return result
    
    def query(self, oid: str) -> Optional[str]:
        """Execute SNMP GET query. Returns value or None."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            pdu = self._build_snmp_pdu(oid)
            sock.sendto(pdu, (self.target_ip, 161))
            
            response, addr = sock.recvfrom(4096)
            sock.close()
            
            parsed = self._parse_snmp_response(response)
            
            # Extract the value from response
            for oid_key, value in parsed.items():
                return str(value)
            
            return None
        except Exception as e:
            return None
    
    def enumerate_system(self) -> Dict[str, str]:
        """Enumerate system info from SNMP."""
        oids = {
            'sysDescr': '1.3.6.1.2.1.1.1.0',
            'sysObjectID': '1.3.6.1.2.1.1.2.0',
            'sysUpTime': '1.3.6.1.2.1.1.3.0',
            'sysContact': '1.3.6.1.2.1.1.4.0',
            'sysName': '1.3.6.1.2.1.1.5.0',
            'sysLocation': '1.3.6.1.2.1.1.6.0',
            'sysServices': '1.3.6.1.2.1.1.7.0',
        }
        
        results = {}
        for name, oid in oids.items():
            value = self.query(oid)
            if value:
                results[name] = value
        
        return results
    
    def enumerate_interfaces(self) -> List[Dict[str, str]]:
        """Enumerate network interfaces."""
        interfaces = []
        
        # Query interface count
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            
            pdu = self._build_snmp_pdu('1.3.6.1.2.1.2.1.0')  # ifNumber
            sock.sendto(pdu, (self.target_ip, 161))
            response, _ = sock.recvfrom(4096)
            sock.close()
            
            parsed = self._parse_snmp_response(response)
            for oid_key, value in parsed.items():
                if_count = int(value) if isinstance(value, (int, str)) else 0
                break
        except:
            if_count = 10  # Default scan
        
        # Query interface details
        for i in range(1, min(if_count + 1, 20)):  # Cap at 20 interfaces
            if_data = {}
            
            # ifDescr
            descr = self.query(f'1.3.6.1.2.1.2.2.1.2.{i}')
            if descr:
                if_data['Description'] = descr
            
            # ifType
            if_type = self.query(f'1.3.6.1.2.1.2.2.1.3.{i}')
            if if_type:
                if_data['Type'] = if_type
            
            # ifMTU
            mtu = self.query(f'1.3.6.1.2.1.2.2.1.4.{i}')
            if mtu:
                if_data['MTU'] = mtu
            
            # ifSpeed
            speed = self.query(f'1.3.6.1.2.1.2.2.1.5.{i}')
            if speed:
                if_data['Speed'] = speed
            
            # ifPhysAddress (MAC)
            mac = self.query(f'1.3.6.1.2.1.2.2.1.6.{i}')
            if mac:
                if_data['MAC'] = mac
            
            if if_data:
                interfaces.append({f'Interface {i}': if_data})
        
        return interfaces
    
    def enumerate_routes(self) -> List[Dict[str, str]]:
        """Enumerate routing table."""
        routes = []
        
        for i in range(256):  # Scan up to 256 routes
            route_data = {}
            
            # ipRouteDest
            dest = self.query(f'1.3.6.1.2.1.4.21.1.1.{i}')
            if dest:
                route_data['Destination'] = dest
            
            # ipRouteNextHop
            nexthop = self.query(f'1.3.6.1.2.1.4.21.1.7.{i}')
            if nexthop:
                route_data['NextHop'] = nexthop
            
            # ipRouteMask
            mask = self.query(f'1.3.6.1.2.1.4.21.1.11.{i}')
            if mask:
                route_data['Mask'] = mask
            
            if route_data:
                routes.append(route_data)
            else:
                break
        
        return routes
    
    def enumerate_processes(self) -> List[Dict[str, str]]:
        """Enumerate running processes (hrSWRunTable)."""
        processes = []
        
        for i in range(1, 256):
            proc_data = {}
            
            # hrSWRunName
            name = self.query(f'1.3.6.1.2.1.25.4.2.1.2.{i}')
            if name:
                proc_data['Name'] = name
            
            # hrSWRunPath
            path = self.query(f'1.3.6.1.2.1.25.4.2.1.4.{i}')
            if path:
                proc_data['Path'] = path
            
            # hrSWRunParameters
            params = self.query(f'1.3.6.1.2.1.25.4.2.1.5.{i}')
            if params:
                proc_data['Parameters'] = params
            
            if proc_data:
                processes.append(proc_data)
            else:
                if i > 20:  # Stop after 20 empty
                    break
        
        return processes