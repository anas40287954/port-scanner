"""Core scanning: SYN stealth, UDP floods, aggressive probing, retry logic."""

import socket
import threading
import time
import errno
import queue
import struct
import random
from queue import Queue, PriorityQueue
from typing import Tuple, Dict, List
from snmp_aggressive import AggressiveSNMPHunter, SNMPPortPrioritizer
import threading
from protocol_prober import ProtocolProber
from fingerprinter import ServiceFingerprinter
from os_detection import OSFingerprinter, OSDetailFingerprinter
from evasion import EvolutionTechniques
from utils import clean_banner


class SYNScanner:
    """Raw socket SYN scanning (stealthy, half-open)."""
    
    def __init__(self, target_ip, evasion):
        self.target_ip = target_ip
        self.evasion = evasion
        self.source_ip = self._get_local_ip()
    
    def _get_local_ip(self) -> str:
        """Get local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def _checksum(self, data: bytes) -> int:
        """Calculate IP/TCP checksum."""
        total = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                total += (data[i] << 8) + data[i + 1]
            else:
                total += data[i] << 8
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        return ~total & 0xFFFF
    
    def craft_syn_packet(self, dst_port: int, seq: int = None) -> bytes:
        """Craft raw TCP SYN packet."""
        if seq is None:
            seq = random.randint(1000, 100000)
        
        src_port = random.randint(40000, 65535)
        
        # IP Header
        ip_version = 4
        ip_header_len = 5
        ip_dscp = 0
        ip_total_len = 40  # 20 (IP) + 20 (TCP)
        ip_id = random.randint(1, 65535)
        ip_flags = 0x4000  # Don't fragment
        ip_frag_offset = 0
        ip_ttl = 64
        ip_proto = 6  # TCP
        ip_header = struct.pack(
            "!BHHHBBH4s4s",
            (ip_version << 4) | ip_header_len,
            ip_dscp,
            ip_total_len,
            ip_id,
            ip_flags | ip_frag_offset,
            ip_ttl,
            ip_proto,
            0,  # Checksum (filled after)
            socket.inet_aton(self.source_ip),
            socket.inet_aton(self.target_ip)
        )
        
        # TCP Header (SYN only)
        tcp_src_port = src_port
        tcp_dst_port = dst_port
        tcp_seq = seq
        tcp_ack = 0
        tcp_header_len = 5
        tcp_flags = 0x02  # SYN
        tcp_window = 65535
        
        tcp_header = struct.pack(
            "!HHIIBBHHH",
            tcp_src_port,
            tcp_dst_port,
            tcp_seq,
            tcp_ack,
            (tcp_header_len << 4) | 0,
            tcp_flags,
            tcp_window,
            0,  # Checksum (filled after)
            0   # Urgent pointer
        )
        
        # Calculate TCP checksum (pseudo-header)
        pseudo_header = struct.pack(
            "!4s4sBBH",
            socket.inet_aton(self.source_ip),
            socket.inet_aton(self.target_ip),
            0,
            6,
            len(tcp_header)
        )
        tcp_checksum = self._checksum(pseudo_header + tcp_header)
        tcp_header = tcp_header[:16] + struct.pack("!H", tcp_checksum) + tcp_header[18:]
        
        # Calculate IP checksum
        ip_checksum = self._checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack("!H", ip_checksum) + ip_header[12:]
        
        return ip_header + tcp_header
    
    def probe_syn(self, port: int, timeout: float = 2.0) -> Tuple[str, int]:
        """Send SYN packet, listen for SYN-ACK (open) or RST (closed)."""
        start_time = time.time()
        
        try:
            # Create raw socket
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            raw_sock.settimeout(timeout)
            
            # Send SYN
            syn_packet = self.craft_syn_packet(port)
            raw_sock.sendto(syn_packet, (self.target_ip, port))
            
            # Listen for response
            try:
                response, addr = raw_sock.recvfrom(65535)
                response_time = int((time.time() - start_time) * 1000)
                
                # Parse TCP flags
                ip_header_len = (response[0] & 0x0F) * 4
                tcp_flags = response[ip_header_len + 13]
                
                if tcp_flags & 0x12:  # SYN-ACK
                    raw_sock.close()
                    return ('open', response_time)
                elif tcp_flags & 0x04:  # RST
                    raw_sock.close()
                    return ('closed', response_time)
            except socket.timeout:
                response_time = int((time.time() - start_time) * 1000)
                raw_sock.close()
                return ('filtered', response_time)
            
            raw_sock.close()
            return ('filtered', int((time.time() - start_time) * 1000))
        except (PermissionError, OSError):
            # Fallback to connect scan if raw sockets unavailable
            return self._probe_connect_fallback(port, timeout)
    
    def _probe_connect_fallback(self, port: int, timeout: float) -> Tuple[str, int]:
        """Fallback connect scan when raw sockets unavailable."""
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            result = sock.connect_ex((self.target_ip, port))
            response_time = int((time.time() - start_time) * 1000)
            sock.close()
            
            if result == 0:
                return ('open', response_time)
            elif result in (errno.ECONNREFUSED, 10061, 111):
                return ('closed', response_time)
            else:
                return ('filtered', 1000)
        except Exception:
            sock.close()
            return ('filtered', 1000)


class UDPScanner:
    """Aggressive UDP scanning with multiple probe retries."""
    
    def __init__(self, target_ip: str, evasion: EvolutionTechniques):
        self.target_ip = target_ip
        self.evasion = evasion
    
    def probe_udp_aggressive(self, port: int) -> Tuple[str, int]:
        """UDP scanning with retry logic and multiple probe strategies."""
        start_time = time.time()
        
        # Standard UDP probes
        probes = {
            53: b"\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # DNS
            123: bytes([0x1b]) + b"\x00" * 47,  # NTP
            161: b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\xff\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x01",  # SNMP
            5353: b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",  # mDNS
        }
        
        probe = probes.get(port, b"test probe data")
        
        retries = self.evasion.get_retries()
        
        for attempt in range(retries):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(self.evasion.get_timeout())
                
                sock.sendto(probe, (self.target_ip, port))
                
                try:
                    data, addr = sock.recvfrom(4096)
                    response_time = int((time.time() - start_time) * 1000)
                    sock.close()
                    return ('open', response_time)
                except socket.timeout:
                    sock.close()
                    if attempt < retries - 1:
                        self.evasion.randomize_delay()
                    continue
            except Exception:
                continue
        
        response_time = int((time.time() - start_time) * 1000)
        return ('open|filtered', response_time)


class AdvancedScanner:
    """Heavy-duty port scanner: SYN stealth, UDP floods, aggressive probing."""
    
    def __init__(self, target_ip: str, aggression: int = 3, threads: int = None, hunt_snmp: bool = False):
        """Initialize scanner."""
        self.target_ip = target_ip
        self.evasion = EvolutionTechniques(aggression)
        self.thread_count = threads or max(4, (self.evasion.get_thread_count() // 2))
        
        # Initialize all scanners/fingerprinters
        self.protocol_prober = ProtocolProber(target_ip)
        self.fingerprinter = ServiceFingerprinter()
        self.os_fingerprinter = OSFingerprinter(target_ip)
        self.os_detail_fingerprinter = OSDetailFingerprinter()
        self.syn_scanner = SYNScanner(target_ip, self.evasion)  # PASS evasion
        self.udp_scanner = UDPScanner(target_ip, self.evasion)  # PASS evasion
        
        self.hunt_snmp = hunt_snmp
        if self.hunt_snmp:
            self.snmp_hunter = AggressiveSNMPHunter(target_ip)
        
        # Use regular Queue
        self.port_queue = queue.Queue()
        
        self.results = []
        self.ttl = 0
        self.snmp_result = None
        self.snmp_thread = None
        
        # Probe type mapping
        self.probes = {
            21: ("TCP", b"USER\r\n"),
            22: ("TCP", b""),
            25: ("TCP", b"EHLO\r\n"),
            53: ("UDP", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
            80: ("TCP", b"GET / HTTP/1.0\r\n\r\n"),
            110: ("TCP", b"USER test\r\n"),
            123: ("UDP", b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
            143: ("TCP", b""),
            161: ("UDP", b""),
            162: ("UDP", b""),
            199: ("UDP", b""),
            443: ("TCP", b""),
            445: ("TCP", b""),
            3306: ("TCP", b""),
            3389: ("TCP", b""),
            5432: ("TCP", b"SELECT\r\n"),
            5900: ("TCP", b""),
            7161: ("UDP", b""),
            8080: ("TCP", b"GET / HTTP/1.0\r\n\r\n"),
            8888: ("TCP", b"GET / HTTP/1.0\r\n\r\n"),
            9200: ("TCP", b""),
            9300: ("TCP", b""),
            10161: ("UDP", b""),
            11161: ("UDP", b""),
            27017: ("TCP", b""),
            3000: ("TCP", b"GET / HTTP/1.0\r\n\r\n"),
            5000: ("TCP", b"GET / HTTP/1.0\r\n\r\n"),
            2222: ("TCP", b""),
            8443: ("TCP", b""),
            465: ("TCP", b""),
            587: ("TCP", b"EHLO\r\n"),
            990: ("TCP", b""),
        }
    
    def grab_banner_active(self, port: int, protocol: str) -> str:
        """Active protocol-specific probing with retries."""
        prober = ProtocolProber(self.target_ip)
        retries = self.evasion.get_retries()
        
        for attempt in range(retries):
            try:
                if protocol == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(self.evasion.get_timeout())
                    probe = self.probes.get(port, ("UDP", b""))[1]
                    sock.sendto(probe, (self.target_ip, port))
                    try:
                        data, addr = sock.recvfrom(4096)
                        sock.close()
                        return clean_banner(data)
                    except socket.timeout:
                        sock.close()
                        if attempt < retries - 1:
                            self.evasion.randomize_delay()
                        continue
                else:  # TCP
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(self.evasion.get_timeout())
                    sock.connect((self.target_ip, port))
                    
                    banner = ""
                    
                    if port in [22, 2222]:
                        banner = prober.probe_ssh(sock)
                    elif port in [80, 8080, 8888, 3000, 5000]:
                        banner = prober.probe_http(sock, port)
                    elif port in [443, 8443]:
                        banner = prober.probe_tls_ssl(sock, self.target_ip)
                    elif port in [25, 587, 465]:
                        banner = prober.probe_smtp(sock)
                    elif port in [21, 990]:
                        banner = prober.probe_ftp(sock)
                    elif port in [3306, 3307]:
                        banner = prober.probe_mysql(sock)
                    elif port in [5432, 5433]:
                        banner = prober.probe_postgresql(sock)
                    elif port == 3389:
                        banner = prober.probe_rdp(sock)
                    elif port == 53:
                        banner = prober.probe_dns(sock, self.target_ip)
                    elif port in [27017, 27018]:
                        banner = prober.probe_mongodb(sock)
                    elif port in [9200, 9300]:
                        banner = prober.probe_elasticsearch(sock)
                    elif port == 161:  # SNMP
                        banner = prober.probe_snmp(sock, self.target_ip)
                    else:
                        banner = prober.probe_http(sock, port)
                        if not banner:
                            try:
                                banner_raw = sock.recv(4096)
                                banner = clean_banner(banner_raw)
                            except socket.timeout:
                                banner = ""
                    
                    sock.close()
                    return banner
            except Exception as e:
                try:
                    sock.close()
                except:
                    pass
                if attempt < retries - 1:
                    self.evasion.randomize_delay()
                continue
        
        return ""
    
    def scan_worker(self):
        """Worker thread for port scanning."""
        while True:
            try:
                item = self.port_queue.get(timeout=2)
                
                # Check for stop signal
                if item == "STOP":
                    self.port_queue.task_done()
                    break
                
                port = item
                
                # Determine protocol
                protocol, probe_data = self.probes.get(port, ("TCP", b""))
                
                # Scan based on protocol
                if protocol == "TCP":
                    print(f"[DEBUG] Scanning port {port} (TCP)")  # ADD
                    state, response_time = self.syn_scanner.probe_syn(port)
                    print(f"[DEBUG] Port {port}: state={state}, time={response_time}ms")  # ADD
                    
                    if state == "open":
                        print(f"[DEBUG] Port {port} OPEN - grabbing banner")  # ADD
                        banner = self.grab_banner_active(port, "TCP")
                        print(f"[DEBUG] Banner: {banner[:50] if banner else '(empty)'}...")  # ADD
                        service = self.fingerprinter.identify_service(port, banner)
                        version = self.fingerprinter.extract_version(banner)
                        
                        self.results.append({
                            'port': port,
                            'protocol': 'TCP',
                            'state': 'open',
                            'service': service,
                            'banner': banner,
                            'version': version,
                            'response_time': response_time,
                        })
                    elif state == "closed":
                        self.results.append({
                            'port': port,
                            'protocol': 'TCP',
                            'state': 'closed',
                            'service': 'N/A',
                            'banner': '',
                            'version': '',
                            'response_time': response_time,
                        })
                    else:
                        self.results.append({
                            'port': port,
                            'protocol': 'TCP',
                            'state': 'filtered',
                            'service': 'N/A',
                            'banner': '',
                            'version': '',
                            'response_time': response_time,
                        })
                
                elif protocol == "UDP":
                    state, response_time = self.udp_scanner.probe_udp_aggressive(port)
                    if state == "open":
                        service = self.fingerprinter.guess_by_port(port)
                        self.results.append({
                            'port': port,
                            'protocol': 'UDP',
                            'state': 'open',
                            'service': service,
                            'banner': '',
                            'version': '',
                            'response_time': response_time,
                        })
                    else:
                        service = self.fingerprinter.guess_by_port(port)
                        self.results.append({
                            'port': port,
                            'protocol': 'UDP',
                            'state': state,
                            'service': service,
                            'banner': '',
                            'version': '',
                            'response_time': response_time,
                        })
                
                self.port_queue.task_done()
            
            except queue.Empty:
                continue
            except Exception as e:
                self.port_queue.task_done()
                continue
    
    def scan(self, start_port: int = 1, end_port: int = 65535, protocol_filter: str = "BOTH"):
        """Aggressive scanning with parallel SNMP hunting."""
        print(f"[*] Heavy-Duty Scanner: {self.target_ip} ({start_port}-{end_port})")
        print(f"[*] Aggression Level: {self.evasion.aggression}/5")
        print(f"[*] Protocol: {protocol_filter}")
        print(f"[*] Threads: {self.thread_count}")
        
        if self.hunt_snmp:
            print(f"[*] SNMP Hunting: ENABLED (parallel on ports 161/162/7161)\n")
        else:
            print()
        
        print("[*] ICMP Ping...")
        self.ttl = self.os_fingerprinter.get_ttl(self.target_ip)
        if self.ttl > 0:
            print(f"[+] TTL: {self.ttl}\n")
        else:
            print("[!] No ICMP response\n")
        
        # START SNMP hunt in TRUE background (non-blocking)
        if self.hunt_snmp:
            self.snmp_thread = threading.Thread(
                target=self._hunt_snmp_background,
                daemon=False
            )
            self.snmp_thread.start()
            print("[*] SNMP hunt started (background)...\n")
        
        # Queue ports for TCP/UDP scan
        common_ports = [80, 443, 22, 25, 53, 3389, 3306, 5432, 21, 110, 143]
        port_list = []
        
        for port in range(start_port, end_port + 1):
            protocol = self.probes.get(port, ("TCP", b""))[0]
            
            # Filter by protocol
            if protocol_filter == "TCP" and protocol == "UDP":
                continue
            if protocol_filter == "UDP" and protocol == "TCP":
                continue
            
            priority = 0 if port in common_ports else 1
            port_list.append((priority, port))
        
        # Sort by priority (common ports first)
        port_list.sort(key=lambda x: x[0])
        
        # Put all ports in queue
        for _, port in port_list:
            self.port_queue.put(port)
        
        # Launch scanner threads
        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=self.scan_worker, daemon=False)
            t.start()
            threads.append(t)
        
        print("[*] Port scanning started...\n")
        
        # Wait for all ports to be scanned
        self.port_queue.join()
        
        # Signal workers to stop (use sentinel)
        for _ in range(self.thread_count):
            self.port_queue.put("STOP")
        
        # Wait for all threads to finish
        for t in threads:
            t.join()
        
        # NOW wait for SNMP hunt (if it's still running)
        if self.snmp_thread:
            print("[*] Waiting for SNMP hunt to complete...")
            self.snmp_thread.join(timeout=60)
            print("[*] SNMP hunt complete.\n")
        
        self.results.sort(key=lambda x: (x['port'], x['protocol']))
        
    def _hunt_snmp_background(self):
        """Background SNMP hunting thread (non-blocking)."""
        print("[*] Background: Hunting SNMP on ports 161, 162, 7161...\n")
        self.snmp_result = self.snmp_hunter.hunt_all_snmp_ports()
    
    def print_results(self):
        """Print SNMP results + port scan results."""
        
        # Wait for SNMP hunt to complete (with timeout)
        if self.snmp_thread:
            self.snmp_thread.join(timeout=60)
        
        # ============ SNMP RESULTS FIRST ============
        if self.hunt_snmp and self.snmp_result:
            print("\n" + "="*110)
            print("===== SNMP INTELLIGENCE (PRIORITY) =====")
            print("="*110)
            
            if self.snmp_result['found']:
                port = self.snmp_result.get('port', 161)
                print(f"\n[+++] SNMP FOUND!")
                print(f"[+++] Community: {self.snmp_result['community']}")
                print(f"[+++] Version: {self.snmp_result['version']}\n")
                
                print("System Information Extracted:")
                for key, value in self.snmp_result['mib_data'].items():
                    print(f"  {key:<20}: {value}")
            elif 'all_ports' in self.snmp_result:
                print("\n[-] SNMP not found on any port\n")
                for port, info in self.snmp_result['all_ports'].items():
                    print(f"    Port {port}: {'FOUND' if info['found'] else 'closed'}")
            else:
                print("\n[-] SNMP not accessible or community unknown\n")
        
        # ============ PORT SCAN RESULTS ============
        print("\n" + "="*110)
        print("===== PORT SCAN RESULTS =====")
        print("="*110 + "\n")
        print(f"{'Port':<6} | {'Proto':<4} | {'State':<12} | {'Service':<15} | {'Version':<20} | Time")
        print("-" * 110)
        
        open_count = 0
        open_ports = []
        services = []
        banners = []
        
        for result in self.results:
            if 'open' in result['state']:
                open_count += 1
                open_ports.append(result['port'])
                services.append(result['service'])
                banners.append(result['banner'])
                
                version_str = result['version'][:20] if result['version'] else "(unknown)"
                state_str = result['state']
                
                print(f"{result['port']:<6} | {result['protocol']:<4} | {state_str:<12} | "
                    f"{result['service']:<15} | {version_str:<20} | {result['response_time']}ms")
        
        print(f"\n[+] Open ports: {open_count} | Total scanned: {len(self.results)}")
        
        # ============ OS DETECTION ============
        print("\n" + "="*110)
        print("===== OS DETECTION =====")
        print("="*110 + "\n")
        
        tcp_fp = {}
        if open_ports:
            first_open_port = open_ports[0]
            print(f"[*] Probing TCP stack on port {first_open_port}...")
            tcp_fp = self.os_fingerprinter.capture_tcp_fingerprint(self.target_ip, first_open_port)
            if tcp_fp.get("window", -1) > 0:
                print(f"[+] TCP Window: {tcp_fp['window']} | TTL: {tcp_fp['ttl']}\n")
        
        os_guess, confidence = self.os_fingerprinter.fingerprint_os(
            self.ttl, open_ports, services, banners, tcp_fp
        )
        
        print(f"Primary OS: {os_guess} ({confidence}% confidence)")
        
        # Detailed classification
        print("\n" + "-"*110)
        if os_guess == "Linux":
            distro, dist_conf = self.os_detail_fingerprinter.classify_linux_distro(banners, services)
            print(f"Linux Distro: {distro} ({dist_conf}%)")
        elif os_guess == "Windows":
            win_ver, win_conf = self.os_detail_fingerprinter.classify_windows_version(banners, services)
            print(f"Windows Version: {win_ver} ({win_conf}%)")
        else:
            print(f"Device Category: {os_guess}")
        
        # Service versions
        print("\n" + "-"*110)
        print("\nDetected Service Versions:\n")
        versions = self.os_detail_fingerprinter.extract_service_versions(banners)
        if versions:
            for svc, ver in versions.items():
                print(f"  {svc:<15}: {ver}")
        else:
            print("  (None detected)")