"""Core port scanning engine."""

import socket
import threading
import time
import errno
from queue import Queue
from typing import Tuple

from protocol_prober import ProtocolProber
from fingerprinter import ServiceFingerprinter
from os_detection import OSFingerprinter, OSDetailFingerprinter
from utils import clean_banner


class AdvancedScanner:
    def __init__(self, target_ip: str, threads: int = 16):
        self.target_ip = target_ip
        self.thread_count = threads
        self.port_queue = Queue()
        self.results = []
        self.results_lock = threading.Lock()
        self.fingerprinter = ServiceFingerprinter()
        self.os_fingerprinter = OSFingerprinter()
        self.os_detail_fingerprinter = OSDetailFingerprinter()
        self.ttl = -1

        self.probes = {
            21: ("TCP", b"USER anonymous\r\n"),
            22: ("TCP", b""),
            25: ("TCP", b"EHLO scanner\r\n"),
            53: ("UDP", b"\x00\x00\x10\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
            80: ("TCP", b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
            110: ("TCP", b"USER test\r\n"),
            143: ("TCP", b""),
            443: ("TCP", b"CONNECT localhost:443 HTTP/1.1\r\n\r\n"),
            445: ("TCP", b"\xff\x53\x4d\x42\x72"),
            3306: ("TCP", b""),
            3389: ("TCP", b"\x03\x00\x00"),
            5432: ("TCP", b"SELECT 1;\n"),
            5900: ("TCP", b""),
            8080: ("TCP", b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
            8888: ("TCP", b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
            9200: ("TCP", b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"),
            27017: ("TCP", b""),
            3000: ("TCP", b""),
            5000: ("TCP", b""),
            2222: ("TCP", b""),
            8443: ("TCP", b""),
            465: ("TCP", b""),
            587: ("TCP", b""),
            990: ("TCP", b""),
            9300: ("TCP", b""),
        }

    def probe_port_tcp(self, port: int) -> Tuple[str, int]:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1.0)

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
            try:
                sock.close()
            except Exception:
                pass
            return ('filtered', 1000)

    def probe_port_udp(self, port: int) -> Tuple[str, int]:
        start_time = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1.0)

        try:
            probe = self.probes.get(port, ("UDP", b"test"))[1]
            sock.sendto(probe, (self.target_ip, port))

            try:
                data, addr = sock.recvfrom(1024)
                response_time = int((time.time() - start_time) * 1000)
                sock.close()
                return ('open', response_time)
            except socket.timeout:
                sock.close()
                return ('open|filtered', 1000)
        except Exception:
            try:
                sock.close()
            except Exception:
                pass
            return ('filtered', 1000)

    def grab_banner_active(self, port: int, protocol: str) -> str:
        """Single connection with protocol-specific active probing."""
        prober = ProtocolProber()
    
        try:
            if protocol == "UDP":
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(2.0) 
                probe = self.probes.get(port, ("UDP", b""))[1]
                sock.sendto(probe, (self.target_ip, port))
                try:
                    data, addr = sock.recvfrom(4096)
                    sock.close()
                    return clean_banner(data)
                except socket.timeout:
                    sock.close()
                    return ""
            else:  # TCP
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2.0)
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
            return ""

    def scan_worker(self):
        while True:
            port = self.port_queue.get()
            if port is None:
                break

            protocol = self.probes.get(port, ("TCP", b""))[0]

            if protocol == "TCP":
                state, response_time = self.probe_port_tcp(port)
            else:
                state, response_time = self.probe_port_udp(port)

            result = {
                'port': port,
                'protocol': protocol,
                'state': state,
                'response_time': response_time,
                'banner': '',
                'service': 'Unknown',
                'version': ''
            }

            if 'open' in state:
                result['banner'] = self.grab_banner_active(port, protocol)
                service, version = self.fingerprinter.fingerprint(result['banner'], port)
                result['service'] = service
                result['version'] = version
            else:
                result['service'] = self.fingerprinter._guess_by_port(port)

            with self.results_lock:
                self.results.append(result)

            self.port_queue.task_done()

    def scan(self, start_port: int = 1, end_port: int = 65535):
        print(f"[*] Scanning {self.target_ip} from port {start_port} to {end_port}")
        print(f"[*] Using {self.thread_count} threads\n")

        print("[*] Performing ICMP ping check...")
        self.ttl = self.os_fingerprinter.get_ttl(self.target_ip)
        if self.ttl > 0:
            print(f"[+] ICMP Ping Response Received (TTL: {self.ttl})\n")
        else:
            print("[!] No ICMP response (host may block ping or require root)\n")

        for port in range(start_port, end_port + 1):
            self.port_queue.put(port)

        threads = []
        for _ in range(self.thread_count):
            t = threading.Thread(target=self.scan_worker, daemon=False)
            t.start()
            threads.append(t)

        self.port_queue.join()

        for _ in range(self.thread_count):
            self.port_queue.put(None)

        for t in threads:
            t.join()

        self.results.sort(key=lambda x: (x['port'], x['protocol']))

    def print_results(self):
        print("\n===== SCAN RESULTS =====\n")
        print(f"{'Port':<6} | {'Proto':<4} | {'State':<12} | {'Service':<15} | {'Version':<20} | Response")
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

        print(f"\n[+] Total open ports: {open_count}")
        print(f"[+] Total scanned: {len(self.results)}")

        # === OS DETECTION ===
        print("\n===== OS DETECTION ENGINE =====\n")
        
        tcp_fp = {}
        if open_ports:
            first_open_port = open_ports[0]
            print(f"[*] Probing TCP stack parameters on port {first_open_port}...")
            tcp_fp = self.os_fingerprinter.capture_tcp_fingerprint(self.target_ip, first_open_port)
            if tcp_fp.get("window", -1) > 0:
                print(f"[+] Captured TCP Window Size: {tcp_fp['window']} | Response TTL: {tcp_fp['ttl']}")

        os_guess, confidence = self.os_fingerprinter.fingerprint_os(
            self.ttl, open_ports, services, banners, tcp_fp
        )
        
        print(f"\nPrimary OS Prediction: {os_guess}")
        print(f"Overall Confidence: {confidence}%")

        # === DETAILED OS CLASSIFICATION ===
        print("\n===== DETAILED CLASSIFICATION =====\n")
        if os_guess == "Linux":
            distro, dist_conf = self.os_detail_fingerprinter.classify_linux_distro(banners, services)
            print(f"Linux Distro/Kernel: {distro} (Confidence: {dist_conf}%)")
        elif os_guess == "Windows":
            win_ver, win_conf = self.os_detail_fingerprinter.classify_windows_version(banners, services)
            print(f"Windows Variant: {win_ver} (Confidence: {win_conf}%)")
        else:
            print(f"Device Category: {os_guess}")

        # === SERVICE VERSIONS ===
        print("\n===== DETECTED SERVICE VERSIONS =====\n")
        service_versions = self.os_detail_fingerprinter.extract_service_versions(banners)
        if service_versions:
            for service, version in service_versions.items():
                print(f"{service:<15}: {version}")
        else:
            print("(No specific service version strings parsed)")