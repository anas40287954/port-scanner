"""Heavy-duty scanner with aggressive SNMP hunting."""

from scanner_core import AdvancedScanner


def main():
    target = "64.29.17.3"
    
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║  HEAVY-DUTY PORT SCANNER + AGGRESSIVE SNMP HUNTER             ║")
    print("╚═══════════════════════════════════════════════════════════════╝\n")
    print(f"Target: {target}\n")
    
    aggression = 3
    print(f"Aggression: {aggression}/5")
    print(f"SNMP Hunting: ENABLED (parallel on ports 161/162/7161)\n")
    
    scanner = AdvancedScanner(target, aggression=aggression, threads=None, hunt_snmp=True)
    
    try:
        # BOTH TCP and UDP (restores 53, 123, etc)
        scanner.scan(0, 200, protocol_filter="BOTH")
        scanner.print_results()
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        scanner.print_results()


if __name__ == "__main__":
    main()