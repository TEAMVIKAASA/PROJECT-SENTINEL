import sys
from core.sniffer import start_sniffing

if __name__ == "__main__":
    try:
        start_sniffing()
    except KeyboardInterrupt:
        print("\n[!] Sentinel Guard shut down cleanly.")
        sys.exit(0)