import socket
import sys
import time

TARGET_HOST = "127.0.0.1"

def simulate_port_scan():
    print(f"[*] Simulating port scan against {TARGET_HOST} (hitting 60 ports)...")
    for port in range(1, 61):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect_ex((TARGET_HOST, port))
            s.close()
        except Exception:
            pass
    print("[+] Port scan simulation complete.")

def simulate_syn_flood():
    print(f"[*] Simulating rapid connection flood against {TARGET_HOST}:80 (50 requests)...")
    for _ in range(50):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            s.connect_ex((TARGET_HOST, 80))
            s.close()
        except Exception:
            pass
    print("[+] SYN flood simulation complete.")

if __name__ == "__main__":
    print("Select test attack:")
    print("1. Port Scan Reconnaissance")
    print("2. SYN / Connection Flood")
    choice = input("Enter choice (1 or 2): ").strip()

    if choice == "1":
        simulate_port_scan()
    elif choice == "2":
        simulate_syn_flood()
    else:
        print("Invalid choice.")