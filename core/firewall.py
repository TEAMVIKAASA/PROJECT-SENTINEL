import platform
import subprocess

CURRENT_OS = platform.system()

def block_ip(ip: str) -> bool:
    """Blocks an IP address at the OS firewall level."""
    # Prevent accidental self-lockout during testing
    if ip in ("127.0.0.1", "localhost", "::1"):
        print(f"[!] Simulation safeguard: Skipping firewall block for loopback {ip}.")
        return True

    try:
        if CURRENT_OS == "Windows":
            cmd = f'netsh advfirewall firewall add rule name="Sentinel_Block_{ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
        elif CURRENT_OS == "Linux":
            cmd = f'sudo iptables -A INPUT -s {ip} -j DROP'
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
        print(f"[🛡️ IPS ACTION] Firewall rule created: Blocked {ip}")
        return True
    except Exception as e:
        print(f"[-] Failed to apply firewall rule for {ip}: {e}")
        return False

def unblock_ip(ip: str) -> bool:
    """Removes the block rule for a previously banned IP."""
    if ip in ("127.0.0.1", "localhost", "::1"):
        return True

    try:
        if CURRENT_OS == "Windows":
            cmd = f'netsh advfirewall firewall delete rule name="Sentinel_Block_{ip}"'
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
        elif CURRENT_OS == "Linux":
            cmd = f'sudo iptables -D INPUT -s {ip} -j DROP'
            subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL)
        print(f"[+] Firewall rule removed for {ip}")
        return True
    except Exception as e:
        print(f"[-] Failed to remove firewall rule for {ip}: {e}")
        return False