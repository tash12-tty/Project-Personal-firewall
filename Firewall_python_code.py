import os
from scapy.all import sniff, IP, TCP, UDP

LOG_FILE = "firewall_log.txt"

# ----------------------------
# User-defined firewall rules
# ----------------------------
# You can modify or add more
rules = [
    {"protocol": "tcp", "port": 80, "action": "allow"},   # Allow HTTP
    {"protocol": "tcp", "port": 22, "action": "block"},   # Block SSH
    {"protocol": "udp", "port": 53, "action": "allow"},   # Allow DNS
]

# ----------------------------
# Apply iptables rules
# ----------------------------
def apply_rules():
    os.system("sudo iptables -F")  # Flush all old rules
    for rule in rules:
        proto = rule["protocol"]
        port = rule["port"]
        action = rule["action"]

        if action == "block":
            os.system(f"sudo iptables -A INPUT -p {proto} --dport {port} -j DROP")
        else:
            os.system(f"sudo iptables -A INPUT -p {proto} --dport {port} -j ACCEPT")

    print("[+] Firewall rules applied successfully.\n")

# ----------------------------
# Log packets
# ----------------------------
logged_packets = set()

def log_packet(packet, status):
    key = (packet[IP].src, packet[IP].dst, status)
    if key not in logged_packets:
        with open(LOG_FILE, "a") as f:
            f.write(f"{packet[IP].src} -> {packet[IP].dst} | {status}\n")
        logged_packets.add(key)

# ----------------------------
# Monitor network packets
# ----------------------------
def monitor_traffic(packet):
    if IP in packet:
        if TCP in packet or UDP in packet:
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            proto = "tcp" if TCP in packet else "udp"

            for rule in rules:
                if rule["protocol"] == proto and rule["port"] == dst_port:
                    if rule["action"] == "block":
                        log_packet(packet, "BLOCKED")
                    # Skip logging allowed packets


if __name__ == "__main__":
    apply_rules()
    print("[+] Starting packet monitoring... Press Ctrl+C to stop.\n")
    sniff(prn=monitor_traffic, store=False)

