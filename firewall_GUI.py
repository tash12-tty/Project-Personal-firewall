import os
import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff, IP, TCP, UDP

rules = []
LOG_FILE = "firewall_log.txt"

def apply_rules():
    os.system("sudo iptables -F")
    for rule in rules:
        if rule["action"] == "block":
            os.system(f"sudo iptables -A INPUT -p {rule['protocol']} --dport {rule['port']} -j DROP")
        else:
            os.system(f"sudo iptables -A INPUT -p {rule['protocol']} --dport {rule['port']} -j ACCEPT")
    messagebox.showinfo("Firewall", "Rules applied successfully!")

def add_rule():
    protocol = proto_entry.get().lower()
    port = int(port_entry.get())
    action = action_entry.get().lower()
    rules.append({"protocol": protocol, "port": port, "action": action})
    listbox.insert(tk.END, f"{protocol.upper()} | Port {port} | {action.upper()}")
    proto_entry.delete(0, tk.END)
    port_entry.delete(0, tk.END)
    action_entry.delete(0, tk.END)

def log_packet(packet, status):
    with open(LOG_FILE, "a") as f:
        f.write(f"{packet[IP].src} -> {packet[IP].dst} | {status}\n")

def monitor_traffic(packet):
    if IP in packet:
        if TCP in packet or UDP in packet:
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            proto = "tcp" if TCP in packet else "udp"

            for rule in rules:
                if rule["protocol"] == proto and rule["port"] == dst_port:
                    if rule["action"] == "block":
                        log_packet(packet, "BLOCKED")
                    else:
                        log_packet(packet, "ALLOWED")

def start_monitor():
    messagebox.showinfo("Firewall", "Monitoring started. Press Ctrl+C in terminal to stop.")
    sniff(prn=monitor_traffic, store=False)

# ----------------- GUI SECTION -----------------
root = tk.Tk()
root.title("Kali Linux Simple Firewall")

tk.Label(root, text="Protocol (tcp/udp):").grid(row=0, column=0)
proto_entry = tk.Entry(root)
proto_entry.grid(row=0, column=1)

tk.Label(root, text="Port:").grid(row=1, column=0)
port_entry = tk.Entry(root)
port_entry.grid(row=1, column=1)

tk.Label(root, text="Action (allow/block):").grid(row=2, column=0)
action_entry = tk.Entry(root)
action_entry.grid(row=2, column=1)

tk.Button(root, text="Add Rule", command=add_rule).grid(row=3, column=0, pady=10)
tk.Button(root, text="Apply Rules", command=apply_rules).grid(row=3, column=1, pady=10)
tk.Button(root, text="Start Monitor", command=start_monitor).grid(row=4, column=0, columnspan=2)

tk.Label(root, text="Current Rules:").grid(row=5, column=0)
listbox = tk.Listbox(root, width=40)
listbox.grid(row=6, column=0, columnspan=2)

root.mainloop()

