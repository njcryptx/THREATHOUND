import os
import json
import smtplib
import requests
import tkinter as tk
from tkinter import scrolledtext
import platform
import pandas as pd
import scapy.all as scapy
from sklearn.ensemble import IsolationForest

def display_banner():
    banner = """
'########:'##::::'##:'########::'########::::'###::::'########:'##::::'##::'#######::'##::::'##:'##::: ##:'########::
... ##..:: ##:::: ##: ##.... ##: ##.....::::'## ##:::... ##..:: ##:::: ##:'##.... ##: ##:::: ##: ###:: ##: ##.... ##:
::: ##:::: ##:::: ##: ##:::: ##: ##::::::::'##:. ##::::: ##:::: ##:::: ##: ##:::: ##: ##:::: ##: ####: ##: ##:::: ##:
::: ##:::: #########: ########:: ######:::'##:::. ##:::: ##:::: #########: ##:::: ##: ##:::: ##: ## ## ##: ##:::: ##:
::: ##:::: ##.... ##: ##.. ##::: ##...:::: #########:::: ##:::: ##.... ##: ##:::: ##: ##:::: ##: ##. ####: ##:::: ##:
::: ##:::: ##:::: ##: ##::. ##:: ##::::::: ##.... ##:::: ##:::: ##:::: ##: ##:::: ##: ##:::: ##: ##:. ###: ##:::: ##:
::: ##:::: ##:::: ##: ##:::. ##: ########: ##:::: ##:::: ##:::: ##:::: ##:. #######::. #######:: ##::. ##: ########::
:::..:::::..:::::..::..:::::..::........::..:::::..:::::..:::::..:::::..:::.......::::.......:::..::::..::........:::   
    ThreatHound - Cybersecurity Analyzer
    Created by: njcryptx
    """
    print(banner)

def read_auth_logs(log_path="auth.log"):
    logs = []
    if os.path.exists(log_path):
        with open(log_path, "r") as file:
            for line in file:
                if "Failed password" in line or "Accepted password" in line:
                    logs.append(line.strip())
    return logs

def extract_ip_addresses(logs):
    ip_list = []
    for log in logs:
        parts = log.split()
        for part in parts:
            if part.count('.') == 3:
                ip_list.append(part)
    return list(set(ip_list))

def sniff_packets(packet_count=50):
    packets = scapy.sniff(count=packet_count, store=False)
    captured = []
    for pkt in packets:
        if scapy.IP in pkt:
            src = pkt[scapy.IP].src
            dst = pkt[scapy.IP].dst
            captured.append((src, dst))
    return captured

def detect_anomalies(ip_list):
    if not ip_list:
        return []
    df = pd.DataFrame(ip_list, columns=["source_ip", "destination_ip"])
    df["encoded_src"] = pd.factorize(df["source_ip"])[0]
    df["encoded_dst"] = pd.factorize(df["destination_ip"])[0]
    model = IsolationForest(contamination=0.1)
    df["anomaly"] = model.fit_predict(df[["encoded_src", "encoded_dst"]])
    anomalies = df[df["anomaly"] == -1]
    anomalies.to_csv("anomalies.csv", index=False)
    with open("anomalies.json", "w") as f:
        json.dump(anomalies.to_dict(), f, indent=4)
    return anomalies.values.tolist()

def send_email_alert(message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login("your_email@gmail.com", "password")
    server.sendmail("your_email@gmail.com", "receiver_email@gmail.com", message)
    server.quit()

def check_blacklist(ip):
    response = requests.get(f"https://www.abuseipdb.com/check/{ip}")
    return response.status_code == 200

def block_ip(ip):
    system_platform = platform.system()
    if system_platform == "Linux":
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
    elif system_platform == "Windows":
        os.system(f"netsh advfirewall firewall add rule name=\"Block {ip}\" dir=in action=block remoteip={ip}")
    else:
        print(f"Unsupported platform: {system_platform}. Could not block IP.")

def run_analysis():
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, "[🔍] Reading authentication logs...\n")
    logs = read_auth_logs(log_entry.get())
    output_text.insert(tk.END, "[⚡] Extracting IP addresses...\n")
    ip_addresses = extract_ip_addresses(logs)
    output_text.insert(tk.END, "[🕵️] Sniffing network traffic...\n")
    packets = sniff_packets(int(packet_entry.get()))
    output_text.insert(tk.END, "[🔬] Detecting anomalies...\n")
    anomalies = detect_anomalies(packets + [(ip, None) for ip in ip_addresses])
    if anomalies:
        output_text.insert(tk.END, "[🚨] Suspicious activity detected!\n")
        for anomaly in anomalies:
            output_text.insert(tk.END, f"Suspicious connection: {anomaly[0]} -> {anomaly[1]}\n")
            if check_blacklist(anomaly[0]):
                output_text.insert(tk.END, f"[⚠️] {anomaly[0]} is a known malicious IP!\n")
                block_ip(anomaly[0])
                send_email_alert(f"ALERT: Malicious IP detected: {anomaly[0]}")
    else:
        output_text.insert(tk.END, "[✅] No anomalies detected.\n")

display_banner()
root = tk.Tk()
root.title("ThreatHound - Cybersecurity Analyzer")
tk.Label(root, text="Enter Log File Path:").pack()
log_entry = tk.Entry(root, width=50)
log_entry.pack()
log_entry.insert(0, "auth.log")
tk.Label(root, text="Enter Number of Packets to Capture:").pack()
packet_entry = tk.Entry(root, width=10)
packet_entry.pack()
packet_entry.insert(0, "50")
start_button = tk.Button(root, text="Start Analysis", command=run_analysis)
start_button.pack()
output_text = scrolledtext.ScrolledText(root, width=70, height=20)
output_text.pack()
root.mainloop()
