# ThreatHound - Advanced Cybersecurity Analyzer

## 🔥 Overview
ThreatHound is a powerful **cybersecurity tool** designed to assist researchers in analyzing authentication logs, monitoring network traffic, detecting anomalies, and mitigating security threats. With an **interactive GUI**, it provides a user-friendly interface for seamless security analysis and reporting.

## 🚀 Features
- **🎨 ASCII Banner** – Displays an attractive banner with the tool name & creator.
- **📊 GUI-based Interface** – Simplifies user interaction for input handling.
- **📜 Log Analysis** – Extracts and analyzes IP addresses from authentication logs.
- **📡 Network Traffic Sniffing** – Captures live network packets and identifies unusual activity.
- **🔬 Anomaly Detection** – Uses machine learning (Isolation Forest) to detect suspicious patterns.
- **📡 Threat Intelligence** – Checks IPs against threat intelligence databases.
- **✉️ Email Alerts** – Notifies users when threats are detected.
- **🛡️ Auto-Mitigation** – Blocks malicious IPs using firewall rules.
- **📜 Detailed Reporting** – Saves logs and reports in **CSV & JSON** format for analysis.

## 🛠️ Installation
### 1️⃣ Clone the Repository
```bash
git clone https://github.com/njcryptx/ThreatHound.git
cd ThreatHound
```
### 2️⃣ Install Dependencies
```bash
pip install -r requirements.txt
```

## 🎯 Usage
### 1️⃣ Run the Tool
```bash
python network_sniffer.py
```
### 2️⃣ Enter Inputs in the GUI
- **Log File Path** – Path to authentication logs (default: `auth.log`)
- **Packet Count** – Number of network packets to capture (default: `50`)

### 3️⃣ Click "Start Analysis"
- The tool will analyze logs and sniff network traffic.
- View real-time logs, network activity, and detected anomalies.
- Identified threats are automatically **logged & mitigated**.

## 🛡️ How It Works
1. **Log Analysis** – Extracts IPs from authentication logs.
2. **Network Monitoring** – Captures packets from the specified network interface.
3. **Anomaly Detection** – Uses ML models to detect suspicious activity.
4. **Threat Intelligence** – Compares IPs with external threat databases.
5. **Auto-Mitigation** – Blocks flagged IPs via firewall commands.
6. **Alerts & Reporting** – Sends notifications and saves logs for further analysis.

## 📢 Setting Up Alerts
### 🔔 Email Alerts
To receive **email notifications** when threats are detected:
1. Open `network_sniffer.py` and find the `send_alert_email()` function.
2. Configure your **SMTP settings**:
   ```python
   SMTP_SERVER = "smtp.gmail.com"
   SMTP_PORT = 587
   EMAIL_ADDRESS = "your_email@gmail.com"
   EMAIL_PASSWORD = "your_password"
   ```
3. Modify the recipient email address in the function:
   ```python
   recipient = "your_alert_email@example.com"
   ```
4. Ensure **less secure app access** is enabled for your email provider (or use an app password).
5. Restart the script to activate email alerts.

### 🖥️ Desktop Notifications (Windows/Linux/macOS)
To enable **desktop pop-up alerts**:
1. Install the `plyer` package:
   ```bash
   pip install plyer
   ```
2. Modify the alert function in `network_sniffer.py`:
   ```python
   from plyer import notification

   def show_notification(title, message):
       notification.notify(
           title=title,
           message=message,
           timeout=5
       )
   ```
3. Call `show_notification("Threat Detected!", "Suspicious activity detected on the network.")` whenever a threat is flagged.

## 📜 Requirements
See `requirements.txt` for necessary Python packages.

## 🛠️ Dependencies (requirements.txt)
```
scapy
pandas
sklearn
requests
tk
plyer
```

## ⚠️ Disclaimer
ThreatHound is intended **for educational and ethical research purposes only**. Misuse of this tool is strictly prohibited.

## 💡 Contributing
Feel free to **fork** this repository, improve the tool, and submit pull requests!

---
👨‍💻 Created by **njcryptx** 🚀

