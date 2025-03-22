import time
import logging
import smtplib
from email.mime.text import MIMEText
from scapy.all import sniff, IP
from collections import defaultdict
import subprocess
import configparser
import os
from datetime import datetime

# Load configuration from config.ini
config = configparser.ConfigParser()
config_file = 'config.ini'

# Create a default config file if it doesn't exist
if not os.path.exists(config_file):
    config['MONITOR'] = {
        'monitor_duration': '60',  # in seconds
        'packet_threshold': '1',
        'suspicious_ip_threshold': '10',
        'target_ip': '13.53.115.71'
    }
    config['LOGGING'] = {
        'log_file': 'ddos_monitor.log',
        'log_level': 'INFO'
    }
    config['ALERT'] = {
        'enable_email_alert': 'False',
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': '587',
        'smtp_username': 'hasnainallwebfor@gmail.com',
        'smtp_password': 'gskhhxgmpsdcsbbt',
        'recipient_email': '229219@theemcoe.org'
    }
    config['BLOCKING'] = {
        'enable_blocking': 'False'
    }
    with open(config_file, 'w') as f:
        config.write(f)
    print(f"Default configuration file created at {config_file}. Please review and update it as needed.")
    exit(0)
else:
    config.read(config_file)

# Configuration Parameters
MONITOR_DURATION = int(config['MONITOR']['monitor_duration'])  # Duration to monitor in seconds
PACKET_THRESHOLD = int(config['MONITOR']['packet_threshold'])  # Number of packets to trigger alert
SUSPICIOUS_IP_THRESHOLD = int(config['MONITOR']['suspicious_ip_threshold'])  # Packets from a single IP to be suspicious
TARGET_IP = config['MONITOR']['target_ip']  # Target IP address

# Logging Configuration
LOG_FILE = config['LOGGING']['log_file']
LOG_LEVEL = config['LOGGING']['log_level'].upper()

logging.basicConfig(
    filename=LOG_FILE,
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Email Alert Configuration
ENABLE_EMAIL_ALERT = config.getboolean('ALERT', 'enable_email_alert')
SMTP_SERVER = config['ALERT']['smtp_server']
SMTP_PORT = config.getint('ALERT', 'smtp_port')
SMTP_USERNAME = config['ALERT']['smtp_username']
SMTP_PASSWORD = config['ALERT']['smtp_password']
RECIPIENT_EMAIL = config['ALERT']['recipient_email']

# IP Blocking Configuration
ENABLE_BLOCKING = config.getboolean('BLOCKING', 'enable_blocking')

# Global Variables
packet_count = 0
ip_counter = defaultdict(int)
start_time = time.time()

def send_email_alert(subject, body):
    """Send an email alert."""
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SMTP_USERNAME
    msg['To'] = RECIPIENT_EMAIL

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        logging.info("Email alert sent successfully.")
    except Exception as e:
        logging.error(f"Failed to send email alert: {e}")

def block_ip(ip_address):
    """Block an IP address using firewall rules (iptables example)."""
    try:
        # Example for Linux using iptables
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', ip_address, '-j', 'DROP'], check=True)
        logging.info(f"Blocked IP address: {ip_address}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to block IP {ip_address}: {e}")

def analyze_packet(packet):
    global packet_count
    if IP in packet:
        ip_layer = packet[IP]
        # Filter packets directed to the TARGET_IP
        if ip_layer.dst == TARGET_IP:
            packet_count += 1
            src_ip = ip_layer.src
            ip_counter[src_ip] += 1

def monitor():
    logging.info(f"Starting DDoS monitoring for {MONITOR_DURATION} seconds...")
    logging.info(f"Monitoring traffic directed to IP: {TARGET_IP}")
    print(f"Starting DDoS monitoring for {MONITOR_DURATION} seconds...")
    print(f"Monitoring traffic directed to IP: {TARGET_IP}")
    
    sniff(timeout=MONITOR_DURATION, prn=analyze_packet, filter=f"dst host {TARGET_IP}")
    end_time = time.time()
    duration = end_time - start_time
    logging.info(f"Monitoring completed in {duration:.2f} seconds.")
    logging.info(f"Total packets captured: {packet_count}")
    print(f"\nMonitoring completed in {duration:.2f} seconds.")
    print(f"Total packets captured: {packet_count}")

    # Check overall traffic volume
    if packet_count > PACKET_THRESHOLD:
        alert_msg = f"ALERT: High traffic volume detected! {packet_count} packets in {MONITOR_DURATION} seconds."
        logging.warning(alert_msg)
        print(alert_msg)
        if ENABLE_EMAIL_ALERT:
            send_email_alert("DDoS Alert: High Traffic Volume", alert_msg)

    # Identify suspicious IPs
    suspicious_ips = {ip: count for ip, count in ip_counter.items() if count > SUSPICIOUS_IP_THRESHOLD}
    if suspicious_ips:
        alert_msg = "\nSuspicious IP addresses detected:"
        logging.warning(alert_msg)
        print(alert_msg)
        for ip, count in suspicious_ips.items():
            msg = f" - {ip}: {count} packets"
            logging.warning(msg)
            print(msg)
            if ENABLE_BLOCKING:
                block_ip(ip)
            if ENABLE_EMAIL_ALERT:
                send_email_alert("DDoS Alert: Suspicious IP Detected", msg)
    else:
        no_alert_msg = "\nNo suspicious IP addresses detected."
        logging.info(no_alert_msg)
        print(no_alert_msg)

    # Generate Summary Report
    generate_report(duration)

def generate_report(duration):
    """Generate a summary report of the monitoring session."""
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = (
        f"\n----- DDoS Monitoring Report -----\n"
        f"Time: {report_time}\n"
        f"Monitoring Duration: {duration:.2f} seconds\n"
        f"Target IP: {TARGET_IP}\n"
        f"Total Packets Captured: {packet_count}\n"
    )
    # Overall traffic volume
    if packet_count > PACKET_THRESHOLD:
        report += f"High traffic volume detected: {packet_count} packets exceeded threshold of {PACKET_THRESHOLD}.\n"
    else:
        report += f"Traffic volume within normal limits: {packet_count} packets.\n"

    # Suspicious IPs
    if ip_counter:
        report += "Top 10 IPs by packet count:\n"
        sorted_ips = sorted(ip_counter.items(), key=lambda item: item[1], reverse=True)
        for ip, count in sorted_ips[:10]:
            report += f" - {ip}: {count} packets\n"
    else:
        report += "No IPs detected.\n"

    report += "----- End of Report -----\n"

    # Save report to a file
    report_file = f"ddos_report_{int(time.time())}.txt"
    try:
        with open(report_file, 'w') as f:
            f.write(report)
        logging.info(f"Summary report generated: {report_file}")
        print(f"Summary report saved to {report_file}")
    except Exception as e:
        logging.error(f"Failed to write summary report: {e}")
        print(f"Failed to write summary report: {e}")

if __name__ == "__main__":
    monitor()
