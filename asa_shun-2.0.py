import re
import socket
from collections import defaultdict, deque
from datetime import datetime, timedelta
from getpass import getpass
from netmiko import ConnectHandler


net_device = {
     "device_type":"cisco_asa",
     "ip":"",
     "username":"",
     "password":"",
     "secret":"",
     "port":22,
 }


# Dictionary to store IP addresses and their timestamps
ip_tracker = defaultdict(deque)

# Regular expression to extract syslog message ID and user IP
syslog_pattern = re.compile(r'%ASA-\d-(\d+).*?user IP = (\d+\.\d+\.\d+\.\d+)')

def analyze_syslog(log_line, threshold, asa_host, asa_username, asa_password):
    """
    Analyze a syslog line to extract the message ID and user IP.
    If the message ID is 113005, track the IP address.
    """
    match = syslog_pattern.search(log_line)
    if match:
        message_id = match.group(1)
        user_ip = match.group(2)
        # local User auth generates ID 113015, remote user auth generates 113005
        if message_id == "113015" or "113005":
            print(log_line)
            print(f"\nDetected syslog ID {message_id}. User IP: {user_ip}")
            track_ip(user_ip, threshold, asa_host, asa_username, asa_password)

def track_ip(ip, threshold, asa_host, asa_username, asa_password):
    """
    Track an IP address and check if it appears a specified number of times within one hour.
    If the threshold is reached, block the IP on the ASA firewall.
    """
    now = datetime.now()
    ip_tracker[ip].append(now)

    print(ip_tracker)

    # Remove timestamps older than one hour
    while ip_tracker[ip] and now - ip_tracker[ip][0] > timedelta(hours=1):
        ip_tracker[ip].popleft()

    # If the IP appears the specified number of times within one hour, block it
    if len(ip_tracker[ip]) >= threshold:
        print(f"\nALERT: IP {ip} detected as an attacker ({threshold} occurrences within one hour). Blocking IP...\n")
        block_ip_on_asa(ip, asa_host, asa_username, asa_password)
        # Clear the IP's history to avoid repeated alerts
        ip_tracker[ip].clear()

def block_ip_on_asa(ip, asa_host, asa_username, asa_password):
    """
    Use SSH to connect to the Cisco ASA firewall and block the IP using the `shun` command.
    """
    try:
        net_device["ip"] = asa_host
        net_device["username"] = asa_username
        net_device["password"] = asa_password
        net_device["secret"] = asa_password

        ssh_conn = ConnectHandler(**net_device)
        shun_com = "shun " + ip
        output = ssh_conn.send_command(shun_com)
        print(output)
        ssh_conn.disconnect()
        
    except Exception as e:
        print(f"Failed to block IP {ip} on ASA firewall: {e}")

def start_syslog_server(udp_port, threshold, asa_host, asa_username, asa_password):
    """
    Start a UDP syslog server to listen for incoming syslog messages.
    """
    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('0.0.0.0', udp_port))
    print(f"\nSyslog server listening on UDP port {udp_port}...\n")

    while True:
        # Receive syslog messages
        data, addr = sock.recvfrom(8192)  # Buffer size is 8192 bytes
        log_line = data.decode('utf-8').strip()
        # print(f"Received syslog from {addr}: {log_line}")

        # Analyze the syslog message
        analyze_syslog(log_line, threshold, asa_host, asa_username, asa_password)

        # Track IPs and block if necessary
        #for ip in ip_tracker:
        #    track_ip(ip, threshold, asa_host, asa_username, asa_password)

def main():
    """
    Main function to configure and start the syslog server.
    """
    # User-defined parameters
    udp_port = int(input("Enter UDP port to listen on: "))*
    # udp_port = 9981
    threshold = int(input("Enter the threshold for blocking IPs (e.g., 3): "))
    #threshold =2
    asa_host = input("Enter ASA firewall IP address: ")
    #asa_host = "192.168.100.1"
    asa_username = input("Enter ASA username: ")
    # asa_username = "admin"
    #asa_password = input("Enter ASA password: ")
    asa_password = getpass(prompt="Enter ASA password: ")

    # Start the syslog server
    start_syslog_server(udp_port, threshold, asa_host, asa_username, asa_password)

if __name__ == "__main__":
    main()