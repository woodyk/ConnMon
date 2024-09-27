#!/usr/bin/env python3
#
# ConnMon.py
# Author: Wadih Khairallah

from scapy.all import sniff, TCP, UDP, ICMP, IP
import os
import sys
import signal
import socket
import argparse
import netifaces
import psutil
import platform
from collections import defaultdict
import time
import json
import logging
from threading import Timer
from logging.handlers import RotatingFileHandler

# Global variables
LOCAL_IPS = set()
active_tcp_connections = {}
active_udp_flows = {}
active_icmp_flows = {}
icmp_timers = {}
daemon_pid_file = '/tmp/net_monitor_daemon.pid'

# Function to check if the script has enough privileges to run
def check_permissions():
    # For Unix-based systems (Linux/macOS)
    if os.geteuid() != 0:
        print("Error: This script requires root privileges to capture network traffic. Please run it using sudo.")
        sys.exit(1)

    # For Windows
    if platform.system() == 'Windows':
        # Checking if the script is run with administrator privileges
        try:
            import ctypes
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("Error: This script requires administrator privileges to capture network traffic. Please run it as an administrator.")
                sys.exit(1)
        except Exception as e:
            print(f"Error checking for administrator privileges: {e}")
            sys.exit(1)

# Get local IP addresses
def get_local_ips():
    local_ips = set()  # Use a set to avoid duplicates
    try:
        # Iterate over all interfaces and fetch associated IPs
        interfaces = netifaces.interfaces()
        for iface in interfaces:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                for addr in addrs[netifaces.AF_INET]:
                    local_ips.add(addr['addr'])  # Add IPv4 addresses
    except Exception as e:
        print(f"Error getting local IPs: {e}")
    return local_ips

LOCAL_IPS = get_local_ips()

# Logging setup
def setup_logging(log_file, log_format):
    logger = logging.getLogger('net_monitor')

    # Check if the logger already has handlers to prevent adding them again
    if not logger.hasHandlers():
        logger.setLevel(logging.INFO)

        if log_file:
            handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=2)
        else:
            handler = logging.StreamHandler(sys.stdout)

        if log_format == 'jsonl':
            formatter = logging.Formatter('%(message)s')
        else:
            formatter = logging.Formatter('%(asctime)s %(process)d %(levelname)s: %(message)s', datefmt='%b %d %H:%M:%S')

        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    # Return the logger with the appropriate handler attached
    return logger

# Log connection in jsonl format
def log_jsonl(logger, direction, proto, state, src_ip, src_port, dst_ip, dst_port, app_info=None):
    log_data = {
        "TIMESTAMP": int(time.time()),
        "DIRECTION": direction,
        "PROTO": proto,
        "STATE": state,
        "SRC_IP": src_ip,
        "SRC_PORT": src_port,
        "DST_IP": dst_ip,
        "DST_PORT": dst_port
    }
    if app_info:
        log_data["PROCESS"] = app_info  # Add the process information to the JSON if available

    logger.info(json.dumps(log_data))

# Get connection direction (Ingress/Egress)
def get_direction(src_ip, dst_ip):
    if src_ip in LOCAL_IPS:
        return "Egress"
    elif dst_ip in LOCAL_IPS:
        return "Ingress"
    return "Unknown"

# Capture existing TCP connections at startup
# Capture existing TCP connections at startup
def capture_existing_connections(show_app, logger, log_format):
    connections = psutil.net_connections(kind='tcp')
    for conn in connections:
        if conn.status == 'ESTABLISHED' and conn.laddr and conn.raddr:
            local_ip, local_port = conn.laddr
            remote_ip, remote_port = conn.raddr
            connection_id = (local_ip, local_port, remote_ip, remote_port)
            direction = get_direction(local_ip, remote_ip)
            app_info = get_application_info(conn.pid, show_app)  # Fetch the application info at startup
            active_tcp_connections[connection_id] = direction
            if log_format == 'jsonl':
                log_jsonl(logger, direction, 'TCP', 'open', local_ip, local_port, remote_ip, remote_port, app_info)
            else:
                logger.info(f"[+] {direction} Existing TCP Connection: Src: {local_ip}:{local_port} --> Dst: {remote_ip}:{remote_port} {app_info}")

# Handle TCP packets (connection tracking)
def handle_tcp_packet(packet, interface, show_app, logger, log_format):
    ip_layer = packet[IP]
    tcp_layer = packet[TCP]
    connection_id = (ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport)

    # TCP connection establishment (SYN without ACK)
    if tcp_layer.flags & 0x02:  # SYN flag is set
        if connection_id not in active_tcp_connections:
            direction = get_direction(ip_layer.src, ip_layer.dst)
            app_info = get_application_info_by_addr(ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport, show_app)
            if log_format == 'jsonl':
                log_jsonl(logger, direction, 'TCP', 'open', ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport, app_info)
            else:
                logger.info(f"[+] {direction} TCP Connection Established: Src: {ip_layer.src}:{tcp_layer.sport} --> Dst: {ip_layer.dst}:{tcp_layer.dport} on Interface: {interface} {app_info}")
            active_tcp_connections[connection_id] = direction

    # TCP connection termination (FIN or RST flags)
    if tcp_layer.flags & 0x01 or tcp_layer.flags & 0x04:  # FIN or RST flags are set
        if connection_id in active_tcp_connections:
            direction = active_tcp_connections.pop(connection_id, "Unknown")
            app_info = get_application_info_by_addr(ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport, show_app)  # Fetch app info again for closure
            if log_format == 'jsonl':
                log_jsonl(logger, direction, 'TCP', 'close', ip_layer.src, tcp_layer.sport, ip_layer.dst, tcp_layer.dport, app_info)
            else:
                logger.info(f"[-] {direction} TCP Connection Closed: Src: {ip_layer.src}:{tcp_layer.sport} --> Dst: {ip_layer.dst}:{tcp_layer.dport} on Interface: {interface} {app_info}")

# Handle UDP packets (stateless flow tracking)
def handle_udp_packet(packet, interface, show_app, logger, log_format):
    ip_layer = packet[IP]
    udp_layer = packet[UDP]
    flow_id = (ip_layer.src, udp_layer.sport, ip_layer.dst, udp_layer.dport)

    if flow_id not in active_udp_flows:
        direction = get_direction(ip_layer.src, ip_layer.dst)
        app_info = get_application_info_by_addr(ip_layer.src, udp_layer.sport, ip_layer.dst, udp_layer.dport, show_app)
        if log_format == 'jsonl':
            log_jsonl(logger, direction, 'UDP', 'open', ip_layer.src, udp_layer.sport, ip_layer.dst, udp_layer.dport, app_info)
        else:
            logger.info(f"[+] {direction} UDP Flow: Src: {ip_layer.src}:{udp_layer.sport} --> Dst: {ip_layer.dst}:{udp_layer.dport} on Interface: {interface} {app_info}")
        active_udp_flows[flow_id] = direction

# Function to handle ICMP packets (ping detection)
def handle_icmp_packet(packet, interface, show_app, logger, log_format):
    ip_layer = packet[IP]
    icmp_layer = packet[ICMP]
    flow_id = (ip_layer.src, ip_layer.dst)

    # Handle ICMP Echo Request (start of ping)
    if icmp_layer.type == 8:  # Echo Request
        if flow_id not in active_icmp_flows:
            direction = get_direction(ip_layer.src, ip_layer.dst)
            app_info = get_application_info_by_addr(ip_layer.src, 0, ip_layer.dst, 0, show_app)  # ICMP doesn't have ports, use 0
            if log_format == 'jsonl':
                log_jsonl(logger, direction, 'ICMP', 'open', ip_layer.src, 0, ip_layer.dst, 0, app_info)
            else:
                logger.info(f"[+] {direction} ICMP Echo Request (Ping) Started: Src: {ip_layer.src} --> Dst: {ip_layer.dst} on Interface: {interface}")
            active_icmp_flows[flow_id] = direction
        reset_icmp_timer(flow_id, ip_layer.src, ip_layer.dst, interface, logger, log_format)

# Reset ICMP timer (ping stops if no echo request is received after timeout)
def reset_icmp_timer(flow_id, src_ip, dst_ip, interface, logger, log_format):
    timeout = 5  # 5 seconds timeout for ping stop detection
    if flow_id in icmp_timers:
        icmp_timers[flow_id].cancel()  # Cancel any existing timers
    timer = Timer(timeout, icmp_timeout_callback, [flow_id, src_ip, dst_ip, interface, logger, log_format])
    icmp_timers[flow_id] = timer
    timer.start()

def icmp_timeout_callback(flow_id, src_ip, dst_ip, interface, logger, log_format):
    if flow_id in active_icmp_flows:
        direction = active_icmp_flows.pop(flow_id, "Unknown")
        if log_format == 'jsonl':
            log_jsonl(logger, direction, 'ICMP', 'close', src_ip, 0, dst_ip, 0)
        else:
            logger.info(f"[-] {direction} ICMP Echo Request (Ping) Stopped: Src: {src_ip} --> Dst: {dst_ip} on Interface: {interface}")
        icmp_timers.pop(flow_id, None)

# Handle packet callback
def packet_callback(packet, protocols, interfaces, show_app, logger, log_format):
    if IP in packet:
        ip_layer = packet[IP]
        interface = packet.sniffed_on

        # Check if the interface is one of the specified interfaces
        if interfaces and interface not in interfaces:
            return

        # Protocol-specific handling
        if TCP in packet and 'tcp' in protocols:
            handle_tcp_packet(packet, interface, show_app, logger, log_format)
        elif UDP in packet and 'udp' in protocols:
            handle_udp_packet(packet, interface, show_app, logger, log_format)
        elif ICMP in packet and 'icmp' in protocols:
            handle_icmp_packet(packet, interface, show_app, logger, log_format)

# Function to get the application information based on PID
def get_application_info(pid, show_app):
    if not show_app or pid is None:
        return ""
    try:
        process = psutil.Process(pid)
        return f"[App: {process.name()} (PID: {pid})]"
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "[App: Unknown]"

# Function to get application info by matching local/remote IP and port
def get_application_info_by_addr(src_ip, src_port, dst_ip, dst_port, show_app):
    if not show_app:
        return ""
    try:
        connections = psutil.net_connections(kind='inet')
        for conn in connections:
            if conn.laddr == (src_ip, src_port) and conn.raddr == (dst_ip, dst_port):
                return get_application_info(conn.pid, show_app)
    except psutil.AccessDenied:
        pass
    return "[App: Unknown]"

# Daemonize the script to run in the background
def daemonize(log_file, logger):
    if os.fork():
        sys.exit(0)  # Exit the parent process
    os.setsid()  # Create a new session
    if os.fork():
        sys.exit(0)  # Exit the second parent process
    sys.stdout.flush()
    sys.stderr.flush()

    # Redirect standard file descriptors to /dev/null
    with open('/dev/null', 'w') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
        os.dup2(devnull.fileno(), sys.stdout.fileno())
        os.dup2(devnull.fileno(), sys.stderr.fileno())

    # Write the PID file for the daemon
    with open(daemon_pid_file, 'w') as pid_file:
        pid_file.write(str(os.getpid()))

    logger.info("Daemon started.")

# Function to stop the daemon
def stop_daemon():
    if os.path.exists(daemon_pid_file):
        with open(daemon_pid_file, 'r') as pid_file:
            pid = int(pid_file.read().strip())
        os.kill(pid, signal.SIGTERM)
        os.remove(daemon_pid_file)
        print("Daemon stopped.")
    else:
        print("No running daemon found.")

# Graceful shutdown on Ctrl+C
def shutdown_handler(sig, frame):
    print("\nShutting down the network monitor.")
    if os.path.exists(daemon_pid_file):
        os.remove(daemon_pid_file)
    sys.exit(0)

# Main function to start packet sniffer
def main():
    parser = argparse.ArgumentParser(description='Network Traffic Monitor')
    parser.add_argument('--proto', type=str, default="tcp,udp,icmp", help="Comma-separated protocols to monitor (TCP, UDP, ICMP)")
    parser.add_argument('--iface', type=str, default=None, help="Comma-separated interfaces to monitor (default is all)")
    parser.add_argument('--daemon', type=str, choices=['start', 'stop'], help="Run as a daemon in the background or stop a running daemon")
    parser.add_argument('--log', type=str, help="Log file for daemon mode")
    parser.add_argument('--format', type=str, choices=['standard', 'jsonl'], default='standard', help="Log format: 'standard' or 'jsonl'")
    parser.add_argument('--show-app', action='store_true', help="Show related application for each connection")
    args = parser.parse_args()

    # Check if the script has enough privileges
    check_permissions()

    # Parse protocols and interfaces
    protocols = [proto.lower() for proto in args.proto.split(',')]
    interfaces = args.iface.split(',') if args.iface else None
    show_app = args.show_app
    log_format = args.format
    log_file = args.log

    # Handle daemon start/stop
    if args.daemon == 'start':
        if not log_file:
            print("Error: --log <filename> is required in daemon mode.")
            sys.exit(1)
        logger = setup_logging(log_file, log_format)
        daemonize(log_file, logger)
    elif args.daemon == 'stop':
        stop_daemon()
        sys.exit(0)

    # Handle SIGINT (Ctrl+C) for graceful shutdown
    signal.signal(signal.SIGINT, shutdown_handler)

    logger = setup_logging(log_file, log_format)
    logger.info(f"Starting network traffic monitor on protocols: {protocols}")
    if interfaces:
        logger.info(f"Monitoring interfaces: {interfaces}")
    
    # Capture existing TCP connections
    if 'tcp' in protocols:
        capture_existing_connections(show_app, logger, log_format)

    # Start sniffing network traffic
    sniff(prn=lambda packet: packet_callback(packet, protocols, interfaces, show_app, logger, log_format), store=0, iface=interfaces)

if __name__ == "__main__":
    main()

