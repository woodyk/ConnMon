# ConnMon - Real-time Network Connection Monitor

ConnMon is a powerful, cross-platform network monitoring tool designed to identify and track network connections in real-time. It supports MacOS, Linux, and Windows, providing detailed insights into TCP, UDP, and ICMP traffic on your system.

## Features

- Real-time monitoring of TCP, UDP, and ICMP connections
- Cross-platform support (MacOS, Linux, Windows)
- Ability to filter by specific network interfaces
- Daemon mode for background operation
- Logging in standard or JSON Line (jsonl) format
- Application identification for connections (optional)
- Existing TCP connection capture at startup

## Requirements

- Python 3.x
- Root/Administrator privileges (for packet capture)
- Required Python packages:
  - scapy
  - psutil
  - netifaces

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/woodyk/ConnMon.git
   cd ConnMon
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt 
   ```

## Usage

Basic usage:
```
sudo python3 ConnMon.py
```

### Command-line Options

- `--proto`: Comma-separated protocols to monitor (TCP, UDP, ICMP). Default is "tcp,udp,icmp".
- `--iface`: Comma-separated interfaces to monitor. Default is all interfaces.
- `--daemon`: Run as a daemon in the background ('start') or stop a running daemon ('stop').
- `--log`: Specify a log file (required for daemon mode).
- `--format`: Log format, either 'standard' or 'jsonl'. Default is 'standard'.
- `--show-app`: Show related application for each connection.

Examples:
```
# Monitor only TCP and UDP on eth0 interface
sudo python3 ConnMon.py --proto tcp,udp --iface eth0

# Run as a daemon with JSON Line logging
sudo python3 ConnMon.py --daemon start --log /var/log/connmon.log --format jsonl

# Stop the daemon
sudo python3 ConnMon.py --daemon stop

# Monitor with application information
sudo python3 ConnMon.py --show-app
```

## Output

ConnMon provides detailed information about network connections, including:

- Connection direction (Ingress/Egress)
- Protocol (TCP/UDP/ICMP)
- Source and destination IP addresses and ports
- Interface name
- Application name and PID (if --show-app is used)

## Permissions

ConnMon requires root/administrator privileges to capture network packets. Always run the script with sudo (on Unix-based systems) or as an administrator (on Windows).

## Contributing

Contributions to ConnMon are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is for educational and administrative purposes only. Always ensure you have the necessary permissions before monitoring network traffic, especially in corporate or shared environments.

## Author

Wadih Khairallah

## Support

For support, please open an issue on the GitHub repository.
