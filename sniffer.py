import socket
import threading
from queue import Queue
import re

# List of common and lesser-known ports to scan with their definitions
PORTS_TO_SCAN = {
    20: "FTP Data Transfer",
    21: "FTP Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP (Submission)",
    993: "IMAPS",
    995: "POP3S",
    135: "Microsoft RPC",
    139: "NetBIOS",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    1723: "PPTP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8081: "HTTP Alternate",
    8443: "HTTPS Alternate",
    8888: "HTTP Alternate",
    9000: "SonarQube",
    9200: "Elasticsearch",
    10000: "Webmin"
}

def is_valid_ip(ip):
    # Validate IPv4 address format
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if not pattern.match(ip):
        return False
    # Ensure each octet is in the range 0-255
    octets = ip.split('.')
    return all(0 <= int(octet) <= 255 for octet in octets)

def scan_port(ip, port, open_ports):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports.append(port)
        sock.close()
    except socket.error as e:
        print(f"Error scanning port {port}: {e}")

def worker(ip, queue, open_ports):
    while not queue.empty():
        port = queue.get()
        scan_port(ip, port, open_ports)
        queue.task_done()

def scan_ports(ip, num_threads=100):
    open_ports = []
    queue = Queue()
    threads = []

    for port in PORTS_TO_SCAN.keys():
        queue.put(port)

    for _ in range(num_threads):
        thread = threading.Thread(target=worker, args=(ip, queue, open_ports))
        thread.start()
        threads.append(thread)

    queue.join()

    for thread in threads:
        thread.join()

    return open_ports

if __name__ == "__main__":
    while True:
        ip = input("Enter the IP address to scan (or type 'exit' to quit): ")
        if ip.lower() == 'exit':
            print("Exiting the program.")
            break
        if is_valid_ip(ip):
            print(f"Scanning {ip} for open ports...")
            open_ports = scan_ports(ip, num_threads=100)
            if open_ports:
                print("\nOpen ports:")
                for port in open_ports:
                    print(f"Port {port}: {PORTS_TO_SCAN.get(port, 'Unknown Service')}")
            else:
                print("\nNo open ports found.")
        else:
            print("Invalid IP address. Please enter a valid IPv4 address.")