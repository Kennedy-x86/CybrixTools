import socket
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(ip, port, timeout=1):
    """
    Attempts to connect to a port on the given IP.
    Returns True if the port is open, else False.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


def scan_ports(ip, start_port, end_port, max_threads=100, timeout=1):
    """
    Scans a range of ports on the given IP address.
    Returns a list of open ports.
    """
    open_ports = []
    ports = list(range(start_port, end_port + 1))

    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port, timeout): port for port in ports}
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                continue

    return sorted(open_ports)


def run_main():
    print("\nCybrixTools - Port Scanner")
    print("==========================")

    print("1. Scan my own IP")
    print("2. Enter an external IP or hostname")
    choice = input("Choose an option (1 or 2): ").strip()

    if choice == "1":
        target_ip = socket.gethostbyname(socket.gethostname())
        print(f"Detected local IP: {target_ip}")
    elif choice == "2":
        target_ip = input("Enter the IP address or hostname to scan: ").strip()
        try:
            target_ip = socket.gethostbyname(target_ip)
        except socket.gaierror:
            print("Error: Could not resolve hostname.")
            return
    else:
        print("Invalid option. Exiting.")
        return

    print("\nPort Range Options:")
    print("1. Use default range (0 - 1023)")
    print("2. Specify custom port range")
    range_choice = input("Choose an option (1 or 2): ").strip()

    if range_choice == "1":
        port_start = 0
        port_end = 1023
    elif range_choice == "2":
        try:
            port_start = int(input("Enter starting port: "))
            port_end = int(input("Enter ending port: "))
            if port_start < 0 or port_end > 65535 or port_start > port_end:
                raise ValueError
        except ValueError:
            print("Invalid port range. Must be between 0 and 65535.")
            return
    else:
        print("Invalid option. Exiting.")
        return

    print(f"\nScanning {target_ip} from port {port_start} to {port_end}...\n")
    open_ports = scan_ports(target_ip, port_start, port_end)

    if open_ports:
        print("Open ports:")
        for port in open_ports:
            print(f"  - Port {port} is open")
    else:
        print("No open ports found in the specified range.")


if __name__ == "__main__":
    run_main()