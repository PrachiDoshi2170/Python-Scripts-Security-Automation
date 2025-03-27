import subprocess
import csv
import threading
import queue

# Lock for writing to CSV
lock = threading.Lock()

# Queue for IPs (ensures sequential execution with threading)
ip_queue = queue.Queue()

def scan_target(ip, csv_writer):
    #Scans a single IP using nmap and saves results.
    print(f"Starting scan for {ip}...\n")

    # Run nmap with verbose output and scan all ports (-p-)
    try:
        process = subprocess.Popen(
            ["nmap","-p-", "-sS", "-T4", "--min-rate=1000","--max-rate=3000", "-v", ip],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        # Print output in real time
        output_lines = []
        for line in process.stdout:
            print(line, end="")  # Real-time verbose output
            output_lines.append(line.strip())

        process.wait()  # Ensure process completes

        # Extract relevant information
        parsed_results = parse_nmap_output(output_lines, ip)

        # Write results to CSV
        with lock:
            for entry in parsed_results:
                csv_writer.writerow(entry)

    except Exception as e:
        print(f"Error scanning {ip}: {e}")

# Note working

def parse_nmap_output(output_lines, ip):
    """Parses nmap's output and structures it into a list of dictionaries."""
    results = []
    for line in output_lines:
        if "/" in line and "open" in line:  # Extracting open ports
            parts = line.split()
            port_info = parts[0].split("/")  # Extracting port number & protocol
            port = port_info[0]
            protocol = port_info[1]
            state = parts[1]
            service = parts[2] if len(parts) > 2 else "unknown"

            results.append({"IP Address": ip, "Port": port, "Protocol": protocol, "State": state, "Service": service})
    return results

def worker(csv_writer):
    """Worker thread that scans one IP at a time from the queue."""
    while not ip_queue.empty():
        ip = ip_queue.get()
        scan_target(ip, csv_writer)
        ip_queue.task_done()

def main():
    input_file = "ips.txt"  # File containing IPs
    output_file = "scan_results.csv"

    # Read IPs and add to queue
    with open(input_file, "r") as f:
        ip_list = [line.strip() for line in f if line.strip()]

    for ip in ip_list:
        ip_queue.put(ip)

    # Open CSV file for writing
    with open(output_file, "w", newline="") as csvfile:
        fieldnames = ["IP Address", "Port", "Protocol", "State", "Service"]
        csv_writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        csv_writer.writeheader()

        # Start worker thread (only one IP scanned at a time)
        thread = threading.Thread(target=worker, args=(csv_writer,))
        thread.start()
        thread.join()  # Ensures sequential execution

    print(f"\nScanning complete. Results saved to {output_file}")

if __name__ == "__main__":
    main()
