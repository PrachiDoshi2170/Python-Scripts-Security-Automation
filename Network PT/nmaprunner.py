''' Testing purpose, use scanme.nmap.org to check whether it working for you or not'''
import subprocess
import pandas as pd
import threading
import queue

# Queue for IPs
ip_queue = queue.Queue()

# Shared list for storing scan results
scan_results = []
lock = threading.Lock()  # Ensures thread-safe operations

def scan_target(ip):
    # Scans a single IP and stores results.
    print(f"\n[DEBUG] Scanning {ip}...\n")

    try:
        # Run Nmap with all ports, verbose mode, and faster scanning
        process = subprocess.Popen(
            ["nmap", "-p1-100", ip],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            universal_newlines=True
        )

        output_lines = []
        for line in process.stdout:
            print(line, end="")  # Real-time output
            output_lines.append(line.strip())

        process.wait()  # Ensure process completes

        # Parse and print extracted results
        parsed_results = parse_nmap_output(output_lines, ip)
        if parsed_results:
            print(f"[DEBUG] Parsed results for {ip}: {parsed_results}\n")
        else:
            print(f"[DEBUG] No open ports found for {ip}\n")

        # Store results in a thread-safe manner
        with lock:
            scan_results.extend(parsed_results)

    except Exception as e:
        print(f"[ERROR] Scanning {ip} failed: {e}")

def parse_nmap_output(output_lines, ip):
    # Parses nmap output and extracts open ports."""
    results = []
    for line in output_lines:
        if "/" in line and "open" in line:  # Checking if line contains port info
            try:
                parts = line.split()
                port_info = parts[0].split("/")  # Port and protocol

                port = port_info[0]
                protocol = port_info[1]
                state = parts[1]
                service = parts[2] if len(parts) > 2 else "unknown"

                # Adding parsed data to results
                results.append({
                    "IP Address": ip,
                    "Port": port,
                    "Protocol": protocol,
                    "State": state,
                    "Service": service
                })
            except IndexError:
                # Skip lines that don't match the expected format
                print(f"[WARNING] Malformed line in Nmap output: {line}")
                continue
    return results

def worker():
    # Worker thread that scans one IP at a time
    while not ip_queue.empty():
        ip = ip_queue.get()
        scan_target(ip)
        ip_queue.task_done()

def save_results_to_csv(filename="scan_results.csv"):
    """Saves scan results to a CSV file using pandas."""
    if scan_results:
        print(f"\n[DEBUG] Final scan results before writing CSV:\n{scan_results}\n")
        df = pd.DataFrame(scan_results)
        df.to_csv(filename, index=False)
        print(f"[SUCCESS] Results saved to {filename}")
    else:
        print("\n[WARNING] No open ports found. CSV file not created.")

def main():
    input_file = "ips.txt"  # File containing IPs
    output_file = "scan_results.csv"

    # Read and validate IPs
    with open(input_file, "r") as f:
        ip_list = [line.strip() for line in f if line.strip()]

    if not ip_list:
        print("[ERROR] No IPs found in the input file. Exiting.")
        return

    # Load IPs into queue
    for ip in ip_list:
        ip_queue.put(ip)

    # Start single worker thread
    thread = threading.Thread(target=worker)
    thread.start()
    thread.join()  # Ensures sequential execution

    # Save results to CSV
    save_results_to_csv(output_file)

if __name__ == "__main__":
    main()
