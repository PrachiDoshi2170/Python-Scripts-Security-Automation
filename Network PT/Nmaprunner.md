# Nmap Multi-Threaded Scanner

## Overview
This script performs **multi-threaded Nmap scans** on a list of IP addresses and saves the results to a CSV file. It is useful for **network administrators, cybersecurity professionals, and penetration testers** who need to quickly identify open ports on multiple targets. This scanner only works if you are performing scans on ips or subnets. For automating OS or version detection, I will be creating a new .py file or add an extra function that iterated through all the open ports and perform the OS/version detection, but that is another story to unfold

## Features
- **Multi-threaded execution** for faster scans
- **Parses Nmap output** and extracts open ports, protocols, and services
- **Exports results to a CSV file** for easy analysis, but only for open ports 

## Requirements
- Python 3.x
- Nmap installed and accessible from the command line
- Required Python libraries:
  ```bash
  pip install pandas
  ```

## Usage
1. **Prepare the input file and output file:**
   - Create a file named `ips.txt` containing a list of IP addresses, one per line in the same folder.
   - Create a file named `scan_resulta.csv` to store the output of the scan. 
> [!IMPORTANT]
> Remember to change the ***name of the file*** in the code when you perform new scan or save the data somewhere else before you perform another scan otherwise the data from your new scan will overwrite the data from your previous scan.

2. **Run the script:**
   ```bash
   python nmap_scan.py
   ```

3. **Check the results:**
   - The output will be stored in `scan_results.csv`.

## Example Output (CSV)
| IP Address  | Port | Protocol | State | Service |
|-------------|------|----------|-------|---------|
| 192.168.1.1 | 22   | tcp      | open  | ssh     |
| 192.168.1.1 | 80   | tcp      | open  | http    |

## Notes
- To test if Nmap is working, use `scanme.nmap.org` as a target.
- Example:
    - This script scans **ports 1-100** by default. Modify `-p1-100` in the script to change the range.
    - Another example is performing all port scanning, ***modify line 21***, change the flags to `"nmap","-p-","-sS","--min-rate=1000", "--max-rate=3000", "-T4", ip`. This command will be added for all the ips in the queue to perform scan:
        - -p- : For all 65535 ports
        - -sS : For SYN stealth scan, this ensures that the connection does not waste time on completing the whole TCP handshake.
        - --min-rate=1000: Sends 1000 packets all at once to increase probing speed
        - --max-rate-3000: Send max 3000 packets at once to avoid firewall/IPS blocking
        - -T4: Timing template, the higher the faster, max you can do is 5
- Based on the above example all you need to do is change the flags that you want to use for your scan, remember to separate each flags by comma and send it within double quotes and voila you have your automated nmap scanner

## Disclaimer
This script should **only** be used on networks you own or have explicit permission to scan. Unauthorized scanning should be termed illegal. Author does not support usage of this script for illegal probing.

## Author
Developed by Prachi Doshi. Contributions via PR and feedback are welcome!

