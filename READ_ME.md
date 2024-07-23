# Network Scanner using ARP

This Python script performs an ARP scan on a specified network range to discover active devices and their MAC addresses. It uses the Scapy library to send ARP requests and capture responses. The results can be saved to a CSV or JSON file, and detailed logs are maintained for troubleshooting and auditing purposes.

## Features
- Perform ARP scans on a specified IP range.
- Output results to the console.
- Save results to CSV or JSON files.
- Detailed logging for debugging and auditing.

## Requirements
- Python 3.x
- Scapy
- Pandas

## Installation
1. Clone the repository:
   ```sh
   git clone https://github.com/yusufdalbudak/macchanger.git
   cd macchanger

Install the required Python packages:
pip install scapy pandas


Usage
sudo python netwdiscover.py -t <target_ip_range>


-----------------------------------------------------------------------------------------------

Example:
sudo python netwdiscover.py -t 192.168.1.1/24


To perform a network scan and save results to a CSV file:
sudo python netwdiscover.py -t <target_ip_range> -o <output_file.csv>



-------------------------------------------------------------------------------------------------

Script Details
Logging Setup
Logs are saved to network_scan.log with detailed information about the scanning process.

Functions
get_arguments()
Parses and returns command-line arguments using argparse.

scan(ip)
Performs the ARP scan on the specified IP range using Scapy and returns the list of responses.

print_result(answered_list)
Prints the scan results to the console.

save_results(answered_list, output_file)
Saves the scan results to a specified output file in CSV or JSON format.

main()
Main function that orchestrates the argument parsing, scanning, and result handling.
--------------------------------------------------------------------------------------

Example Output:
[DEBUG] Scanning IP range: 192.168.1.1/24
[DEBUG] Number of responses: 1
IP                      MAC Address
-----------------------------------------
192.168.1.120           00:33:50:ef:2c:85


---------------------------------------------------------------------------------------

License
This project is licensed under the MIT License. See the LICENSE file for details.

Contributing
Contributions are welcome! Please feel free to submit a Pull Request or open an issue to discuss any changes.





















