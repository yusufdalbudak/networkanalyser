import scapy.all as scapy
import argparse
import pandas as pd
import json
import logging

# Setup logging
logging.basicConfig(filename='network_scan.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# This function gets command-line arguments using argparse
def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner using ARP")
    # Add target IP/range argument
    parser.add_argument("-t", "--target", dest="target", required=True, help="Target IP / IP range to scan")
    # Add output file argument (optional)
    parser.add_argument("-o", "--output", dest="output", required=False, help="Output file to save results (CSV or JSON)")
    args = parser.parse_args()
    return args

# This function performs the ARP scan using Scapy
def scan(ip):
    logging.info(f"Scanning IP range: {ip}")
    # Create an ARP request for the given IP range
    arp_request = scapy.ARP(pdst=ip)
    # Create an Ethernet frame to broadcast the ARP request
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # Combine the ARP request with the Ethernet frame
    arp_request_broadcast = broadcast / arp_request
    try:
        # Send the ARP request and capture the response
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        logging.info(f"Number of responses: {len(answered_list)}")
    except PermissionError:
        logging.error("Permission Denied. Please run as root.")
        print("[-] Permission Denied. Please run as root.")
        return []
    except Exception as e:
        logging.error(f"Error: {e}")
        print(f"[-] Error: {e}")
        return []
    return answered_list

# This function prints the scan results
def print_result(answered_list):
    if not answered_list:
        print("[-] No results found.")
        return
    # Print header
    print("IP\t\t\tMAC Address\n-----------------------------------------")
    # Print each IP and MAC address pair
    for element in answered_list:
        print(f"{element[1].psrc}\t\t{element[1].hwsrc}")

# This function saves the scan results to a file (CSV or JSON)
def save_results(answered_list, output_file):
    # Format the results as a list of dictionaries
    results = [{"IP": element[1].psrc, "MAC": element[1].hwsrc} for element in answered_list]
    if output_file.endswith('.csv'):
        # Save results to a CSV file
        df = pd.DataFrame(results)
        df.to_csv(output_file, index=False)
        logging.info(f"Results saved to {output_file}")
    elif output_file.endswith('.json'):
        # Save results to a JSON file
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        logging.info(f"Results saved to {output_file}")
    else:
        logging.error("Unsupported file format. Please use CSV or JSON.")
        print("Unsupported file format. Please use CSV or JSON.")

# Main function to orchestrate the ARP scan
def main():
    # Get command-line arguments
    args = get_arguments()
    # Perform the scan
    scan_result = scan(args.target)
    if scan_result:
        # Print the scan results
        print_result(scan_result)
        # Save the scan results if an output file is specified
        if args.output:
            save_results(scan_result, args.output)
    else:
        print("[-] No results found.")

# Check if the script is being run directly
if __name__ == "__main__":
    main()
