import os
import logging
from datetime import datetime
from azure.identity import DefaultAzureCredential
from azure.mgmt.network import NetworkManagementClient

# Configure logging
logging.basicConfig(
    filename="scan_results.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode="w"  # 'w' to overwrite each time; use 'a' to append
)

# Define the list of dangerous ports
insecure_ports = [21, 23, 110, 139, 445, 3389, 80]

def get_user_input():
    """Collect user input for Azure resources."""
    subscription_id = input("Enter Subscription ID: ")
    resource_group = input("Enter Resource Group Name: ")
    nsg_name = input("Enter Network Security Group Name: ")
    return subscription_id, resource_group, nsg_name

def is_port_insecure(port, insecure_ports):
    """Check if a given port is in the insecure ports list."""
    try:
        port = int(port)
        return port in insecure_ports
    except ValueError:
        return False

def log_scan_results(insecure_ports_found):
    """Log the scan results to a file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    logging.info(f"Scan Timestamp: {timestamp}")
    
    if insecure_ports_found:
        logging.info("\nInsecure Ports Found:")
        for name, port in insecure_ports_found:
            logging.info(f"Rule Name: {name}, Port: {port}")
        logging.info("\nScan completed successfully.\n")
    else:
        logging.info("No insecure ports found.\n")

def scan_ports(subscription_id, resource_group, nsg_name):
    """Scan for insecure ports in the specified NSG."""
    credential = DefaultAzureCredential()
    network_client = NetworkManagementClient(credential, subscription_id)

    # Retrieve NSG rules
    nsg = network_client.network_security_groups.get(resource_group, nsg_name)
    insecure_ports_found = []

    for rule in nsg.security_rules:
        if rule.destination_port_range:
            # Single Port
            if '-' not in rule.destination_port_range:
                if is_port_insecure(rule.destination_port_range, insecure_ports):
                    insecure_ports_found.append((rule.name, rule.destination_port_range))
            # Port Range
            else:
                start_port, end_port = map(int, rule.destination_port_range.split('-'))
                for port in range(start_port, end_port + 1):
                    if port in insecure_ports:
                        insecure_ports_found.append((rule.name, port))

    # Log the scan results
    log_scan_results(insecure_ports_found)
    
    return insecure_ports_found

def main():
    subscription_id, resource_group, nsg_name = get_user_input()
    insecure_ports_found = scan_ports(subscription_id, resource_group, nsg_name)

    if insecure_ports_found:
        print("\nInsecure Ports Found:")
        for name, port in insecure_ports_found:
            print(f"Rule Name: {name}, Port: {port}")
    else:
        print("\nNo insecure ports found.")
    
    print("\nScan results have been logged to 'scan_results.txt'.")

if __name__ == "__main__":
    main()
