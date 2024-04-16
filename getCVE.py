import pandas as pd
import socket

def sort_ips(ip_list):
    # This function sorts IP addresses numerically
    return sorted(ip_list, key=lambda ip: socket.inet_aton(ip))

def assign_hostnames_by_ip_order(data):
    # Get unique IPs and sort them
    unique_ips = sort_ips(data['IP'].unique())
    
    # Map IPs to hostnames in numerical order
    ip_to_hostname = {ip: f"vuln-{index+1}.lan" for index, ip in enumerate(unique_ips)}
    return ip_to_hostname

def process_csv_and_generate_cve(csv_file_path, output_file_path):
    # Load CSV data
    csv_data = pd.read_csv(csv_file_path)
    
    # Assign hostnames based on IP order
    ip_to_hostname = assign_hostnames_by_ip_order(csv_data)
    csv_data['Hostname'] = csv_data['IP'].map(ip_to_hostname)
    
    # Group data by hostname and gather unique CVEs
    grouped_data = csv_data.groupby('Hostname')['CVEs'].apply(lambda x: x.dropna().unique())
    
    # Create the output text content
    output_content = ""
    for hostname, cves in grouped_data.items():
        output_content += hostname + "\n"
        output_content += "\n".join(cves) + "\n"
    
    # Write to the file
    with open(output_file_path, 'w') as file:
        file.write(output_content)

# Example usage
csv_file_path = 'oval.csv'
output_file_path = 'CVE.txt'
process_csv_and_generate_cve(csv_file_path, output_file_path)
