import pandas as pd
import re

def sanitize_name(name):
    """Sanitize names to be safe for use in GraphViz and Prolog."""
    return re.sub(r'[^a-zA-Z0-9_]', '_', name)

def generate_mulval_input(csv_file_path, output_file_path):
    """Generate a MulVAL-compatible Prolog file from a given CSV."""
    # Load the CSV data
    csv_data = pd.read_csv(csv_file_path)

    # Prepare the initial part of the MulVAL input
    mulval_input = "attackerLocated(internet).\n"

    # Process each IP
    for ip, group in csv_data.groupby('IP'):
        server_id = f"server_{ip.replace('.', '_')}"
        mulval_input += f"attackGoal(execCode({server_id},_)).\n\n"
        for index, row in group.iterrows():
            port = int(row['Port']) if pd.notna(row['Port']) else None
            protocol = row['Port Protocol'] if pd.notna(row['Port Protocol']) else 'tcp'
            service = sanitize_name(row['NVT Name'].split()[0] if pd.notna(row['NVT Name']) else 'UnknownService')
            application = service  # Simplified assumption
            cves = row['CVEs'].split(',') if pd.notna(row['CVEs']) else []
            
            # Create network and vulnerability entries
            mulval_input += f"hacl(internet, {server_id}, '{protocol}', {port}).\n"
            for cve in cves:
                cve = cve.strip()
                if cve:
                    mulval_input += (f"vulExists({server_id}, '{cve}', '{service}').\n"
                                     f"vulProperty('{cve}', remoteExploit, privEscalation).\n")
            mulval_input += f"networkServiceInfo({server_id}, '{service}', '{protocol}', {port}, '{application}').\n\n"

    # Write the MulVAL input to a file
    with open(output_file_path, 'w') as file:
        file.write(mulval_input)

# Usage
csv_file_path = 'oval.csv'
output_file_path = 'attack.P'
generate_mulval_input(csv_file_path, output_file_path)
