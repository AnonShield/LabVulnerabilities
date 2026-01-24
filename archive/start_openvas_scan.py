#!/mnt/c/Users/crist/Documents/tramppo/trabalho/venv/bin/python3
import sys
import os
import time
import subprocess
import xml.etree.ElementTree as ET

OPENVAS_HOST = '127.0.0.1'
OPENVAS_PORT = '9390' # Port as string for gvm-cli

# Use environment variables for credentials
OPENVAS_GMP_USER = 'admin'
OPENVAS_GMP_PASSWORD = 'Tr4mpp0Sup3rS3cur3P4ssw0rd!'

TARGETS_FILE = 'targets.txt'
SCAN_CONFIG_NAME = 'Full and Fast'
SCAN_TASK_NAME = 'Vulnerability Lab Scan'
PORT_LIST_NAME = 'All IANA assigned TCP'
DEFAULT_SCANNER_NAME = 'OpenVAS Scanner' # Default scanner name

# Full path to gvm-cli executable inside the venv
GVM_CLI_PATH = os.path.join(os.path.dirname(sys.executable), 'gvm-cli')

def run_gvm_cli_command(gmp_xml_command, description="Executing gvm-cli command"):
    """Helper function to run gvm-cli commands with XML payload."""
    print(f"--- {description} ---")
    full_command = [
        GVM_CLI_PATH, "tls", # CONNECTION_TYPE
        "--hostname", OPENVAS_HOST, "--port", OPENVAS_PORT, # Connection type options
        "--xml", gmp_xml_command # XML GMP command
    ]
    
    # Set environment variables for authentication
    env_vars = os.environ.copy()
    env_vars['GVM_USERNAME'] = OPENVAS_GMP_USER
    env_vars['GVM_PASSWORD'] = OPENVAS_GMP_PASSWORD

    print(f"Command: {' '.join(full_command)}")
    result = subprocess.run(full_command, capture_output=True, text=True, check=False, env=env_vars)
    
    if result.returncode != 0:
        print(f"Error: {description} failed.")
        print(f"Stdout: {result.stdout}")
        print(f"Stderr: {result.stderr}")
        sys.exit(1)
    
    print(f"Stdout: {result.stdout}")
    return result.stdout

def get_target_ips(targets_file):
    """Reads IPs from targets.txt and returns them as a comma-separated string."""
    try:
        with open(targets_file, 'r') as f:
            ips = [line.strip() for line in f if line.strip()]
        return ','.join(ips)
    except FileNotFoundError:
        print(f"Error: Targets file '{targets_file}' not found.")
        sys.exit(1)

def parse_id_from_xml(xml_string, element_tag, attribute_name='id'):
    """Parses an XML string to extract an ID."""
    try:
        root = ET.fromstring(xml_string)
        # Handle cases where the element_tag might be an attribute itself (e.g., config_id)
        if attribute_name == 'id':
            elem = root.find(f'.//{element_tag}')
        else: # For response elements where ID is an attribute of the response root
            elem = root.find(f'.//') # This is problematic. Need more specific path.
            # Example: <create_target_response id="UUID">
            if root.tag == element_tag:
                return root.get(attribute_name)
            else:
                elem = root.find(f'.//{element_tag}')
        
        if elem is not None:
            return elem.get(attribute_name)
    except ET.ParseError:
        pass
    return None

def main():
    print("--- OpenVAS Scan Automation Script ---")
    
    target_ips = get_target_ips(TARGETS_FILE)
    if not target_ips:
        print("No target IPs found. Exiting.")
        sys.exit(1)
    print(f"Target IPs for scan: {target_ips}")

    # 1. Get Scan Configuration ID
    gmp_xml_command = f"<get_configs filter_string='name={SCAN_CONFIG_NAME}'/>"
    response_xml = run_gvm_cli_command(gmp_xml_command, f"Getting ID for Scan Config '{SCAN_CONFIG_NAME}'")
    scan_config_id = parse_id_from_xml(response_xml, "config", 'id')
    if not scan_config_id:
        print(f"Error: Scan configuration '{SCAN_CONFIG_NAME}' not found.")
        sys.exit(1)
    print(f"Scan Config ID: {scan_config_id}")

    # 2. Get Port List ID
    gmp_xml_command = f"<get_port_lists filter_string='name={PORT_LIST_NAME}'/>"
    response_xml = run_gvm_cli_command(gmp_xml_command, f"Getting ID for Port List '{PORT_LIST_NAME}'")
    port_list_id = parse_id_from_xml(response_xml, "port_list", 'id')
    if not port_list_id:
        print(f"Error: Port List '{PORT_LIST_NAME}' not found.")
        sys.exit(1)
    print(f"Port List ID: {port_list_id}")

    # 3. Get Scanner ID
    gmp_xml_command = f"<get_scanners filter_string='name={DEFAULT_SCANNER_NAME}'/>"
    response_xml = run_gvm_cli_command(gmp_xml_command, "Getting ID for default Scanner")
    scanner_id = parse_id_from_xml(response_xml, "scanner", 'id')
    if not scanner_id:
        print(f"Error: Default scanner '{DEFAULT_SCANNER_NAME}' not found.")
        sys.exit(1)
    print(f"Scanner ID: {scanner_id}")

    # 4. Create or Get Target
    target_name = f"Lab Targets ({time.strftime('%Y%m%d-%H%M%S')})"
    gmp_xml_command = f"<get_targets filter_string='hosts={target_ips}'/>"
    response_xml = run_gvm_cli_command(gmp_xml_command, f"Checking for existing target with IPs: {target_ips}")
    target_id = parse_id_from_xml(response_xml, "target", 'id') # Check if existing target

    if target_id:
        print(f"Target for IPs '{target_ips}' already exists with ID: {target_id}")
    else:
        gmp_xml_command = f"<create_target><name>{target_name}</name><hosts>{target_ips}</hosts><port_list id='{port_list_id}'/></create_target>"
        response_xml = run_gvm_cli_command(gmp_xml_command, f"Creating new target '{target_name}'")
        target_id = parse_id_from_xml(response_xml, "create_target_response", 'id')
        if not target_id:
            print("Error: Failed to create target.")
            sys.exit(1)
        print(f"Target created with ID: {target_id}")
    
    # 5. Create and Start Task
    gmp_xml_command = f"<get_tasks filter_string='name={SCAN_TASK_NAME}'/>"
    response_xml = run_gvm_cli_command(gmp_xml_command, f"Checking for existing task '{SCAN_TASK_NAME}'")
    existing_task_id = parse_id_from_xml(response_xml, "task", 'id')

    if existing_task_id:
        print(f"Existing task '{SCAN_TASK_NAME}' found with ID: {existing_task_id}. Stopping and deleting it.")
        run_gvm_cli_command(f"<stop_task task_id='{existing_task_id}'/>", f"Stopping existing task '{SCAN_TASK_NAME}'")
        run_gvm_cli_command(f"<delete_task task_id='{existing_task_id}'/>", f"Deleting existing task '{SCAN_TASK_NAME}'")

    gmp_xml_command = f"<create_task><name>{SCAN_TASK_NAME}</name><config id='{scan_config_id}'/><target id='{target_id}'/><scanner id='{scanner_id}'/></create_task>"
    response_xml = run_gvm_cli_command(gmp_xml_command, f"Creating scan task '{SCAN_TASK_NAME}'")
    task_id = parse_id_from_xml(response_xml, "create_task_response", 'id')
    if not task_id:
        print("Error: Failed to create task.")
        sys.exit(1)
    print(f"Scan task created with ID: {task_id}")

    gmp_xml_command = f"<start_task task_id='{task_id}'/>"
    run_gvm_cli_command(gmp_xml_command, f"Starting scan task '{SCAN_TASK_NAME}'")
    print(f"Scan task '{SCAN_TASK_NAME}' started. Task ID: {task_id}")

    print("\nOpenVAS scan initiated successfully!")
    print(f"You can monitor its progress via the OpenVAS web interface (http://{OPENVAS_HOST}:8080) or using 'gvm-cli' with task ID: {task_id}")

if __name__ == '__main__':
    if os.path.basename(os.getcwd()) != 'trabalho':
        print("Please run this script from the 'trabalho/' directory.")
        sys.exit(1)
    main()