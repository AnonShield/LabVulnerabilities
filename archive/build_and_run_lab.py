#!/usr/bin/env python3
import yaml
import sys
import os
import time
import subprocess

# This script is now self-contained and does not need external files other than the docker-compose.yml

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <output-shell-script>")
        sys.exit(1)

    compose_file = 'docker-compose.yml' # Hardcoded to use the original
    output_script = sys.argv[1]

    # --- Step 1: Get a fresh list of failing services ---
    print("--- Checking for unavailable Docker images (this may take a moment)...")
    pull_command = ["docker-compose", "pull", "--ignore-pull-failures"]
    pull_result = subprocess.run(pull_command, capture_output=True, text=True, check=False)
    
    failed_services = set()
    # Process both stdout and stderr for error messages
    for line in (pull_result.stdout + pull_result.stderr).splitlines():
        if "ERROR: for" in line or "manifest for" in line or "not found" in line:
            parts = line.split()
            if "for" in parts:
                try:
                    service_name_index = parts.index("for") + 1
                    if service_name_index < len(parts):
                        failed_services.add(parts[service_name_index])
                except (ValueError, IndexError):
                    continue
            elif "manifest for" in line:
                 # e.g., "manifest for jeroenwillemsen/wrongsecrets:latest not found"
                 try:
                    image_name = line.split("manifest for ")[1].split(" not found")[0]
                    # This is harder as we need to map image back to service.
                    # For now, this is a known limitation, but the 'ERROR: for' is more common.
                 except IndexError:
                    continue
    
    print(f"Found {len(failed_services)} services with unavailable images: {', '.join(failed_services) if failed_services else 'None'}")

    # --- Step 2: Generate the robust run script ---
    try:
        with open(compose_file, 'r') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading or parsing YAML file: {e}")
        sys.exit(1)

    with open(output_script, 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("# This script was auto-generated to bypass docker-compose and be resilient to errors.\n")
        f.write("\n")
        f.write("echo 'Starting all functional lab containers manually...\n'")
        
        f.write("echo '--> Ensuring docker network exists...\n'")
        f.write("docker network inspect trabalho_vulnnet >/dev/null 2>&1 || docker network create --subnet=172.30.0.0/16 trabalho_vulnnet\n\n")

        services = data.get('services', {})
        if not services:
            f.write("echo 'No services found in the docker-compose file.'\n")
            sys.exit(0)
        
        successful_starts = 0
        failed_starts = 0

        for service_name, service_data in services.items():
            if service_name in failed_services:
                print(f"Skipping service with unavailable image: {service_name}")
                continue

            if not service_data:
                continue
            
            image = service_data.get('image')
            if not image:
                continue

            container_name = service_data.get('container_name', service_name)
            
            f.write(f"# --- Service: {service_name} ---\n")
            f.write(f"echo '--> Processing {container_name}'\n")
            f.write(f"docker rm -f {container_name} >/dev/null 2>&1 || true\n")

            command_parts = ['docker run -d']
            command_parts.append(f'--name {container_name}')
            command_parts.append('--network trabalho_vulnnet')

            if 'networks' in service_data and isinstance(service_data['networks'], dict):
                for net_config in service_data['networks'].values():
                    if net_config and 'ipv4_address' in net_config:
                        command_parts.append(f"--ip {net_config['ipv4_address']}")
                        break 

            if 'ports' in service_data and service_data['ports']:
                for port in service_data['ports']:
                    command_parts.append(f'-p "{port}"')

            if 'environment' in service_data and service_data['environment']:
                if isinstance(service_data['environment'], dict):
                    for key, value in service_data['environment'].items():
                        value_str = str(value).replace('"', '\"')
                        command_parts.append(f'-e "{key}={value_str}"')
                elif isinstance(service_data['environment'], list):
                    for env_var in service_data['environment']:
                        env_var_str = str(env_var).replace('"', '\"')
                        command_parts.append(f'-e "{env_var_str}"')
            
            if 'volumes' in service_data and service_data['volumes']:
                for volume in service_data['volumes']:
                    command_parts.append(f'-v "{volume}"')
            
            if service_data.get('privileged'):
                command_parts.append('--privileged')
            if service_data.get('tty'):
                command_parts.append('-t')
            if service_data.get('stdin_open'):
                command_parts.append('-i')

            command_parts.append(image)

            if 'command' in service_data:
                command_parts.append(service_data['command'])
            
            full_command = ' '.join(command_parts)
            
            # This makes the script resilient
            f.write("if ! " + full_command + "; then\n")
            f.write(f"    echo 'ERROR: Failed to start {container_name}. Continuing...\n'")
            f.write("fi\n\n")

    os.chmod(output_script, 0o755)
    print(f"Successfully generated resilient executable script: {output_script}")

if __name__ == '__main__':
    if os.path.basename(os.getcwd()) != 'trabalho':
        print("Please run this script from the 'trabalho/' directory.")
        sys.exit(1)
    
    # The script now takes only one argument: the output script name
    main()
