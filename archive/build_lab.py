#!/usr/bin/env python3
import yaml
import sys
import os

def parse_failed_services(log_file_path):
    """Parses the docker-compose pull log to find failed services."""
    failed_services = set()
    try:
        with open(log_file_path, 'r') as f:
            for line in f:
                if "ERROR: for" in line:
                    parts = line.split()
                    try:
                        service_name = parts[2]
                        failed_services.add(service_name)
                    except IndexError:
                        continue
    except FileNotFoundError:
        print(f"Warning: Log file not found at {log_file_path}. Assuming no services failed.")
    return failed_services

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <compose-file> <log-file> <output-script>")
        sys.exit(1)

    compose_file = sys.argv[1]
    log_file = sys.argv[2]
    output_script = sys.argv[3]

    failed_services = parse_failed_services(log_file)
    print(f"Found {len(failed_services)} failed services: {', '.join(failed_services) if failed_services else 'None'}")
    
    try:
        with open(compose_file, 'r') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        print(f"Error reading or parsing YAML file: {e}")
        sys.exit(1)

    with open(output_script, 'w') as f:
        f.write("#!/bin/bash\n")
        f.write("# This script was auto-generated to bypass docker-compose issues.\n")
        f.write("set -e\n\n")
        f.write("echo 'Starting all functional lab containers manually...'\n\n")
        
        f.write("echo 'Ensuring docker network exists...'\n")
        f.write("docker network inspect trabalho_vulnnet >/dev/null 2>&1 || docker network create --subnet=172.30.0.0/16 trabalho_vulnnet\n\n")

        services = data.get('services', {})
        if not services:
            f.write("echo 'No services found in the docker-compose file.'\n")
            sys.exit(0)

        for service_name, service_data in services.items():
            if service_name in failed_services:
                print(f"Skipping failed service: {service_name}")
                continue

            if not service_data:
                print(f"Skipping empty service definition for '{service_name}'")
                continue
            
            image = service_data.get('image')
            if not image:
                print(f"Skipping service '{service_name}' because it has no image.")
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
            f.write(full_command + "\n\n")

    os.chmod(output_script, 0o755)
    print(f"Successfully generated executable script: {output_script}")

if __name__ == '__main__':
    main()