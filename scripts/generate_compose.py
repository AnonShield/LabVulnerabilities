
import re
import yaml

def parse_docker_run_command(command_line):
    parts = command_line.split()
    service_def = {}
    
    i = 0
    while i < len(parts):
        if parts[i] == '-d':
            pass
        elif parts[i] == '-p':
            i += 1
            if 'ports' not in service_def:
                service_def['ports'] = []
            service_def['ports'].append(parts[i])
        elif parts[i] == '--name':
            i += 1
            service_def['container_name'] = parts[i]
        elif parts[i] == '-e':
            i += 1
            if 'environment' not in service_def:
                service_def['environment'] = []
            service_def['environment'].append(parts[i])
        elif parts[i].startswith('docker.bintray.io') or '/' in parts[i] or ':' in parts[i] and 'mysql' not in parts[i]:
            if 'image' not in service_def:
                service_def['image'] = parts[i]
        i += 1
        
    if 'image' not in service_def:
        # Handle images that don't follow the previous patterns, like 'mysql:5.5'
        for part in reversed(parts):
            if ':' in part and 'mysql' in part or 'postgres' in part:
                 service_def['image'] = part
                 break
                 
    # Command might be at the end
    if 'ports' in service_def and service_def['ports']:
        if parts[-1] not in service_def['ports'][0] :
            command_parts = []
            # Find where the command starts
            try:
                start_index = parts.index(service_def.get('image')) + 1
                command_parts = parts[start_index:]
                if command_parts:
                    service_def['command'] = ' '.join(command_parts)
            except (ValueError, KeyError):
                pass # No image found or other issue
    elif 'image' in service_def: # if no ports, but image is present
        try:
            start_index = parts.index(service_def.get('image')) + 1
            command_parts = parts[start_index:]
            if command_parts:
                 service_def['command'] = ' '.join(command_parts)
        except (ValueError, KeyError):
            pass # No image found or other issue

    return service_def

def main():
    with open('adicional/containers_adicionais_50plus.md', 'r') as f:
        content = f.read()

    docker_commands = re.findall(r'`(docker run .*)`', content)

    services = {}
    ip_subnet = 1
    ip_host = 1

    for command in docker_commands:
        service_def = parse_docker_run_command(command)
        if 'container_name' in service_def:
            service_name = service_def['container_name']
            
            # Assign IP
            ip_address = f'172.31.{ip_subnet}.{ip_host}'
            ip_host += 1
            if ip_host > 254:
                ip_host = 1
                ip_subnet += 1

            service_def['networks'] = {'vulnnet': {'ipv4_address': ip_address}}
            
            # Use the service name as the key
            services[service_name] = service_def

    # Create the full docker-compose structure
    compose_data = {
        'version': '3.8',
        'networks': {
            'vulnnet': {
                'driver': 'bridge',
                'ipam': {
                    'config': [
                        {'subnet': '172.30.0.0/16'}
                    ]
                }
            }
        },
        'services': services
    }

    with open('docker-compose.adicional.yml', 'w') as f:
        yaml.dump(compose_data, f, default_flow_style=False, sort_keys=False)

if __name__ == '__main__':
    main()
