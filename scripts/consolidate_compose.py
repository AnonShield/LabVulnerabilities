
import yaml

def main():
    # Read the base docker-compose file
    with open('docker-compose.yml', 'r') as f:
        base_compose = yaml.safe_load(f)

    # Read the additional docker-compose file
    with open('docker-compose.adicional.yml', 'r') as f:
        adicional_compose = yaml.safe_load(f)

    # Merge the services
    base_compose['services'].update(adicional_compose['services'])

    # Find and replace the prometheus image
    if 'prom18' in base_compose['services']:
        print("Found 'prom18' service, updating image...")
        base_compose['services']['prom18']['image'] = 'prom/prometheus:v2.15.2'
        # Optional: rename the service for clarity
        base_compose['services']['prometheus-old'] = base_compose['services'].pop('prom18')
        base_compose['services']['prometheus-old']['container_name'] = 'prometheus-old'


    # Write the merged content back to the main docker-compose.yml
    with open('docker-compose.yml', 'w') as f:
        yaml.dump(base_compose, f, default_flow_style=False, sort_keys=False)

    print("Successfully merged and updated docker-compose.yml")

if __name__ == '__main__':
    main()
