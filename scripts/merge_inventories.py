
import pandas as pd
import yaml

def main():
    # Read the original inventory
    inventory_df = pd.read_csv('inventory.csv')

    # Read the additional inventory
    adicional_inventory_df = pd.read_csv('adicional/inventory_adicional_50plus.csv')

    # Read the generated docker-compose file to get IPs
    with open('docker-compose.adicional.yml', 'r') as f:
        compose_data = yaml.safe_load(f)

    # Create a mapping from container name to IP address
    ip_map = {}
    for service_name, service_data in compose_data['services'].items():
        ip_map[service_name] = service_data['networks']['vulnnet']['ipv4_address']

    # Add the 'IP' column to the additional inventory
    adicional_inventory_df['IP'] = adicional_inventory_df['Container'].map(ip_map)

    # Reorder columns to match the original inventory
    # Getting the columns from inventory_df and checking if they exist in adicional_inventory_df
    cols = inventory_df.columns.tolist()
    adicional_cols = adicional_inventory_df.columns.tolist()
    final_cols = []
    for col in cols:
        if col in adicional_cols:
            final_cols.append(col)

    adicional_inventory_df = adicional_inventory_df[final_cols]
    
    # Concatenate the two dataframes
    full_inventory_df = pd.concat([inventory_df, adicional_inventory_df], ignore_index=True)

    # Save the merged inventory
    full_inventory_df.to_csv('inventory_full.csv', index=False)

if __name__ == '__main__':
    main()
