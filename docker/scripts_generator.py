import pandas as pd
import yaml
import os

def read_masterCSV():
    master_df = pd.read_csv("/home/honeypot/Documents/IoT-Honeypot/honeypot-master.csv").to_dict(orient="records")
    for record in master_df:
        if type(record['open_ports']) == str:
            record['open_ports'] = list(map(int, record['open_ports'].split(',')))
        elif type(record['open_ports']) == int:
            record['open_ports'] = [record['open_ports']]
    return master_df

def generate_docker_compose(master_df):
    docker_services = {}
    for i in range(len(master_df)):
        iot_addr = "10.0.64." + str(i+1)
        inet_addr = "10.1.64." + str(i+1)
        docker_services[master_df[i]['node']] = {
            'image': "wormhole:latest",
            'container_name': master_df[i]['node'],
            'hostname': master_df[i]['hostname'],
            'cap_add': ["NET_ADMIN"],
            'devices': ["/dev/net/tun"],
            'networks': {'iot': {'ipv4_address': iot_addr}, 'inet': {'ipv4_address': inet_addr}},
            'volumes': ["shared:/home/shared"],
            'stdin_open': True,
            'tty': True
        }
    docker_networks = {
        'inet': {'external': {'name': "inet-bridge"}},
        'iot': {'external': {'name': "iot-bridge"}}
    }
    docker_volumes = {'shared': {'external': {'name': "shared"}}}

    compose_dict = {'version': "2", 'services': docker_services, 'networks': docker_networks, 'volumes': docker_volumes}

    with open("/home/honeypot/Documents/IoT-Honeypot/docker/compose-wormholes.yml", "w") as file:
        yaml.dump(compose_dict, file)

    print("Successfully generated docker-compose.yml")

def generate_socat_data(master_df):
    with open("/media/honeypot/data/socat-data.txt", "w") as file:
        for record in master_df:
            for i in range(len(record['open_ports'])):
                file.write(record['hostname'] + "=" + record['public_ip'] + ":" + str(record['open_ports'][i]) + ":" +
                           record['forward_ip'] + ":" + str(record['open_ports'][i]) + "\n")
    print("Successfully generated socat-data.txt")

def generate_capture_filter(master_df):
    devices_ip = set()
    for record in master_df:
        devices_ip.add(record['forward_ip'])
    devices_ip = list(devices_ip)
    with open("/home/honeypot/Documents/IoT-Honeypot/mirroring-port/environ.txt", "w") as file:
        file.write("CAPTURE_FILTER=host ")
        for i in range(len(devices_ip)):
            if not i == len(devices_ip) - 1:
                file.write(devices_ip[i] + " or ")
            else:
                file.write(devices_ip[i])
    print("Successfully generated environ.txt")

master_df = read_masterCSV()
generate_docker_compose(master_df)
generate_socat_data(master_df)
generate_capture_filter(master_df)