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

def generate_auth_data(master_df):
    for record in master_df:
        hostname = record['hostname']
        username = record['username']
        password = record['password']
        #print(hostname + " : " + username + " : " + password)

        auth_file = os.path.join("/home/honeypot/Documents/IoT-Honeypot/docker/ovpn-config/", hostname + ".auth")
        with open(auth_file, "w") as file:
            file.write(username + '\n')
            file.write(password + '\n')
    print("Successfully generated .auth")

master_df = read_masterCSV()
generate_auth_data(master_df)
