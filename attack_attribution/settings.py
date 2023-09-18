import yaml

CONFIG_FILE='/media/honeypot/Data/IoT-Honeypot/attack_attribution/settings.yml'
CONFIG = yaml.load(open(CONFIG_FILE), Loader=yaml.FullLoader)