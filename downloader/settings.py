import yaml

CONFIG_FILE='/media/honeypot/Data/IoT-Honeypot/downloader/settings.yml'
CONFIG = yaml.load(open(CONFIG_FILE), Loader=yaml.FullLoader)