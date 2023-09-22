#!/bin/bash

/usr/bin/rsync -avzh --progress honeypot@10.0.96.10:/home/honeypot/Documents/IoT-Honeypot/mirroring-port/environ.txt /media/honeypot/Data/IoT-Honeypot/mirroring-port/environ/environ.txt
sudo systemctl restart sniffer.service
