#!/bin/bash

/home/honeypot/anaconda3/bin/python scripts_generator.py

for container in "$@"
do
    echo $container
    docker-compose -f compose-wormholes.yml up -d $container
done

for container in "$@"
do
    echo $container
    docker exec $container bash /root/start_openvpn.sh
done

sleep 30

for container in "$@"
do
    echo $container
    if [ `docker exec $container ifconfig | grep "[t]un\|tap" | wc -l` -eq 0 ]
    then
        echo "Could not establish VPN connection"
    else
        echo "VPN connection established"
        echo "Starting socat"
        docker exec -d $container bash /root/start_socat.sh
        echo "Starting dumpcap"
        docker exec -d $container bash /root/start_dumpcap.sh
    fi
done