#!/bin/bash

/home/honeypot/anaconda3/bin/python scripts_generator.py

docker-compose -f compose-wormholes.yml up -d

for container in `docker ps -q`
do
    # get the name of the container
    cont_name=`docker inspect --format='{{.Name}}' $container`

    # check if cont_name matches /w[0-9]*
    if [[ $cont_name = /w[0-9]* ]]
    then
        echo $cont_name
        # run start_openvpn command
        docker exec $container bash /root/start_openvpn.sh
    fi
done

sleep 30

for container in `docker ps -q`
do
    # get the name of the container
    cont_name=`docker inspect --format='{{.Name}}' $container`
    
    # check if cont_name matches /w[0-9]*
    if [[ $cont_name = /w[0-9]* ]]
    then
        echo $cont_name
        # check if vpn tunnel has been established
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
    fi
done

#echo "Starting sniffer.service"
#systemctl restart sniffer.service
