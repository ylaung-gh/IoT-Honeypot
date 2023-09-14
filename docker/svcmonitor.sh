#!/bin/bash

for container in `docker ps -q`; do
    # get the name of the container
    cont_name=`docker inspect --format='{{.Name}}' $container`
    
    # check if cont_name matches /w[0-9]*
    if [[ $cont_name = /w[0-9]* ]]
    then
        echo $cont_name

        if [ `docker exec $container ifconfig | grep "[t]un\|tap" | wc -l` -eq 0 ]
        then
            echo "VPN connection is down"
            docker exec $container bash /root/start_openvpn.sh
            sleep 30
            if [ `docker exec $container ifconfig | grep "[t]un\|tap" | wc -l` -eq 0 ]
            then
                echo "Could not establish VPN connection. Retrying in 1 hour"
            else
                echo "VPN connection established"
            fi
        else
            echo "VPN connection is up"
        fi
    
        if [ `docker exec $container ps -aux | grep "socat" | wc -l` -eq 0 ]
        then
            echo "Socat service is down"
            docker exec -d $container bash /root/start_socat.sh
            if [ `docker exec $container ps -aux | grep "socat" | wc -l` -eq 0 ]
            then
                echo "Could not start Socat. Retrying in 1 hour"
            else
                echo "Socat service started"
            fi
        else
            echo "Socat service is running"
        fi
    
        if [ `docker exec $container ps -aux | grep "dumpcap" | wc -l` -eq 0 ]
        then
            echo "Dumpcap service is down"
            docker exec -d $container bash /root/start_dumpcap.sh
            if [ `docker exec $container ps -aux | grep "dumpcap" | wc -l` -eq 0 ]
            then
                echo "Could not start Dumpcap. Retrying in 1 hour"
            else
                echo "Dumpcap service started"
            fi
        else
            echo "Dumpcap service running"
        fi
    fi
done > /home/honeypot/Documents/IoT-Honeypot/docker/svcmonitor.log
