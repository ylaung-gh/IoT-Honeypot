vpn_down=() 

for container in `docker ps -q`; do
    if [ `docker exec $container ifconfig | grep "[t]un\|tap" | wc -l` -eq 0 ]
    then
        # show the name of the container
        docker inspect --format='{{.Name}}' $container
        vpn_down+=$container
        echo "No existing VPN connection"
        docker exec $container bash /root/start_openvpn.sh
    fi
done

if [ ${#vpn_down[@]} -eq 0 ]
then
    echo "VPN connections in all containers are established"
    exit 0
fi

sleep 30

# check if VPN connections have been established, start socat and dumpcap afterwards
for container in $vpn_down; do
    # show the name of the container
    docker inspect --format='{{.Name}}' $container
    
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
