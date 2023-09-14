public_ip=$(ip -o -4 addr list| grep 'tun\|tap' | /usr/bin/awk '{print $4}' | cut -d'/' -f1);

while IFS='' read -r line || [[ -n "$line" ]]; do
    if [ "$line" ]; then
        extracted_hostname=$(echo $line | cut -d'=' -f1)
        if [ "$extracted_hostname" == `hostname` ]; then
            #echo $extracted_hostname
            extracted_ip_data=$(echo $line | cut -d'=' -f2)
            socat_public_port=$(echo $extracted_ip_data | cut -d':' -f2)
            socat_forward_ip=$(echo $extracted_ip_data | cut -d':' -f3)
            socat_forward_port=$(echo $extracted_ip_data | cut -d':' -f4)
            (socat TCP-LISTEN:${socat_public_port},bind="${public_ip}",reuseaddr,fork TCP:${socat_forward_ip}:${socat_forward_port}) &>/dev/null &
        fi
    fi
done < "/home/shared/socat-data.txt"
