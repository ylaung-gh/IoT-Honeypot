public_ip=$(ip -o -4 addr list| grep 'tun\|tap' | /usr/bin/awk '{print $4}' | cut -d'/' -f1);
public_iface=$(ip -o -4 addr list| grep 'tun\|tap' | /usr/bin/awk '{print $2}');

mkdir -p /home/shared/pcaps/${public_ip}
(dumpcap -i ${public_iface} -B 256 -b duration:3600 -b filesize:512000 -f "not (host 202.94.70.60 or host 103.24.77.60 or host 118.201.255.203)" -w /home/shared/pcaps/${public_ip}/${public_ip}.pcap) &>/dev/null &
