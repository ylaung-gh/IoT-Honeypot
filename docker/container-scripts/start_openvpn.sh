ovpn_serv=$(echo `hostname` | sed 's/_/_*/' | awk -F'_\*' '{print $1"_"$2"-*.ovpn"}')
ovpn_conf=$(find /root/ovpn-config/$ovpn_serv)
ovpn_auth=/root/ovpn-config/$(echo `hostname`).auth
#echo "$ovpn_serv"
#echo "$ovpn_conf"
#echo "$ovpn_auth"
#echo "Connecting to $ovpn_serv"
openvpn --config $ovpn_conf --auth-user-pass $ovpn_auth --daemon