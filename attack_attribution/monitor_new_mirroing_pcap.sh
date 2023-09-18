#!/bin/sh

# DIR=/media/honeypot/431382e8-e800-44f7-b55d-76a2ec01c14a/honeypot2/shared_data/pcaps/mirroring_port
DIR="/media/honeypot/Data/IoT-Honeypot/mirroring-port"

#DIR="/media/honeypot/Data/sample_data/"
# inotifywait - wait for changes to files using inotify
# -e moved_to - A file or directory was moved into a watched directory.
# -m -r are to make the command run indefinitely ("monitor") and recursively in the directory
# --format '%w%f' outputs the directory (path to the file, %w) plus the filename (%f) that caused the event.

#inotifywait -m -r -e moved_to,create --format '%w%f' "$DIR" | while read f
inotifywait -m -e moved_to,close_write --format '%w%f' "$DIR" | while read f

do
    echo "$f"
    #    python get_outbound_connections.py "$f"
    #time tshark -r mirroring_feb.pcap -n -Y "dns" -T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name >> dns_feb.csv
    # Instead call python program that does this and much more
    #tshark -r $f -n -Y "tcp.flags.syn == 1 and tcp.flags.ack == 0 and not (ip.dst == 192.168.0.0/16)" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.port
    python2.7 /media/honeypot/Data/IoT-Honeypot/attack_attribution/pcap_parser.py $f
done
