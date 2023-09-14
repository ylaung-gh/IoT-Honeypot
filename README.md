# IoT-Honeypot



## Useful Commands

- Generate *.auth files with `/home/honeypot/anaconda3/bin/python generate_auth.py`
- Build docker image with `sudo docker build -t wormhole -t wormhole:1.0 .`
- Generate docker compose with `/home/honeypot/anaconda3/bin/python scripts_generator.py`
- Start wormholes with `sudo ./start_wormhole.sh w0 w1`
- Go inside a container with `sudo docker exec -it w0 /bin/bash`
- Up the containers with `sudo docker-compose -f compose-wormholes.yml up -d`

